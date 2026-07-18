"""Load real / public insider-threat and PAM datasets into CyberVault events.

Keep the synthetic generator for reproducibility; use these loaders for
external validation on CERT, LANL, or anonymized PAM exports.

Expected layout (place downloads under data/datasets/):

  data/datasets/cert/
    logon.csv          # CERT r4.2/r5.2/r6.2 style
    answers.json       # optional: {"malicious_users": ["CSF...", ...]}

  data/datasets/lanl/
    auth.txt           # LANL Unified Host and Network Dataset (auth)

  data/datasets/pam/
    events.jsonl       # anonymized JumpServer / CyberVault events with label

All loaders return (events, counts) with the same event schema as
generate_pam_dataset(), so train_models / the notebook work unchanged.
"""

from __future__ import annotations

import csv
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .dataset import generate_pam_dataset

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

EventList = List[dict]
Counts = Dict[str, int]


def _iso_from_any(value: str, default_hour: int = 12) -> str:
    """Best-effort timestamp → ISO-8601 UTC."""
    if not value:
        return datetime(2020, 1, 1, default_hour, 0, 0, tzinfo=timezone.utc).isoformat()
    text = str(value).strip()
    # Unix epoch seconds
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc).isoformat()
        except (OSError, ValueError):
            pass
    for fmt in (
        '%m/%d/%Y %H:%M:%S',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%d',
    ):
        try:
            dt = datetime.strptime(text.replace('Z', '+0000'), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return datetime(2020, 1, 1, default_hour, 0, 0, tzinfo=timezone.utc).isoformat()


def _event(
    *,
    user_id: str,
    asset_id: str,
    remote_addr: str,
    timestamp: str,
    command: str = '',
    event_type: str = 'command.ingested',
    session_id: str = '',
    label: int = 0,
    anomaly_type: str = 'normal',
    source: str = 'real',
    account: str = 'unknown',
) -> dict:
    return {
        'event_id': str(uuid.uuid4()),
        'event_type': event_type,
        'timestamp': timestamp,
        'session_id': session_id or f'session-{user_id}-{asset_id}',
        'user_id': user_id or 'unknown',
        'asset_id': asset_id or 'unknown',
        'account': account,
        'protocol': 'ssh',
        'remote_addr': remote_addr or '0.0.0.0',
        'payload': {'input': command} if command else {'reason': event_type},
        'metadata': {'source': source},
        'label': int(label),
        'anomaly_type': anomaly_type,
    }


def _counts(events: EventList) -> Counts:
    c: Counts = Counter()
    for e in events:
        if int(e.get('label', 0)) == 0:
            c['normal'] += 1
        else:
            c[str(e.get('anomaly_type') or 'anomaly')] += 1
    return dict(c)


def summarize_events(events: EventList) -> dict:
    labels = [int(e.get('label', 0)) for e in events]
    return {
        'n_events': len(events),
        'n_normal': labels.count(0),
        'n_anomaly': labels.count(1),
        'n_users': len({e.get('user_id') for e in events}),
        'n_assets': len({e.get('asset_id') for e in events}),
        'sources': sorted({(e.get('metadata') or {}).get('source', '?') for e in events}),
    }


# ---------------------------------------------------------------------------
# CERT Insider Threat (logon.csv + optional answers)
# ---------------------------------------------------------------------------

def _load_cert_answers(path: Path) -> set:
    """Return set of malicious user ids from answers.json, insiders.csv, or text."""
    if not path.exists():
        return set()
    text = path.read_text(encoding='utf-8', errors='replace').strip()
    if not text:
        return set()
    if path.suffix.lower() == '.json':
        data = json.loads(text)
        if isinstance(data, dict):
            users = data.get('malicious_users') or data.get('users') or []
            return {str(u) for u in users}
        if isinstance(data, list):
            return {str(u) for u in data}
    if path.suffix.lower() == '.csv':
        users = set()
        with path.open(newline='', encoding='utf-8', errors='replace') as fp:
            for row in csv.DictReader(fp):
                u = (row.get('user') or row.get('user_id') or '').strip()
                ds = str(row.get('dataset') or '')
                # Prefer r4.2 rows when present; otherwise take all
                if u and (not ds or ds.startswith('4.2') or ds == '4.2'):
                    users.add(u)
        return users
    return {line.strip() for line in text.splitlines() if line.strip() and not line.startswith('#')}


def _resolve_cert_bad_users(root: Path) -> set:
    for candidate in (
        root / 'answers.json',
        root / 'malicious_users.txt',
        root / 'answers' / 'insiders.csv',
        root / 'insiders.csv',
    ):
        users = _load_cert_answers(candidate)
        if users:
            return users
    return set()


def load_cert_dataset(
    cert_dir: str | Path,
    max_events: Optional[int] = 50_000,
    seed: int = 42,
) -> Tuple[EventList, Counts]:
    """Map CERT-style logon.csv into CyberVault events.

    Expected columns (flexible naming): date/time, user, pc/computer, activity.
    Label = 1 if user appears in answers (malicious_users).

    For large dumps (~850k+ rows), ``max_events`` keeps a balanced subsample:
    prefer insider-user events, then fill with normals (deterministic via seed).
    """
    import random as _random

    root = Path(cert_dir)
    logon = root / 'logon.csv'
    if not logon.exists():
        alt = root / 'events.csv'
        if not alt.exists():
            raise FileNotFoundError(
                f'CERT logon.csv not found in {root}. '
                'Run: python -m aiss.evaluation.download_datasets'
            )
        logon = alt

    bad_users = _resolve_cert_bad_users(root)
    rng = _random.Random(seed)

    anomaly_events: EventList = []
    normal_events: EventList = []
    anomaly_cap = (max_events // 2) if max_events else None
    normal_cap = max_events if max_events else None

    with logon.open(newline='', encoding='utf-8', errors='replace') as fp:
        reader = csv.DictReader(fp)
        if not reader.fieldnames:
            raise ValueError(f'Empty or invalid CSV: {logon}')
        fields = {name.lower().strip(): name for name in reader.fieldnames}

        def col(*names: str) -> Optional[str]:
            for n in names:
                if n in fields:
                    return fields[n]
            return None

        c_date = col('date', 'time', 'timestamp', 'datetime')
        c_user = col('user', 'user_id', 'username', 'actor')
        c_pc = col('pc', 'computer', 'host', 'dst', 'asset', 'asset_id')
        c_act = col('activity', 'action', 'event', 'type')

        for row in reader:
            user = (row.get(c_user) or 'unknown').strip() if c_user else 'unknown'
            pc = (row.get(c_pc) or 'unknown').strip() if c_pc else 'unknown'
            activity = ((row.get(c_act) or 'Logon') if c_act else 'Logon').strip()
            ts = _iso_from_any(row.get(c_date) if c_date else '')
            is_bad = user in bad_users
            act_l = activity.lower()
            if 'logoff' in act_l:
                etype = 'session.finished'
                cmd = ''
            elif 'logon' in act_l or 'login' in act_l:
                etype = 'login.success'
                cmd = ''
            else:
                etype = 'command.ingested'
                cmd = activity
            ev = _event(
                user_id=user,
                asset_id=pc,
                remote_addr=f'cert-{pc}',
                timestamp=ts,
                command=cmd,
                event_type=etype,
                session_id=f'cert-{user}-{pc}',
                label=1 if is_bad else 0,
                anomaly_type='cert_insider' if is_bad else 'normal',
                source='cert',
                account=user,
            )
            if is_bad:
                if anomaly_cap is None or len(anomaly_events) < anomaly_cap:
                    anomaly_events.append(ev)
            else:
                if normal_cap is None:
                    normal_events.append(ev)
                elif len(normal_events) < normal_cap:
                    normal_events.append(ev)
                else:
                    # reservoir so late normals can replace early ones
                    j = rng.randint(0, len(normal_events) + len(anomaly_events))
                    if j < len(normal_events):
                        normal_events[j] = ev

    if max_events:
        need_normal = max(0, max_events - len(anomaly_events))
        rng.shuffle(normal_events)
        events = anomaly_events + normal_events[:need_normal]
    else:
        events = anomaly_events + normal_events

    if not events:
        raise ValueError(f'No rows loaded from {logon}')
    return events, _counts(events)


# ---------------------------------------------------------------------------
# LANL (auth.txt / auth.csv)
# ---------------------------------------------------------------------------

def load_lanl_dataset(
    lanl_dir: str | Path,
    max_events: Optional[int] = None,
    fail_as_anomaly: bool = True,
) -> Tuple[EventList, Counts]:
    """Map LANL auth records into CyberVault events.

    Typical auth line (comma-separated, no header):
      time,src_user,dst_user,src_comp,dst_comp,auth_type,logon_type,orientation,success

    Prefer ``redteam_raw.txt`` (official cyber1 redteam events) for ground truth.
    ``redteam.txt`` may list only usernames. Failed auths are weak anomalies when
    ``fail_as_anomaly=True``.
    """
    root = Path(lanl_dir)
    auth = root / 'auth.txt'
    if not auth.exists():
        auth = root / 'auth.csv'
    if not auth.exists():
        raise FileNotFoundError(
            f'LANL auth.txt/auth.csv not found in {root}. '
            'Run: python -m aiss.evaluation.download_datasets'
        )

    redteam_users = set()
    rt_users_file = root / 'redteam.txt'
    if rt_users_file.exists():
        redteam_users = {
            line.strip().split(',')[0]
            for line in rt_users_file.read_text(encoding='utf-8', errors='replace').splitlines()
            if line.strip() and not line.startswith('#')
        }

    # Official redteam compromise events → high-confidence anomalies
    events: EventList = []
    rt_raw = root / 'redteam_raw.txt'
    if rt_raw.exists():
        for line in rt_raw.read_text(encoding='utf-8', errors='replace').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',')
            if len(parts) < 4:
                continue
            time_v, user, src_comp, dst_comp = parts[0], parts[1], parts[2], parts[3]
            user = user.split('@')[0]
            redteam_users.add(user)
            events.append(
                _event(
                    user_id=user,
                    asset_id=dst_comp or src_comp,
                    remote_addr=src_comp or '0.0.0.0',
                    timestamp=_iso_from_any(time_v),
                    command='',
                    event_type='login.success',
                    session_id=f'lanl-rt-{user}-{dst_comp}',
                    label=1,
                    anomaly_type='lanl_redteam',
                    source='lanl',
                    account=user,
                )
            )

    auth_budget = None
    if max_events is not None:
        auth_budget = max(0, max_events - len(events))

    with auth.open(encoding='utf-8', errors='replace') as fp:
        first = fp.readline()
        fp.seek(0)
        has_header = any(h in first.lower() for h in ('time', 'user', 'src', 'success'))
        n_auth = 0
        if has_header and ',' in first:
            reader = csv.DictReader(fp)
            for row in reader:
                time_v = row.get('time') or row.get('Time') or ''
                src_user = (row.get('src_user') or row.get('source_user') or row.get('user') or 'unknown')
                src_user = str(src_user).split('@')[0]
                dst_comp = row.get('dst_comp') or row.get('destination_computer') or row.get('pc') or 'unknown'
                src_comp = row.get('src_comp') or row.get('source_computer') or dst_comp
                success = str(row.get('success') or row.get('Success') or 'Success')
                _append_lanl_event(
                    events, time_v, src_user, str(dst_comp), str(src_comp),
                    success, redteam_users, fail_as_anomaly,
                )
                n_auth += 1
                if auth_budget is not None and n_auth >= auth_budget:
                    break
        else:
            for line in fp:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) < 9:
                    continue
                time_v, src_user, _dst_user, src_comp, dst_comp = parts[:5]
                success = parts[8]
                src_user = src_user.split('@')[0]
                _append_lanl_event(
                    events, time_v, src_user, dst_comp, src_comp,
                    success, redteam_users, fail_as_anomaly,
                )
                n_auth += 1
                if auth_budget is not None and n_auth >= auth_budget:
                    break

    if not events:
        raise ValueError(f'No rows loaded from {auth}')
    if max_events and len(events) > max_events:
        events = events[:max_events]
    return events, _counts(events)


def _append_lanl_event(
    events: EventList,
    time_v: str,
    user: str,
    dst_comp: str,
    src_comp: str,
    success: str,
    redteam: set,
    fail_as_anomaly: bool,
) -> None:
    ok = str(success).lower() in ('1', 'success', 'true', 'yes')
    is_red = user in redteam
    is_anom = is_red or (fail_as_anomaly and not ok)
    if is_red:
        atype = 'lanl_redteam'
    elif not ok:
        atype = 'login_failed'
    else:
        atype = 'normal'
    events.append(
        _event(
            user_id=user,
            asset_id=dst_comp or src_comp,
            remote_addr=src_comp or '0.0.0.0',
            timestamp=_iso_from_any(time_v),
            command='',
            event_type='login.success' if ok else 'login.failed',
            session_id=f'lanl-{user}-{dst_comp}',
            label=1 if is_anom else 0,
            anomaly_type=atype,
            source='lanl',
            account=user,
        )
    )


# ---------------------------------------------------------------------------
# Real anonymized PAM / JumpServer JSONL
# ---------------------------------------------------------------------------

def load_pam_dataset(path: str | Path) -> Tuple[EventList, Counts]:
    """Load anonymized PAM events (JSON array or JSONL) with required label field."""
    from ..web.log_analyzer import parse_log_content

    p = Path(path)
    if p.is_dir():
        candidates = list(p.glob('*.jsonl')) + list(p.glob('*.json'))
        if not candidates:
            raise FileNotFoundError(f'No .jsonl/.json in {p}')
        p = candidates[0]

    events = parse_log_content(p.read_text(encoding='utf-8'))
    normalized: EventList = []
    for i, e in enumerate(events):
        if 'label' not in e:
            raise ValueError(
                f'Event #{i+1} missing "label" (0=normal, 1=anomaly). '
                'Anonymized PAM exports must include labels for supervised training.'
            )
        e = dict(e)
        e.setdefault('metadata', {})
        if isinstance(e['metadata'], dict):
            e['metadata'].setdefault('source', 'pam_real')
        e.setdefault('anomaly_type', 'anomaly' if int(e['label']) == 1 else 'normal')
        e.setdefault('event_type', 'command.ingested')
        e.setdefault('user_id', 'unknown')
        e.setdefault('asset_id', 'unknown')
        e.setdefault('remote_addr', '0.0.0.0')
        e.setdefault('payload', {})
        normalized.append(e)
    return normalized, _counts(normalized)


# ---------------------------------------------------------------------------
# Unified entrypoint
# ---------------------------------------------------------------------------

SUPPORTED_SOURCES = ('synthetic', 'cert', 'lanl', 'pam')


def load_benchmark_dataset(
    source: str = 'synthetic',
    *,
    data_root: str | Path | None = None,
    seed: int = 42,
    max_events: Optional[int] = None,
    pam_path: str | Path | None = None,
) -> Tuple[EventList, Counts, dict]:
    """Load one dataset by name.

    Returns (events, counts, meta) where meta documents provenance for papers.
    """
    source = (source or 'synthetic').lower().strip()
    root = Path(data_root) if data_root else Path(__file__).resolve().parents[2] / 'data' / 'datasets'
    meta = {'source': source, 'data_root': str(root), 'seed': seed}

    if source == 'synthetic':
        events, counts = generate_pam_dataset(seed=seed)
        meta['reproducible'] = True
        meta['note'] = 'Deterministic synthetic PAM (seed fixed).'
    elif source == 'cert':
        events, counts = load_cert_dataset(
            root / 'cert',
            max_events=max_events if max_events is not None else 50_000,
            seed=seed,
        )
        meta['reproducible'] = True
        meta['note'] = 'CERT r4.2 logon mapped to CyberVault; labels from answers.json / insiders.'
    elif source == 'lanl':
        events, counts = load_lanl_dataset(
            root / 'lanl',
            max_events=max_events if max_events is not None else 150_000,
        )
        meta['reproducible'] = True
        meta['note'] = 'LANL cyber1 auth sample + redteam users; full auth is 7GB+.'
    elif source == 'pam':
        path = pam_path or (root / 'pam')
        events, counts = load_pam_dataset(path)
        meta['reproducible'] = False
        meta['note'] = 'Organization-specific anonymized PAM; share schema not raw IPs.'
    else:
        raise ValueError(f'Unknown source={source!r}. Choose one of {SUPPORTED_SOURCES}')

    meta['summary'] = summarize_events(events)
    # Deterministic shuffle so train/test splits are stable across runs
    import random as _random
    rng = _random.Random(seed)
    events = list(events)
    rng.shuffle(events)
    return events, counts, meta
