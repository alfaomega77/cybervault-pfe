"""Rich event detail for dashboard drill-down (privileged login, etc.)."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..config import settings
from .session_activity import get_session_activity


def _load_baselines() -> Dict[str, dict]:
    path = Path(settings.baselines_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        return data.get('users') or {}
    except (json.JSONDecodeError, OSError):
        return {}


def _find_record(event_id: str) -> Optional[dict]:
    path = Path(settings.decision_log_path)
    if not path.exists() or not event_id:
        return None
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get('event_id') == event_id:
            return record
    return None


def _parse_hour_from_record(record: dict) -> Optional[int]:
    ctx = record.get('context') or {}
    if ctx.get('hour_utc') is not None:
        return int(ctx['hour_utc'])
    for reason in (record.get('decision') or {}).get('reasons') or []:
        if reason.startswith('unusual_hour:'):
            try:
                return int(reason.split(':', 1)[1])
            except ValueError:
                pass
    ts = ctx.get('event_timestamp') or (record.get('execution') or {}).get('timestamp')
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00')).hour
    except ValueError:
        return None


def _infer_user_id(record: dict, session_events: List[dict]) -> str:
    ctx = record.get('context') or {}
    user_id = (ctx.get('user_id') or record.get('user_id') or '').strip()
    if user_id:
        return user_id
    for ev in session_events:
        if ev.get('user_id'):
            return ev['user_id']
    return ''


def _typical_hours_label(histogram: dict, threshold: float = 0.05) -> List[int]:
    if not histogram:
        return []
    total = sum(int(v) for v in histogram.values())
    if total <= 0:
        return []
    hours = []
    for hour, count in histogram.items():
        if int(count) / total >= threshold:
            hours.append(int(hour))
    return sorted(hours)


def _missing_fields(ctx: dict) -> List[str]:
    labels = {
        'user_id': 'Utilisateur',
        'remote_addr': 'Adresse IP',
        'asset_id': 'Serveur (asset)',
        'account': 'Compte privilégié',
        'protocol': 'Protocole',
    }
    missing = []
    for key, label in labels.items():
        if not (ctx.get(key) or ctx.get('asset_name')):
            if key == 'asset_id' and ctx.get('asset_name'):
                continue
            missing.append(label)
    return missing


def _build_login_analysis(record: dict, baseline: Optional[dict], session: dict) -> dict:
    decision = record.get('decision') or {}
    ctx = record.get('context') or {}
    reasons = decision.get('reasons') or []
    hour = _parse_hour_from_record(record)
    risk = float(decision.get('risk_score', 0) or 0)
    action = decision.get('action', 'NO_ACTION')

    summary_parts = [
        "Tentative ou réussite de connexion à un accès privilégié (compte admin, root, service account, etc.).",
    ]

    if hour is not None:
        summary_parts.append(f"Connexion enregistrée vers {hour:02d}h UTC.")

    alert_reasons = []
    for reason in reasons:
        if reason == 'ml_not_trained':
            continue
        if reason.startswith('unusual_hour:'):
            unusual = reason.split(':', 1)[1]
            alert_reasons.append(
                f"Connexion à {unusual}h UTC — en dehors des plages horaires habituelles pour cet utilisateur."
            )
        elif reason.startswith('unusual_ip:'):
            alert_reasons.append(f"Adresse IP inhabituelle : {reason.split(':', 1)[1]}.")
        elif reason.startswith('unusual_asset:'):
            alert_reasons.append(f"Serveur inhabituel : {reason.split(':', 1)[1]}.")
        elif reason.startswith('unusual_account:'):
            alert_reasons.append(f"Compte inhabituel : {reason.split(':', 1)[1]}.")
        elif reason == 'baseline_warming_up':
            alert_reasons.append("Profil comportemental encore en construction — peu d'historique disponible.")
        else:
            alert_reasons.append(reason.replace('_', ' '))

    profile = None
    if baseline and int(baseline.get('event_count', 0)) > 0:
        typical = _typical_hours_label(baseline.get('hours_histogram') or {})
        profile = {
            'event_count': baseline.get('event_count', 0),
            'typical_hours_utc': typical,
            'typical_hours_label': (
                ', '.join(f"{h:02d}h" for h in typical) if typical else 'Pas encore établi'
            ),
            'known_assets': baseline.get('assets') or [],
            'known_accounts': baseline.get('accounts') or [],
            'known_ips': baseline.get('remote_addrs') or [],
            'session_count': len(baseline.get('session_ids') or []),
        }
        if typical and hour is not None and hour not in typical:
            alert_reasons.append(
                f"Habitudes : connexions habituelles vers {profile['typical_hours_label']} UTC."
            )

    if risk >= 0.7:
        severity = 'Élevée'
        recommendation = "Investigation prioritaire — vérifier l'identité de l'utilisateur et la légitimité de l'accès."
    elif risk >= 0.35:
        severity = 'Moyenne'
        recommendation = "Examiner la connexion — confirmer avec le propriétaire du compte si l'accès est attendu."
    else:
        severity = 'Faible'
        recommendation = "Surveillance standard — aucune action immédiate requise."

    if action == 'LOG_ONLY':
        recommendation += " Événement journalisé pour revue ultérieure."
    elif action in ('ALERT_ANALYST', 'LOCK_SESSION', 'KILL_SESSION'):
        recommendation += f" Action automatique : {action}."

    investigation = [
        "Vérifier si l'utilisateur était en astreinte ou en intervention planifiée.",
        "Croiser l'IP source avec les VPN / bureaux connus.",
        "Contrôler les commandes exécutées dans la même session (section ci-dessous).",
    ]
    if ctx.get('remote_addr'):
        investigation.insert(1, f"Rechercher l'IP {ctx['remote_addr']} dans les logs pare-feu / VPN.")
    if not session.get('command_count'):
        investigation.append(
            "Aucune commande shell liée — uploadez des logs command.ingested ou connectez JumpServer pour l'historique complet."
        )

    missing = _missing_fields(ctx)
    data_quality = (
        "Logs enrichis : toutes les métadonnées sont disponibles."
        if not missing
        else f"Logs partiels : champs manquants — {', '.join(missing)}. "
        "Connectez JumpServer en live ou exportez des logs complets (user_id, IP, asset, compte)."
    )

    return {
        'summary': ' '.join(summary_parts),
        'alert_reasons': alert_reasons,
        'severity': severity,
        'recommendation': recommendation,
        'investigation_steps': investigation,
        'data_quality': data_quality,
        'missing_fields': missing,
        'user_profile': profile,
        'connection_hour_utc': hour,
    }


def enrich_record_for_display(record: dict) -> dict:
    """Backfill context for older decision rows."""
    record = dict(record)
    ctx = dict(record.get('context') or {})
    if not ctx.get('user_id'):
        ctx['user_id'] = (record.get('user_id') or '').strip()
    if ctx.get('hour_utc') is None:
        hour = _parse_hour_from_record(record)
        if hour is not None:
            ctx['hour_utc'] = hour
    if not ctx.get('event_timestamp'):
        ctx['event_timestamp'] = (record.get('execution') or {}).get('timestamp') or ''
    record['context'] = ctx
    return record


def get_event_detail(event_id: str) -> Dict[str, Any]:
    record = _find_record(event_id)
    if not record:
        return {'ok': False, 'error': 'Événement introuvable'}

    record = enrich_record_for_display(record)
    session_id = record.get('session_id') or ''
    session = get_session_activity(session_id) if session_id else {
        'session_id': '', 'commands': [], 'command_timeline': [], 'events': [], 'event_count': 0, 'command_count': 0,
    }

    user_id = _infer_user_id(record, session.get('events') or [])
    baselines = _load_baselines()
    baseline = baselines.get(user_id) if user_id else None
    if not baseline and user_id != 'unknown':
        baseline = baselines.get('unknown')

    login_analysis = None
    if (record.get('event_type') or '') in ('privileged_login', 'privilege_escalation', 'login.success', 'login.failed'):
        login_analysis = _build_login_analysis(record, baseline, session)

    return {
        'ok': True,
        'record': record,
        'session': session,
        'baseline': baseline,
        'login_analysis': login_analysis,
    }
