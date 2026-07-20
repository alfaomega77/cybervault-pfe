"""User-defined abnormal behavior rules (command / hours / server / IP)."""

from __future__ import annotations

import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import settings

_LOCK = threading.Lock()

RULE_TYPES = {
    'command',
    'unusual_hours',
    'unusual_server',
    'unusual_ip',
    'custom',
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _path() -> Path:
    configured = getattr(settings, 'behavior_rules_path', '') or ''
    if configured:
        return Path(configured)
    return Path(settings.user_config_path).parent / 'behavior_rules.json'


def _empty() -> dict:
    return {'rules': [], 'updated_at': _now()}


def load_rules() -> dict:
    path = _path()
    if not path.exists():
        return _empty()
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            return _empty()
        rules = data.get('rules')
        if not isinstance(rules, list):
            data['rules'] = []
        return data
    except (OSError, json.JSONDecodeError):
        return _empty()


def list_enabled_rules() -> list[dict]:
    return [r for r in load_rules().get('rules', []) if r.get('enabled', True)]


def list_rules() -> list[dict]:
    return list(load_rules().get('rules', []))


def _validate_rule(payload: dict, *, partial: bool = False) -> dict:
    name = (payload.get('name') or '').strip()
    rule_type = (payload.get('type') or '').strip()
    pattern = (payload.get('pattern') or '').strip()
    if not partial:
        if not name:
            raise ValueError('Le nom de la règle est requis')
        if rule_type not in RULE_TYPES:
            raise ValueError(
                'Type invalide — choisissez : command, unusual_hours, '
                'unusual_server, unusual_ip, custom'
            )
        if not pattern:
            raise ValueError('La valeur / motif est requis')
    if rule_type and rule_type not in RULE_TYPES:
        raise ValueError('Type de règle invalide')
    if rule_type in ('command', 'custom') and pattern:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f'Expression régulière invalide : {exc}') from exc
    if rule_type == 'unusual_hours' and pattern:
        _parse_hours(pattern)  # validate
    risk = payload.get('risk_score', 0.8)
    try:
        risk_f = float(risk)
    except (TypeError, ValueError) as exc:
        raise ValueError('risk_score doit être un nombre entre 0 et 1') from exc
    if not 0.0 <= risk_f <= 1.0:
        raise ValueError('risk_score doit être entre 0 et 1')
    return {
        'name': name[:120],
        'type': rule_type,
        'pattern': pattern[:500],
        'risk_score': risk_f,
        'enabled': bool(payload.get('enabled', True)),
        'description': (payload.get('description') or '').strip()[:500],
    }


def _parse_hours(pattern: str) -> set[int]:
    """Parse '22,23,0,1' or '22-6' (overnight) into hour set."""
    hours: set[int] = set()
    raw = pattern.replace(' ', '')
    if not raw:
        raise ValueError('Indiquez les heures (ex. 22,23,0,1 ou 22-6)')
    for part in raw.split(','):
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            start, end = int(a), int(b)
            if not (0 <= start <= 23 and 0 <= end <= 23):
                raise ValueError('Heures hors plage 0–23')
            if start <= end:
                hours.update(range(start, end + 1))
            else:
                hours.update(range(start, 24))
                hours.update(range(0, end + 1))
        else:
            h = int(part)
            if not 0 <= h <= 23:
                raise ValueError('Heures hors plage 0–23')
            hours.add(h)
    if not hours:
        raise ValueError('Aucune heure valide')
    return hours


def save_rules(data: dict) -> dict:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = dict(data)
    data['updated_at'] = _now()
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    tmp.replace(path)
    return data


def create_rule(payload: dict) -> dict:
    fields = _validate_rule(payload)
    rule = {
        'id': str(uuid.uuid4()),
        **fields,
        'created_at': _now(),
        'updated_at': _now(),
    }
    with _LOCK:
        data = load_rules()
        rules = list(data.get('rules') or [])
        rules.insert(0, rule)
        data['rules'] = rules
        save_rules(data)
    return rule


def update_rule(rule_id: str, payload: dict) -> dict:
    with _LOCK:
        data = load_rules()
        rules = list(data.get('rules') or [])
        for i, rule in enumerate(rules):
            if rule.get('id') != rule_id:
                continue
            merged = {**rule, **payload, 'id': rule_id}
            fields = _validate_rule(merged)
            updated = {**rule, **fields, 'updated_at': _now()}
            rules[i] = updated
            data['rules'] = rules
            save_rules(data)
            return updated
    raise ValueError('Règle introuvable')


def delete_rule(rule_id: str) -> None:
    with _LOCK:
        data = load_rules()
        rules = [r for r in (data.get('rules') or []) if r.get('id') != rule_id]
        if len(rules) == len(data.get('rules') or []):
            raise ValueError('Règle introuvable')
        data['rules'] = rules
        save_rules(data)


def score_custom_rules(event: dict, types: Optional[set] = None) -> dict:
    """Evaluate user rules against an event. Optionally filter by rule types."""
    rules = list_enabled_rules()
    if types is not None:
        rules = [r for r in rules if r.get('type') in types]
    if not rules:
        return {'risk_score': 0.0, 'reasons': [], 'matched': []}

    payload = event.get('payload') or {}
    command = (payload.get('input') or '') or ''
    features = event.get('features') or {}
    hour = features.get('hour_utc')
    if hour is None:
        from ..pipeline.behavioral import event_hour_utc
        hour = event_hour_utc(event)
    hour = int(hour)
    asset_id = (event.get('asset_id') or '').strip()
    asset_name = (event.get('asset_name') or '').strip()
    remote_addr = (event.get('remote_addr') or '').strip()

    risk = 0.0
    reasons: list[str] = []
    matched: list[dict] = []

    for rule in rules:
        rtype = rule.get('type')
        pattern = (rule.get('pattern') or '').strip()
        name = rule.get('name') or 'règle'
        score = float(rule.get('risk_score') or 0.8)
        hit = False

        if rtype in ('command', 'custom'):
            try:
                if re.search(pattern, command, re.IGNORECASE):
                    hit = True
            except re.error:
                if pattern.lower() in command.lower():
                    hit = True
        elif rtype == 'unusual_hours':
            try:
                if hour in _parse_hours(pattern):
                    hit = True
            except ValueError:
                continue
        elif rtype == 'unusual_server':
            needle = pattern.lower()
            if needle and (
                needle in asset_id.lower()
                or needle in asset_name.lower()
                or asset_id.lower() == needle
                or asset_name.lower() == needle
            ):
                hit = True
        elif rtype == 'unusual_ip':
            from ..pipeline.behavioral import ip_in_whitelist
            # Reuse CIDR matcher: "whitelist" helper = membership check
            if remote_addr and ip_in_whitelist(remote_addr, [pattern]):
                hit = True
            elif remote_addr and pattern.lower() in remote_addr.lower():
                hit = True

        if hit:
            risk = max(risk, score)
            reasons.append(f'custom_rule:{name}')
            matched.append({'id': rule.get('id'), 'name': name, 'type': rtype})

    return {
        'risk_score': min(risk, 1.0),
        'reasons': reasons,
        'matched': matched,
    }
