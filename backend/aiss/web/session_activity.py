"""Session activity lookup for dashboard drill-down."""

import json
from pathlib import Path
from typing import Any, Dict, List

from ..config import settings


def _load_feature_store() -> dict:
    path = Path(settings.feature_store_path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return {}


def _commands_from_decisions(session_id: str) -> List[dict]:
    path = Path(settings.decision_log_path)
    if not path.exists() or not session_id:
        return []
    items: List[dict] = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get('session_id') != session_id:
            continue
        ctx = record.get('context') or {}
        cmd = (ctx.get('command') or '').strip()
        items.append({
            'event_id': record.get('event_id'),
            'event_type': record.get('event_type'),
            'timestamp': (record.get('execution') or {}).get('timestamp'),
            'command': cmd,
            'user_id': ctx.get('user_id') or record.get('user_id') or '',
            'account': ctx.get('account') or '',
            'remote_addr': ctx.get('remote_addr') or '',
            'asset': ctx.get('asset_name') or ctx.get('asset_id') or '',
        })
    return items


def get_session_activity(session_id: str) -> Dict[str, Any]:
    """Commands and events for a session (feature store + decision log)."""
    store = _load_feature_store()
    session_ctx = (store.get('sessions') or {}).get(session_id) or {}
    store_commands = list(session_ctx.get('commands') or [])

    decision_events = _commands_from_decisions(session_id)
    command_timeline: List[dict] = []

    for ev in decision_events:
        cmd = ev.get('command') or ''
        if cmd:
            command_timeline.append({
                'command': cmd,
                'timestamp': ev.get('timestamp'),
                'event_type': ev.get('event_type'),
                'event_id': ev.get('event_id'),
            })

    # Feature store may have commands not yet tied to a stored decision row.
    seen_cmds = {item['command'] for item in command_timeline}
    for cmd in store_commands:
        if cmd and cmd not in seen_cmds:
            command_timeline.append({
                'command': cmd,
                'timestamp': None,
                'event_type': 'command.ingested',
                'event_id': None,
            })
            seen_cmds.add(cmd)

    return {
        'session_id': session_id,
        'commands': store_commands,
        'command_timeline': command_timeline,
        'events': decision_events,
        'event_count': len(decision_events),
        'command_count': len(command_timeline) or len(store_commands),
    }
