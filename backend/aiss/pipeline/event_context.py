"""Extract client-facing context from PAM security events."""

from typing import Any, Dict

from .behavioral import event_hour_utc, normalize_remote_addr


def _payload_field(event: dict, *keys: str) -> str:
    payload = event.get('payload') or {}
    if not isinstance(payload, dict):
        return ''
    for key in keys:
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ''


def build_event_context(event: dict) -> Dict[str, Any]:
    """Normalize who / where / what for dashboards and exports."""
    metadata = event.get('metadata') or {}
    features = event.get('features') or {}
    payload = event.get('payload') or {}
    if not isinstance(payload, dict):
        payload = {}

    command = _payload_field(event, 'input', 'command', 'cmd')
    session_commands = list(features.get('recent_commands') or [])
    if command and (not session_commands or session_commands[-1] != command):
        if command not in session_commands:
            session_commands = session_commands + [command]

    hour = features.get('hour_utc')
    if hour is None:
        hour = event_hour_utc(event)

    return {
        'user_id': (event.get('user_id') or payload.get('username') or event.get('username') or '').strip(),
        'account': (event.get('account') or payload.get('account') or '').strip(),
        'asset_id': (event.get('asset_id') or event.get('asset') or '').strip(),
        'asset_name': (event.get('asset_name') or event.get('hostname') or '').strip(),
        'remote_addr': normalize_remote_addr(event),
        'protocol': (event.get('protocol') or '').strip(),
        'command': command,
        'session_commands': session_commands[-20:],
        'payload_username': str(payload.get('username') or '').strip(),
        'login_type': str(payload.get('login_type') or '').strip(),
        'login_status': payload.get('status'),
        'login_reason': str(payload.get('reason') or '').strip(),
        'event_timestamp': event.get('timestamp') or '',
        'hour_utc': hour,
        'org_id': str(event.get('org_id') or '').strip(),
        'source': metadata.get('source') or 'live',
        'filename': metadata.get('filename') or '',
    }
