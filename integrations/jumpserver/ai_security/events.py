import uuid
from datetime import datetime, timezone

from django.conf import settings

from .const import EventType


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def base_envelope(event_type, org_id='', session_id='', user_id='', asset_id='',
                  account='', protocol='', remote_addr='', payload=None, metadata=None):
    return {
        'event_id': str(uuid.uuid4()),
        'event_type': event_type,
        'timestamp': _utc_now_iso(),
        'org_id': str(org_id) if org_id else '',
        'session_id': str(session_id) if session_id else '',
        'user_id': str(user_id) if user_id else '',
        'asset_id': str(asset_id) if asset_id else '',
        'account': account or '',
        'protocol': protocol or '',
        'remote_addr': remote_addr or '',
        'payload': payload or {},
        'metadata': {
            'source': 'jumpserver',
            'js_version': getattr(settings, 'VERSION', ''),
            **(metadata or {}),
        },
    }


def command_ingested_event(command_data, session=None):
    payload = {
        'input': command_data.get('input', ''),
        'output_b64': command_data.get('output', ''),
        'timestamp': command_data.get('timestamp'),
        'risk_level': command_data.get('risk_level'),
    }
    org_id = ''
    user_id = ''
    asset_id = ''
    account = command_data.get('account', '')
    protocol = ''
    remote_addr = ''
    if session is not None:
        org_id = session.org_id
        user_id = session.user_id
        asset_id = session.asset_id
        account = session.account or account
        protocol = session.protocol or ''
        remote_addr = session.remote_addr or ''
    return base_envelope(
        EventType.COMMAND_INGESTED,
        org_id=org_id,
        session_id=command_data.get('session', ''),
        user_id=user_id,
        asset_id=asset_id,
        account=account,
        protocol=protocol,
        remote_addr=remote_addr,
        payload=payload,
    )


def command_acl_violation_event(command_data, session=None):
    event = command_ingested_event(command_data, session=session)
    event['event_type'] = EventType.COMMAND_ACL_VIOLATION
    event['payload']['cmd_filter_acl'] = command_data.get('cmd_filter_acl')
    event['payload']['cmd_group'] = command_data.get('cmd_group')
    return event


def session_lifecycle_event(session, event_name, reason='', extra=None):
    return base_envelope(
        EventType.SESSION_LIFECYCLE,
        org_id=session.org_id,
        session_id=session.id,
        user_id=session.user_id,
        asset_id=session.asset_id,
        account=session.account,
        protocol=session.protocol,
        remote_addr=session.remote_addr,
        payload={
            'lifecycle_event': event_name,
            'reason': reason or '',
            **(extra or {}),
        },
    )


def session_start_event(session):
    event = session_lifecycle_event(session, 'session_created')
    event['event_type'] = EventType.SESSION_START
    return event


def session_end_event(session):
    event = session_lifecycle_event(session, 'session_finished')
    event['event_type'] = EventType.SESSION_END
    return event


def login_event(event_type, username, remote_addr='', login_type='', status=True, reason=''):
    return base_envelope(
        event_type,
        payload={
            'username': username,
            'login_type': login_type or '',
            'status': status,
            'reason': reason or '',
        },
        remote_addr=remote_addr,
    )
