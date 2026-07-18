from terminal.models import Session

from ..events import (
    command_acl_violation_event,
    command_ingested_event,
    session_end_event,
    session_lifecycle_event,
    session_start_event,
)


def _session_map(session_ids):
    sessions = Session.objects.filter(id__in=session_ids).only(
        'id', 'org_id', 'asset_id', 'user_id', 'account', 'protocol', 'remote_addr'
    )
    return {str(item.id): item for item in sessions}


def build_command_events(commands, acl_violation=False):
    session_ids = {command.get('session') for command in commands if command.get('session')}
    session_mapper = _session_map(session_ids)
    events = []
    builder = command_acl_violation_event if acl_violation else command_ingested_event
    for command in commands:
        session = session_mapper.get(str(command.get('session')))
        events.append(builder(command, session=session))
    return events


def build_lifecycle_event(session, event_name, reason='', extra=None):
    return session_lifecycle_event(session, event_name, reason=reason, extra=extra)


def build_session_start_event(session):
    return session_start_event(session)


def build_session_end_event(session):
    return session_end_event(session)
