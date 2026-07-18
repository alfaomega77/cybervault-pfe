from django.conf import settings

from common.utils import get_logger

logger = get_logger(__name__)


def _enabled():
    return getattr(settings, 'AI_SECURITY_ENABLED', False)


def _publish(events):
    """Publish sync first (reliable), then queue Celery if available."""
    if not events:
        return
    try:
        from ai_security.publishers.factory import get_publisher
        get_publisher().publish(events)
    except Exception:
        logger.exception('AI security sync publish failed (%s events)', len(events))
    try:
        from ai_security.tasks import publish_security_events_task
        publish_security_events_task.delay(events)
    except Exception:
        logger.debug('AI security Celery queue unavailable; sync publish already attempted')


def dispatch_command_events(commands, acl_violation=False):
    if not _enabled() or not commands:
        return
    from ai_security.services.event_builder import build_command_events

    events = build_command_events(commands, acl_violation=acl_violation)
    _publish(events)


def dispatch_lifecycle_event(session, event_name, reason='', extra=None):
    if not _enabled():
        return
    from ai_security.services.event_builder import build_lifecycle_event

    event = build_lifecycle_event(session, event_name, reason=reason, extra=extra)
    _publish([event])


def dispatch_login_event(event_type, username, remote_addr='', login_type='', status=True, reason=''):
    if not _enabled():
        return
    from ai_security.events import login_event

    event = login_event(event_type, username, remote_addr=remote_addr,
                        login_type=login_type, status=status, reason=reason)
    _publish([event])
