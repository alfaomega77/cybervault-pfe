from django.db.models.signals import post_save
from django.dispatch import receiver

from authentication.signals import post_auth_failed, post_auth_success
from common.utils import get_request_ip, get_logger
from jumpserver.utils import current_request
from terminal.models import Session

from ai_security.const import EventType
from ai_security.dispatcher import dispatch_login_event, dispatch_lifecycle_event

logger = get_logger(__name__)


@receiver(post_save, sender=Session)
def on_session_saved(sender, instance: Session, created, **kwargs):
    if created:
        dispatch_lifecycle_event(instance, 'session_created')
        return
    if instance.is_finished:
        dispatch_lifecycle_event(instance, 'session_finished')


@receiver(post_auth_success)
def on_auth_success(sender, user, request, login_type=None, **kwargs):
    remote_addr = get_request_ip(request) if request else ''
    dispatch_login_event(
        EventType.LOGIN_SUCCESS,
        username=f'{user.name}({user.username})',
        remote_addr=remote_addr,
        login_type=login_type or '',
        status=True,
    )


@receiver(post_auth_failed)
def on_auth_failed(sender, username, request, reason='', **kwargs):
    remote_addr = get_request_ip(request) if request else ''
    dispatch_login_event(
        EventType.LOGIN_FAILED,
        username=username,
        remote_addr=remote_addr,
        status=False,
        reason=reason or '',
    )
