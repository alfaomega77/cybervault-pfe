from celery import shared_task
from django.utils.translation import gettext_lazy as _

from common.utils import get_logger
from ai_security.publishers.factory import get_publisher

logger = get_logger(__name__)


@shared_task(
    verbose_name=_('Publish AI security events'),
    description=_('Publish security events to the configured AI security sink'),
    ignore_result=True,
)
def publish_security_events_task(events):
    if not events:
        return
    try:
        publisher = get_publisher()
        publisher.publish(events)
    except Exception:
        logger.exception('Failed to publish %s AI security events', len(events))
