import json

import requests
from django.conf import settings

from common.utils import get_logger
from .base import BasePublisher

logger = get_logger(__name__)


class HttpPublisher(BasePublisher):
    def publish(self, events):
        url = settings.AI_SECURITY_WEBHOOK_URL
        if not url:
            logger.warning('AI security HTTP publisher enabled but AI_SECURITY_WEBHOOK_URL is empty')
            return False
        headers = {'Content-Type': 'application/json'}
        token = settings.AI_SECURITY_WEBHOOK_TOKEN
        if token:
            headers['Authorization'] = f'Bearer {token}'
        response = requests.post(
            url,
            data=json.dumps({'events': events}),
            headers=headers,
            timeout=settings.AI_SECURITY_WEBHOOK_TIMEOUT,
        )
        response.raise_for_status()
        logger.debug('AI security: published %s events to webhook', len(events))
        return True
