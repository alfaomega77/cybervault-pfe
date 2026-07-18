import json

from django.conf import settings

from common.utils import get_logger
from common.utils.connection import RedisPubSub
from ai_security.const import SECURITY_EVENTS_REDIS_CHANNEL
from .base import BasePublisher

logger = get_logger(__name__)


class RedisPublisher(BasePublisher):
    def __init__(self):
        channel = settings.AI_SECURITY_REDIS_CHANNEL or SECURITY_EVENTS_REDIS_CHANNEL
        self.channel = RedisPubSub(channel)

    def publish(self, events):
        for event in events:
            self.channel.publish(event)
        logger.debug('AI security: published %s events to redis channel %s',
                     len(events), self.channel.ch)
        return True
