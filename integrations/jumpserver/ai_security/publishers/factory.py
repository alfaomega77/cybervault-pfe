from django.conf import settings

from ai_security.const import PublisherType
from .file_publisher import FilePublisher
from .http_publisher import HttpPublisher
from .kinesis_publisher import KinesisPublisher
from .redis_publisher import RedisPublisher


def get_publisher():
    publisher_type = settings.AI_SECURITY_PUBLISHER
    if publisher_type == PublisherType.REDIS:
        return RedisPublisher()
    if publisher_type == PublisherType.HTTP:
        return HttpPublisher()
    if publisher_type == PublisherType.KINESIS:
        return KinesisPublisher()
    return FilePublisher()
