import json

from django.conf import settings

from common.utils import get_logger
from .base import BasePublisher

logger = get_logger(__name__)


class KinesisPublisher(BasePublisher):
    def __init__(self):
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError('boto3 is required for Kinesis publisher') from exc
        self.client = boto3.client(
            'kinesis',
            region_name=settings.AI_SECURITY_AWS_REGION,
            aws_access_key_id=settings.AI_SECURITY_AWS_ACCESS_KEY_ID or None,
            aws_secret_access_key=settings.AI_SECURITY_AWS_SECRET_ACCESS_KEY or None,
        )
        self.stream_name = settings.AI_SECURITY_KINESIS_STREAM

    def publish(self, events):
        if not self.stream_name:
            logger.warning('AI security Kinesis publisher enabled but stream name is empty')
            return False
        for event in events:
            partition_key = event.get('session_id') or event.get('event_id')
            self.client.put_record(
                StreamName=self.stream_name,
                Data=json.dumps(event, ensure_ascii=False).encode('utf-8'),
                PartitionKey=partition_key[:128] or 'default',
            )
        logger.debug('AI security: published %s events to kinesis stream %s',
                     len(events), self.stream_name)
        return True
