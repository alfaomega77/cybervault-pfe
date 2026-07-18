import json
import os

from django.conf import settings

from common.utils import get_logger
from .base import BasePublisher

logger = get_logger(__name__)


class FilePublisher(BasePublisher):
    """Append-only JSONL sink for local development."""

    def publish(self, events):
        path = settings.AI_SECURITY_FILE_PATH
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, 'a', encoding='utf-8') as fp:
            for event in events:
                fp.write(json.dumps(event, ensure_ascii=False) + '\n')
        logger.debug('AI security: wrote %s events to %s', len(events), path)
        return True
