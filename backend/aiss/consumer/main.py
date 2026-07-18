import json
import logging
import sys
import time
from pathlib import Path

from aiss.config import settings
from aiss.pipeline.processor import EventProcessor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger('aiss.consumer')


def tail_file(path: str, processor: EventProcessor, from_start: bool = False):
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists():
        file_path.touch()

    logger.info('Tailing file: %s (dry_run=%s)', file_path, settings.dry_run)
    with file_path.open('r', encoding='utf-8') as fp:
        if not from_start:
            fp.seek(0, 2)
        while True:
            line = fp.readline()
            if not line:
                time.sleep(0.5)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                logger.warning('Skipping invalid JSON line')
                continue
            if isinstance(event, dict) and 'events' in event:
                for item in event['events']:
                    processor.process(item)
            else:
                processor.process(event)


def consume_redis(processor: EventProcessor):
    try:
        import redis
    except ImportError as exc:
        raise RuntimeError('redis package required for redis consumer mode') from exc

    client = redis.from_url(settings.redis_url)
    pubsub = client.pubsub()
    pubsub.subscribe(settings.redis_channel)
    logger.info('Subscribed to redis channel %s (dry_run=%s)', settings.redis_channel, settings.dry_run)

    for message in pubsub.listen():
        if message.get('type') != 'message':
            continue
        try:
            event = json.loads(message['data'])
        except (json.JSONDecodeError, TypeError):
            logger.warning('Skipping invalid redis payload')
            continue
        processor.process(event)


def main():
    processor = EventProcessor()
    mode = settings.consumer_mode.lower()

    if settings.http_ingest_enabled:
        from aiss.ingest.http_server import start_http_server_background
        start_http_server_background(port=settings.http_ingest_port)

    if mode == 'redis':
        consume_redis(processor)
        return

    events_file = settings.events_file
    if not events_file:
        repo_root = Path(__file__).resolve().parents[2]
        events_file = str(repo_root / 'data' / 'ai_security' / 'events.jsonl')

    from_start = '--from-start' in sys.argv
    tail_file(events_file, processor, from_start=from_start)


if __name__ == '__main__':
    main()
