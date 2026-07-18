"""Batch replay of historical JumpServer-style event logs."""

import json
from datetime import datetime, timezone
from typing import List, Optional

from ..pipeline.processor import EventProcessor

MAX_EVENTS_PER_BATCH = 10_000


def _parse_jsonl(text: str) -> List[dict]:
    events = []
    errors = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line in ('[', ']', '{', '}', '[{', '}]', '},'):
            continue
        line = line.rstrip(',')
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            errors += 1
            continue
        if isinstance(item, dict) and 'events' in item:
            events.extend(item['events'])
        elif isinstance(item, dict):
            events.append(item)
    if errors and not events:
        raise ValueError(
            'Format non reconnu. Utilisez un fichier .json (tableau) ou .jsonl (une ligne par événement).'
        )
    return events


def parse_log_content(text: str) -> List[dict]:
    """Accept JSON array, JSON object, or JSONL (JumpServer exports)."""
    if not text or not text.strip():
        raise ValueError('Le fichier est vide')

    stripped = text.strip().lstrip('\ufeff')

    # Whole file: [ {...}, {...} ] or {"events": [...]}
    try:
        data = json.loads(stripped)
        if isinstance(data, list):
            events = [e for e in data if isinstance(e, dict)]
            if events:
                return events
        if isinstance(data, dict):
            if isinstance(data.get('events'), list):
                return [e for e in data['events'] if isinstance(e, dict)]
            return [data]
    except json.JSONDecodeError:
        pass

    events = _parse_jsonl(stripped)
    if events:
        return events

    raise ValueError(
        'Format non reconnu. Attendu : fichier .json avec un tableau d\'événements, '
        'ou .jsonl avec un objet JSON par ligne.'
    )


def _normalize_events(body: dict) -> List[dict]:
    if body.get('jsonl'):
        events = parse_log_content(body['jsonl'])
    elif body.get('events'):
        events = body['events']
    else:
        raise ValueError('Fournissez un fichier JSON ou JSONL')
    if not events:
        raise ValueError('Aucun événement trouvé dans le fichier')
    if len(events) > MAX_EVENTS_PER_BATCH:
        raise ValueError(f'Maximum {MAX_EVENTS_PER_BATCH} événements par analyse')
    return events


def replay_log_file(body: dict, processor: Optional[EventProcessor] = None) -> dict:
    processor = processor or EventProcessor()
    events = _normalize_events(body)
    filename = body.get('filename', 'upload.jsonl')
    batch_id = f"log-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    decisions = []
    alerts = 0
    high_risk = 0

    for raw in events:
        if not isinstance(raw, dict):
            continue
        event = dict(raw)
        meta = dict(event.get('metadata') or {})
        meta['source'] = 'log_replay'
        meta['batch'] = True
        meta['batch_id'] = batch_id
        meta['filename'] = filename
        event['metadata'] = meta

        decision, execution = processor.process(event)
        score = decision.get('risk_score', 0) or 0
        action = decision.get('action', '')
        if action not in ('NO_ACTION', 'LOG_ONLY') or score >= 0.35:
            alerts += 1
        if score >= 0.7:
            high_risk += 1

        record = {
            'event_id': event.get('event_id'),
            'session_id': event.get('session_id'),
            'event_type': event.get('event_type'),
            'decision': decision,
            'execution': execution,
            'batch_id': batch_id,
            'analysis_mode': 'historical',
        }
        decisions.append(record)

    return {
        'ok': True,
        'batch_id': batch_id,
        'filename': filename,
        'stats': {
            'total': len(decisions),
            'alerts': alerts,
            'high_risk': high_risk,
            'analyzed_at': datetime.now(timezone.utc).isoformat(),
        },
        'decisions': list(reversed(decisions[-50:])),
    }
