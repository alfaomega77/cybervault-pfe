import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import requests

from ..config import settings
from ..notifications.alerter import get_notifier
from ..pipeline.event_context import build_event_context
from .jumpserver_auth import request_auth

logger = logging.getLogger('aiss.actions')
_DECISION_LOG_LOCK = threading.Lock()
_PROCESSED_EVENT_IDS: set = set()

class JumpServerClient:
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        self.base_url = (base_url or settings.jumpserver_url).rstrip('/')
        self.token = token or settings.jumpserver_token

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.token)

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        headers, auth = request_auth(self.token)
        kwargs.setdefault('timeout', 10)
        response = requests.request(method, url, headers=headers, auth=auth, **kwargs)
        response.raise_for_status()
        return response

    def kill_sessions(self, session_ids: List[str]) -> dict:
        url = f'{self.base_url}/api/v1/terminal/tasks/kill-session/'
        return self._request('POST', url, json=session_ids).json()

    def lock_session(self, session_id: str) -> dict:
        url = f'{self.base_url}/api/v1/terminal/tasks/toggle-lock-session/'
        payload = {'session_id': session_id, 'task_name': 'lock_session'}
        return self._request('POST', url, json=payload).json()


class ActionExecutor:
    def __init__(self, client: Optional[JumpServerClient] = None, dry_run: Optional[bool] = None):
        self.client = client or JumpServerClient()
        self.dry_run = settings.dry_run if dry_run is None else dry_run
        self.decision_log = Path(settings.decision_log_path)
        self.decision_log.parent.mkdir(parents=True, exist_ok=True)

    def execute(self, event: dict, decision: dict) -> dict:
        action = decision['action']
        result = {
            'action': action,
            'status': 'skipped',
            'detail': '',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

        if action == 'NO_ACTION':
            result['status'] = 'ok'
            result['detail'] = 'no action required'
        elif action == 'LOG_ONLY':
            result['status'] = 'ok'
            result['detail'] = 'logged only'
        elif action == 'ALERT_ANALYST':
            result['status'] = 'ok'
            result['detail'] = 'alert emitted (log sink in v0)'
        elif action == 'CREATE_TICKET':
            result['status'] = 'ok'
            result['detail'] = 'ticket action deferred to phase 2'
        elif action in ('LOCK_SESSION', 'KILL_SESSION'):
            session_id = event.get('session_id')
            if not session_id:
                result['status'] = 'error'
                result['detail'] = 'missing session_id'
            elif self.dry_run or not self.client.enabled:
                result['status'] = 'dry_run'
                result['detail'] = f'would execute {action} on {session_id}'
            else:
                try:
                    if action == 'KILL_SESSION':
                        payload = self.client.kill_sessions([session_id])
                    else:
                        payload = self.client.lock_session(session_id)
                    result['status'] = 'ok'
                    result['detail'] = json.dumps(payload)
                except requests.RequestException as exc:
                    result['status'] = 'error'
                    result['detail'] = str(exc)
        else:
            result['status'] = 'error'
            result['detail'] = f'unknown action {action}'

        metadata = event.get('metadata') or {}
        analysis_mode = 'historical' if metadata.get('source') == 'log_replay' else 'live'
        event_id = event.get('event_id')
        record = {
            'event_id': event_id,
            'session_id': event.get('session_id'),
            'event_type': event.get('event_type'),
            'user_id': event.get('user_id'),
            'context': build_event_context(event),
            'analysis_mode': analysis_mode,
            'decision': decision,
            'execution': result,
        }
        with _DECISION_LOG_LOCK:
            if event_id and event_id in _PROCESSED_EVENT_IDS:
                result['status'] = 'duplicate'
                result['detail'] = 'event already recorded'
                result['notification'] = {'sent': False, 'reason': 'duplicate_event'}
                return result
            if event_id:
                _PROCESSED_EVENT_IDS.add(event_id)
            with self.decision_log.open('a', encoding='utf-8') as fp:
                fp.write(json.dumps(record, ensure_ascii=False) + '\n')

        try:
            notification = get_notifier().notify_if_needed(event, decision, result)
            result['notification'] = notification
        except Exception:
            logger.exception('Email notification processing failed')
            result['notification'] = {'sent': False, 'reason': 'notification_error'}

        return result
