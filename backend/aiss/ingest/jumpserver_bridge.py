"""Poll JumpServer API for commands and feed the CyberVault pipeline.

Clients only provide URL + API token in Mon PAM — no JumpServer config.yml required.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Set

import requests

from ..config import settings
from ..web.config_store import load_user_config

logger = logging.getLogger('aiss.jumpserver_bridge')

POLL_INTERVAL_SEC = 0.25
REQUEST_TIMEOUT_SEC = 2.5
SESSION_LIMIT = 10
COMMANDS_PER_SESSION = 20
MAX_SESSIONS_PER_LOOP = 4
# Per-session API is slower — only every Nth cycle; global feed is the fast path.
SESSION_SCAN_EVERY = 4


class JumpServerBridge:
    def __init__(self, process_event: Callable[[dict], object]):
        self._process_event = process_event
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._poll_lock = threading.Lock()
        self._run_id = 0
        self._cycle_n = 0
        self._seen: Set[str] = set()
        self._seen_path = Path(settings.integration_state_path).with_name('jumpserver_bridge_seen.txt')
        self._status = {
            'running': False,
            'last_poll_at': None,
            'last_poll_ok': False,
            'last_error': None,
            'commands_ingested': 0,
            'jumpserver_url': None,
        }
        self._load_seen()

    def _load_seen(self) -> None:
        try:
            if self._seen_path.exists():
                self._seen = {
                    line.strip()
                    for line in self._seen_path.read_text(encoding='utf-8').splitlines()
                    if line.strip()
                }
        except OSError:
            self._seen = set()

    def _claim_command(self, cid: str) -> bool:
        """Atomically claim a JumpServer command id. Returns False if already seen."""
        if not cid:
            return False
        with self._lock:
            if cid in self._seen:
                return False
            self._seen.add(cid)
        try:
            self._seen_path.parent.mkdir(parents=True, exist_ok=True)
            with self._seen_path.open('a', encoding='utf-8') as fh:
                fh.write(cid + '\n')
        except OSError as exc:
            logger.warning('bridge seen persist failed for %s: %s', cid, exc)
        return True

    def status(self) -> dict:
        with self._lock:
            return dict(self._status)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and not self._stop.is_set())

    def start(self) -> dict:
        cfg = load_user_config()
        url = (cfg.get('jumpserver_url') or settings.jumpserver_url or '').rstrip('/')
        token = (cfg.get('jumpserver_token') or settings.jumpserver_token or '').strip()
        if not url or not token:
            msg = 'URL et token JumpServer requis pour démarrer le bridge'
            with self._lock:
                self._status.update({'running': False, 'last_error': msg, 'last_poll_ok': False})
            return {'ok': False, 'error': msg, 'status': self.status()}

        with self._lock:
            if self._thread and self._thread.is_alive():
                self._stop.set()
                self._run_id += 1  # invalidate any overlapping old loop
                old = self._thread
            else:
                old = None
            self._stop = threading.Event()
            self._run_id += 1
            run_id = self._run_id
            self._status.update({
                'running': True,
                'last_error': None,
                'jumpserver_url': url,
            })
            self._thread = threading.Thread(
                target=self._loop,
                args=(url, token, run_id),
                name='jumpserver-bridge',
                daemon=True,
            )
        if old is not None:
            old.join(timeout=3)
        with self._lock:
            if run_id == self._run_id:
                self._thread.start()

        from ..web.integration_check import save_integration_state
        save_integration_state(
            bridge_active=True,
            bridge_started_at=datetime.now(timezone.utc).isoformat(),
            bridge_url=url,
        )
        logger.info('JumpServer bridge started → %s', url)
        return {'ok': True, 'status': self.status()}

    def stop(self) -> dict:
        with self._lock:
            self._stop.set()
            thread = self._thread
            self._status['running'] = False
        if thread and thread.is_alive():
            thread.join(timeout=5)
        from ..web.integration_check import save_integration_state
        save_integration_state(
            bridge_active=False,
            bridge_stopped_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.info('JumpServer bridge stopped')
        return {'ok': True, 'status': self.status()}

    def poll_once(self) -> dict:
        """Single poll for verify UI (does not require bridge thread)."""
        cfg = load_user_config()
        url = (cfg.get('jumpserver_url') or settings.jumpserver_url or '').rstrip('/')
        token = (cfg.get('jumpserver_token') or settings.jumpserver_token or '').strip()
        if not url or not token:
            return {'ok': False, 'error': 'URL et token JumpServer requis'}
        try:
            n = self._poll_cycle(url, token)
            return {'ok': True, 'commands_new': n, 'status': self.status()}
        except Exception as exc:
            with self._lock:
                self._status.update({
                    'last_poll_at': datetime.now(timezone.utc).isoformat(),
                    'last_poll_ok': False,
                    'last_error': str(exc),
                })
            return {'ok': False, 'error': str(exc), 'status': self.status()}

    def _js_get(self, base: str, token: str, path: str) -> dict:
        from ..actions.jumpserver_auth import request_auth

        headers, auth = request_auth(token)
        resp = requests.get(
            f'{base}{path}',
            headers=headers,
            auth=auth,
            timeout=REQUEST_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {}

    def _ingest_commands(self, commands: list, seen_in_batch: Set[str]) -> int:
        new_count = 0
        for cmd in commands:
            cid = str(cmd.get('id') or '')
            if not cid or cid in seen_in_batch:
                continue
            seen_in_batch.add(cid)
            inp = (cmd.get('input') or '').strip()
            if not inp:
                continue
            if not self._claim_command(cid):
                continue
            asset = cmd.get('asset') or ''
            event = {
                'event_id': f'js-cmd-{cid}',
                'event_type': 'command.ingested',
                'session_id': cmd.get('session') or '',
                'user_id': cmd.get('user') or '',
                'account': cmd.get('account') or '',
                'asset_name': str(asset).split('(')[0].strip(),
                'remote_addr': cmd.get('remote_addr') or '',
                'protocol': 'ssh',
                'payload': {'input': inp, 'timestamp': cmd.get('timestamp')},
                'metadata': {'source': 'jumpserver', 'bridge': 'api-poll'},
            }
            try:
                self._process_event(event)
                from ..web.integration_check import record_webhook_event
                record_webhook_event(is_test=False, event_id=event['event_id'])
                new_count += 1
                with self._lock:
                    self._status['commands_ingested'] = int(self._status.get('commands_ingested') or 0) + 1
            except Exception as exc:
                logger.warning('bridge process failed for %s: %s', cid, exc)
        return new_count

    def _loop(self, url: str, token: str, run_id: int) -> None:
        while not self._stop.is_set():
            with self._lock:
                if run_id != self._run_id:
                    break
            started = time.monotonic()
            try:
                self._poll_cycle(url, token)
            except Exception as exc:
                logger.warning('bridge poll error: %s', exc)
                with self._lock:
                    self._status.update({
                        'last_poll_at': datetime.now(timezone.utc).isoformat(),
                        'last_poll_ok': False,
                        'last_error': str(exc),
                    })
            elapsed = time.monotonic() - started
            self._stop.wait(max(0.05, POLL_INTERVAL_SEC - elapsed))
        with self._lock:
            if run_id == self._run_id:
                self._status['running'] = False

    def _poll_cycle(self, url: str, token: str) -> int:
        # Serialize polls so bridge thread + UI poll_once cannot race.
        with self._poll_lock:
            return self._poll_cycle_locked(url, token)

    def _poll_cycle_locked(self, url: str, token: str) -> int:
        self._cycle_n += 1
        seen_in_batch: Set[str] = set()
        new_count = 0

        # Fast path: global recent commands first, ingest immediately.
        try:
            recent = self._js_get(
                url,
                token,
                f'/api/v1/terminal/commands/?limit={COMMANDS_PER_SESSION}&order=-timestamp',
            )
            new_count += self._ingest_commands(recent.get('results') or [], seen_in_batch)
        except requests.RequestException as exc:
            logger.debug('global commands fetch: %s', exc)

        # Slower per-session scan less often (and only open sessions).
        if self._cycle_n % SESSION_SCAN_EVERY == 0:
            try:
                sessions = self._js_get(
                    url, token, f'/api/v1/terminal/sessions/?limit={SESSION_LIMIT}',
                )
                open_ids = [
                    s['id'] for s in (sessions.get('results') or [])
                    if not s.get('is_finished')
                ]
                for sid in open_ids[:MAX_SESSIONS_PER_LOOP]:
                    try:
                        data = self._js_get(
                            url,
                            token,
                            f'/api/v1/terminal/commands/?session_id={sid}'
                            f'&limit={COMMANDS_PER_SESSION}&order=-timestamp',
                        )
                        new_count += self._ingest_commands(
                            data.get('results') or [], seen_in_batch,
                        )
                    except requests.RequestException as exc:
                        logger.debug('commands fetch %s: %s', sid[:8], exc)
            except requests.RequestException as exc:
                logger.debug('sessions fetch: %s', exc)

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._status.update({
                'last_poll_at': now,
                'last_poll_ok': True,
                'last_error': None,
                'running': self.is_running() or self._status.get('running', False),
                'jumpserver_url': url,
            })
        from ..web.integration_check import save_integration_state
        save_integration_state(
            bridge_last_poll_at=now,
            bridge_last_poll_ok=True,
            bridge_commands_ingested=self._status.get('commands_ingested'),
        )
        return new_count


_bridge: Optional[JumpServerBridge] = None
_bridge_lock = threading.Lock()


def get_bridge(process_event: Optional[Callable[[dict], object]] = None) -> JumpServerBridge:
    global _bridge
    with _bridge_lock:
        if _bridge is None:
            if process_event is None:
                raise RuntimeError('JumpServerBridge requires process_event on first init')
            _bridge = JumpServerBridge(process_event)
        return _bridge


def start_bridge_if_configured(process_event: Callable[[dict], object]) -> dict:
    """Start bridge when Mon PAM is active with URL+token."""
    bridge = get_bridge(process_event)
    cfg = load_user_config()
    if not cfg.get('pam_live_active'):
        return {'ok': False, 'skipped': True, 'reason': 'pam_live_inactive'}
    url = (cfg.get('jumpserver_url') or settings.jumpserver_url or '').strip()
    token = (cfg.get('jumpserver_token') or settings.jumpserver_token or '').strip()
    if not url or not token:
        return {'ok': False, 'skipped': True, 'reason': 'missing_credentials'}
    return bridge.start()


def stop_bridge() -> dict:
    global _bridge
    with _bridge_lock:
        if _bridge is None:
            return {'ok': True, 'skipped': True}
        return _bridge.stop()
