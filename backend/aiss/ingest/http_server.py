"""HTTP ingest + web UI + REST API for CyberVault."""

import json
import hmac
import logging
import mimetypes
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from ..config import settings
from ..pipeline.processor import EventProcessor
from ..web.auth_store import (
    get_user_by_token,
    login_user,
    logout_user,
    request_password_reset,
    reset_password,
    signup_user,
)
from ..web.config_store import (
    apply_default_onboarding,
    load_user_config,
    public_user_config,
    save_user_config,
    save_user_preferences,
)
from ..web.integration_check import record_webhook_event, run_all_checks, validate_jumpserver_url
from ..web.event_detail import get_event_detail
from ..web.log_analyzer import replay_log_file
from ..web.session_activity import get_session_activity

logger = logging.getLogger('aiss.ingest')

_processor: Optional[EventProcessor] = None
WEB_ROOT = Path(settings.web_root)
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_EVENT_BATCH = 100
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_ATTEMPTS = 5
_LOGIN_ATTEMPTS = {}
_LOGIN_LOCK = threading.Lock()


class RequestTooLarge(ValueError):
    pass


def _login_rate_limited(client_ip: str) -> bool:
    now = time.monotonic()
    with _LOGIN_LOCK:
        attempts = [
            timestamp for timestamp in _LOGIN_ATTEMPTS.get(client_ip, [])
            if now - timestamp < LOGIN_WINDOW_SECONDS
        ]
        _LOGIN_ATTEMPTS[client_ip] = attempts
        return len(attempts) >= LOGIN_MAX_ATTEMPTS


def _record_login_failure(client_ip: str):
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.setdefault(client_ip, []).append(time.monotonic())


def _clear_login_failures(client_ip: str):
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(client_ip, None)


def get_processor() -> EventProcessor:
    global _processor
    if _processor is None:
        _processor = EventProcessor()
    return _processor


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict):
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    handler.send_response(status)
    handler.send_header('Content-Type', 'application/json; charset=utf-8')
    handler.send_header('Content-Length', str(len(body)))
    _send_security_headers(handler)
    handler.end_headers()
    handler.wfile.write(body)


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict:
    try:
        length = int(handler.headers.get('Content-Length', 0))
    except ValueError as exc:
        raise ValueError('Content-Length invalide') from exc
    if length < 0 or length > MAX_REQUEST_BYTES:
        raise RequestTooLarge(f'Requête limitée à {MAX_REQUEST_BYTES // 1024 // 1024} Mo')
    raw = handler.rfile.read(length).decode('utf-8') if length else '{}'
    payload = json.loads(raw) if raw else {}
    if not isinstance(payload, dict):
        raise ValueError('Le corps JSON doit être un objet')
    return payload


def _send_security_headers(handler: BaseHTTPRequestHandler):
    handler.send_header('X-Content-Type-Options', 'nosniff')
    handler.send_header('X-Frame-Options', 'DENY')
    handler.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
    handler.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    handler.send_header(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'",
    )


def _load_all_decisions() -> list:
    path = Path(settings.decision_log_path)
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _clear_decision_history() -> int:
    path = Path(settings.decision_log_path)
    removed = len(_load_all_decisions())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('', encoding='utf-8')
    return removed


def _load_decisions(limit: int = 50, alerts_only: bool = False) -> list:
    records = _load_all_decisions()
    if alerts_only:
        filtered = []
        for r in records:
            action = (r.get('decision') or {}).get('action', '')
            score = (r.get('decision') or {}).get('risk_score', 0) or 0
            if action not in ('NO_ACTION', 'LOG_ONLY') or score >= 0.35:
                filtered.append(r)
        records = filtered
    return list(reversed(records[-limit:]))


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except ValueError:
        return None


def _decision_stats(records: list) -> dict:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    all_records = _load_all_decisions()

    alerts_24h = 0
    high_risk_24h = 0
    last_ts = None
    seen_event_ids = set()

    for r in all_records:
        event_id = r.get('event_id')
        if event_id:
            seen_event_ids.add(event_id)

        action = (r.get('decision') or {}).get('action', '')
        score = (r.get('decision') or {}).get('risk_score', 0) or 0
        ts = _parse_ts((r.get('execution') or {}).get('timestamp'))

        if ts and (last_ts is None or ts > last_ts):
            last_ts = ts

        if not ts or ts < cutoff:
            continue

        is_alert = action not in ('NO_ACTION', 'LOG_ONLY') or score >= 0.35
        if is_alert:
            alerts_24h += 1
        if score >= 0.7:
            high_risk_24h += 1

    return {
        'total': len(all_records),
        'unique_events': len(seen_event_ids),
        'alerts_24h': alerts_24h,
        'high_risk': high_risk_24h,
        'last_activity': last_ts.isoformat() if last_ts else None,
    }


def _bearer_token(handler: BaseHTTPRequestHandler) -> Optional[str]:
    auth = handler.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:].strip()
    return None


def _integration_snippets() -> dict:
    base = settings.public_url.rstrip('/')
    token = settings.webhook_token or '<votre-token-secret>'
    webhook_url = f'{base}/events'
    mac_webhook = webhook_url.replace('localhost', 'host.docker.internal')
    jumpserver_cfg = f"""# Collez dans config.yml de JumpServer puis : jmsctl.sh restart
# (Mac Docker : utilisez host.docker.internal au lieu de localhost)
AI_SECURITY_ENABLED: true
AI_SECURITY_PUBLISHER: http
AI_SECURITY_WEBHOOK_URL: {mac_webhook if 'localhost' in base else webhook_url}
AI_SECURITY_WEBHOOK_TOKEN: {token}"""
    cybervault_env = f"""# Variables CyberVault (optionnel)
AISS_PUBLIC_URL={base}
AISS_DRY_RUN=true
AISS_JUMPSERVER_URL=https://jumpserver.votre-entreprise.com
AISS_JUMPSERVER_TOKEN=<token-api>
AISS_WEBHOOK_TOKEN={token}"""
    return {
        'webhook_url': webhook_url,
        'webhook_url_mac_docker': mac_webhook,
        'jumpserver_config': jumpserver_cfg,
        'cybervault_env': cybervault_env,
        'instructions_fr': [
            'Dans JumpServer : éditez config.yml avec le bloc ci-dessous',
            'Redémarrez JumpServer (jmsctl.sh restart ou docker restart jms_core)',
            'Ouvrez une session SSH dans JumpServer et tapez une commande',
            'Revenez ici et cliquez « Vérifier la connexion »',
        ],
    }


def _serve_static(handler: BaseHTTPRequestHandler, rel_path: str):
    if rel_path in ('', '/', 'index.html'):
        rel_path = 'index.html'
    file_path = (WEB_ROOT / rel_path).resolve()
    try:
        file_path.relative_to(WEB_ROOT.resolve())
    except ValueError:
        handler.send_error(403)
        return

    if not file_path.is_file():
        handler.send_error(404)
        return

    content = file_path.read_bytes()
    mime, _ = mimetypes.guess_type(str(file_path))
    handler.send_response(200)
    handler.send_header('Content-Type', mime or 'application/octet-stream')
    handler.send_header('Content-Length', str(len(content)))
    _send_security_headers(handler)
    if rel_path.startswith('static/'):
        handler.send_header('Cache-Control', 'public, max-age=3600')
    else:
        handler.send_header('Cache-Control', 'no-store')
    handler.end_headers()
    handler.wfile.write(content)


class IngestHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.debug(fmt, *args)

    def _check_webhook_auth(self) -> bool:
        token = settings.webhook_token
        if not token:
            logger.error('Webhook rejected: AISS_WEBHOOK_TOKEN is not configured')
            return False
        auth = self.headers.get('Authorization', '')
        return hmac.compare_digest(auth, f'Bearer {token}')

    def _require_api_user(self, role: Optional[str] = None) -> Optional[dict]:
        user = get_user_by_token(_bearer_token(self))
        if not user:
            _json_response(self, 401, {'ok': False, 'error': 'Session invalide ou expirée'})
            return None
        if role and user.get('role') != role:
            _json_response(self, 403, {'ok': False, 'error': 'Droits administrateur requis'})
            return None
        return user

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        if path in ('/health', '/health/'):
            data_path = Path(settings.decision_log_path).parent
            _json_response(self, 200, {
                'status': 'ok',
                'service': 'cybervault',
                'dry_run': settings.dry_run,
                'storage_ready': data_path.exists() and os.access(data_path, os.W_OK),
            })
            return

        if path.startswith('/api/') and path != '/api/auth/me':
            admin_paths = {
                '/api/config', '/api/integration/verify', '/api/integration/snippets',
            }
            if not self._require_api_user('admin' if path in admin_paths else None):
                return

        if path == '/api/integration/verify':
            try:
                result = run_all_checks(get_processor())
                _json_response(self, 200, {'ok': True, **result})
            except Exception as exc:
                logger.exception('integration verify failed')
                _json_response(self, 500, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/integration/snippets':
            _json_response(self, 200, _integration_snippets())
            return

        if path == '/api/auth/me':
            user = get_user_by_token(_bearer_token(self))
            if not user:
                _json_response(self, 401, {'error': 'Non authentifié'})
                return
            _json_response(self, 200, user)
            return

        if path == '/api/status':
            cfg = load_user_config()
            _json_response(self, 200, {
                'service_ok': True,
                # Env AISS_DRY_RUN is source of truth (same as ActionExecutor).
                'dry_run': bool(settings.dry_run),
                'onboarding_complete': cfg.get('onboarding_complete', False),
                'integration_complete': cfg.get('integration_complete', False),
                'pam_live_active': cfg.get('pam_live_active', False),
                'pam_live_started_at': cfg.get('pam_live_started_at'),
                'jumpserver_url': cfg.get('jumpserver_url', ''),
                'risk_sensitivity': cfg.get('risk_sensitivity', 'medium'),
            })
            return

        if path == '/api/config':
            _json_response(self, 200, public_user_config())
            return

        if path == '/api/decisions':
            qs = parse_qs(parsed.query)
            try:
                limit = int(qs.get('limit', ['50'])[0])
            except (TypeError, ValueError):
                _json_response(self, 400, {'ok': False, 'error': 'Paramètre limit invalide'})
                return
            limit = max(1, min(limit, 500))
            alerts_only = qs.get('alerts_only', ['0'])[0] in ('1', 'true', 'yes')
            records = _load_decisions(limit, alerts_only=alerts_only)
            _json_response(self, 200, {
                'decisions': records,
                'stats': _decision_stats(records),
                'shown': len(records),
            })
            return

        if path.startswith('/api/sessions/') and path.endswith('/activity'):
            session_id = path.split('/api/sessions/', 1)[1].rsplit('/activity', 1)[0]
            session_id = session_id.strip('/')
            if not session_id:
                _json_response(self, 400, {'ok': False, 'error': 'session_id requis'})
                return
            _json_response(self, 200, {'ok': True, **get_session_activity(session_id)})
            return

        if path.startswith('/api/events/') and path.endswith('/detail'):
            event_id = path.split('/api/events/', 1)[1].rsplit('/detail', 1)[0]
            event_id = event_id.strip('/')
            if not event_id:
                _json_response(self, 400, {'ok': False, 'error': 'event_id requis'})
                return
            result = get_event_detail(event_id)
            status = 200 if result.get('ok') else 404
            _json_response(self, status, result)
            return

        if path.startswith('/static/'):
            _serve_static(self, path.lstrip('/'))
            return

        if path.endswith('.html') or path == '/':
            name = 'index.html' if path == '/' else path.lstrip('/')
            _serve_static(self, name)
            return

        self.send_error(404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'

        public_api_paths = {
            '/api/auth/signup',
            '/api/auth/login',
            '/api/auth/forgot-password',
            '/api/auth/reset-password',
        }
        if path.startswith('/api/') and path not in public_api_paths:
            admin_paths = {
                '/api/config', '/api/integration/connect', '/api/integration/stop',
                '/api/integration/send-test-event', '/api/integration/test-alert',
                '/api/decisions/clear',
            }
            if not self._require_api_user('admin' if path in admin_paths else None):
                return

        if path == '/api/config':
            try:
                body = _read_json_body(self)
            except (json.JSONDecodeError, ValueError) as exc:
                _json_response(self, 400, {'ok': False, 'error': str(exc)})
                return
            saved = save_user_preferences(body)
            _json_response(self, 200, {'ok': True, 'config': public_user_config(saved)})
            return

        if path == '/api/auth/signup':
            try:
                body = _read_json_body(self)
                result = signup_user(body)
                apply_default_onboarding({
                    'alert_email': body.get('email', ''),
                    'notify_email': True,
                    'cloud_provider': body.get('cloud_provider', 'aws'),
                    'deploy_env': 'on_prem' if body.get('cloud_provider') == 'on_prem' else 'cloud',
                })
                _json_response(self, 200, {'ok': True, **result})
            except ValueError as exc:
                _json_response(self, 400, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/auth/login':
            client_ip = self.client_address[0]
            if _login_rate_limited(client_ip):
                _json_response(self, 429, {
                    'ok': False,
                    'error': 'Trop de tentatives. Réessayez dans quelques minutes.',
                })
                return
            try:
                body = _read_json_body(self)
                result = login_user(body.get('email', ''), body.get('password', ''))
                _clear_login_failures(client_ip)
                _json_response(self, 200, {'ok': True, **result})
            except ValueError as exc:
                _record_login_failure(client_ip)
                _json_response(self, 401, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/auth/forgot-password':
            client_ip = self.client_address[0]
            if _login_rate_limited(client_ip):
                _json_response(self, 429, {
                    'ok': False,
                    'error': 'Trop de tentatives. Réessayez dans quelques minutes.',
                })
                return
            try:
                body = _read_json_body(self)
                result = request_password_reset(body.get('email', ''))
                _json_response(self, 200, result)
            except (json.JSONDecodeError, ValueError) as exc:
                _record_login_failure(client_ip)
                _json_response(self, 400, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/auth/reset-password':
            client_ip = self.client_address[0]
            if _login_rate_limited(client_ip):
                _json_response(self, 429, {
                    'ok': False,
                    'error': 'Trop de tentatives. Réessayez dans quelques minutes.',
                })
                return
            try:
                body = _read_json_body(self)
                result = reset_password(body.get('token', ''), body.get('password', ''))
                _clear_login_failures(client_ip)
                _json_response(self, 200, result)
            except ValueError as exc:
                _record_login_failure(client_ip)
                _json_response(self, 400, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/auth/logout':
            logout_user(_bearer_token(self) or '')
            _json_response(self, 200, {'ok': True})
            return

        if path == '/api/integration/connect':
            user = get_user_by_token(_bearer_token(self))
            if not user:
                _json_response(self, 401, {'ok': False, 'error': 'Connectez-vous'})
                return
            from ..web.integration_check import connect_pam_docker, send_live_test_event
            try:
                body = _read_json_body(self) if self.headers.get('Content-Length') else {}
            except json.JSONDecodeError:
                body = {}
            try:
                url = validate_jumpserver_url(
                    (body.get('jumpserver_url') or 'http://localhost').strip(),
                )
            except ValueError as exc:
                _json_response(self, 400, {'ok': False, 'error': str(exc)})
                return
            token = (body.get('jumpserver_token') or '').strip()
            if not token:
                token = load_user_config().get('jumpserver_token', '')
            saved = save_user_config({
                'jumpserver_url': url,
                'jumpserver_token': token,
                'integration_complete': True,
                'pam_live_active': True,
                'pam_live_started_at': datetime.now(timezone.utc).isoformat(),
                'onboarding_complete': True,
                'dry_run': bool(settings.dry_run),
                'monitor_logins': True,
                'monitor_commands': True,
                'monitor_sessions': True,
            })
            docker_result = connect_pam_docker()
            test_result = send_live_test_event(get_processor())
            _json_response(self, 200, {
                'ok': True,
                'config': public_user_config(saved),
                'docker': docker_result,
                'test_event': test_result,
                'message': 'PAM intégré — ouvrez le tableau de bord Temps réel.',
            })
            return

        if path == '/api/integration/stop':
            saved = save_user_config({
                'pam_live_active': False,
                'pam_live_stopped_at': datetime.now(timezone.utc).isoformat(),
            })
            _json_response(self, 200, {'ok': True, 'config': public_user_config(saved)})
            return

        if path == '/api/integration/send-test-event':
            user = get_user_by_token(_bearer_token(self))
            if not user:
                _json_response(self, 401, {'ok': False, 'error': 'Connectez-vous'})
                return
            from ..web.integration_check import send_live_test_event
            try:
                result = send_live_test_event(get_processor())
                _json_response(self, 200, {'ok': True, **result})
            except Exception as exc:
                logger.exception('send test event failed')
                _json_response(self, 500, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/integration/demo-live':
            user = get_user_by_token(_bearer_token(self))
            if not user:
                _json_response(self, 401, {'ok': False, 'error': 'Connectez-vous'})
                return
            from ..web.integration_check import run_client_live_simulation
            try:
                body = _read_json_body(self) if self.headers.get('Content-Length') else {}
            except (json.JSONDecodeError, ValueError):
                body = {}
            try:
                result = run_client_live_simulation(
                    get_processor(),
                    alert_email=(body.get('alert_email') or user.get('email') or ''),
                )
                _json_response(self, 200, result)
            except Exception as exc:
                logger.exception('client live demo failed')
                _json_response(self, 500, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/integration/test-alert':
            user = get_user_by_token(_bearer_token(self))
            if not user:
                _json_response(self, 401, {'ok': False, 'error': 'Connectez-vous'})
                return
            from ..notifications.alerter import get_notifier
            try:
                result = get_notifier().send_test_notification()
                smtp_ok = os.getenv('AISS_SMTP_HOST', '')
                _json_response(self, 200, {
                    'ok': True,
                    'notification': result,
                    'smtp_configured': bool(smtp_ok),
                    'message': (
                        'Alerte test envoyée par email.'
                        if result.get('sent') and result.get('email', {}).get('ok')
                        else 'Alerte enregistrée. Configurez AISS_SMTP_* pour recevoir les emails.'
                    ),
                })
            except Exception as exc:
                logger.exception('test alert failed')
                _json_response(self, 500, {'ok': False, 'error': str(exc)})
            return

        if path == '/api/decisions/clear':
            user = get_user_by_token(_bearer_token(self))
            if not user:
                _json_response(self, 401, {'ok': False, 'error': 'Connectez-vous pour supprimer l\'historique'})
                return
            removed = _clear_decision_history()
            _json_response(self, 200, {'ok': True, 'removed': removed})
            return

        if path == '/api/analyze/replay':
            user = get_user_by_token(_bearer_token(self))
            if not user:
                _json_response(self, 401, {'ok': False, 'error': 'Connectez-vous pour analyser des logs'})
                return
            try:
                body = _read_json_body(self)
                result = replay_log_file(body, get_processor())
                _json_response(self, 200, result)
            except (ValueError, json.JSONDecodeError) as exc:
                _json_response(self, 400, {'ok': False, 'error': str(exc)})
            except Exception as exc:
                logger.exception('log replay failed')
                _json_response(self, 500, {'ok': False, 'error': str(exc)})
            return

        if path not in ('/events', '/events/'):
            self.send_error(404)
            return

        if not self._check_webhook_auth():
            self.send_error(401, 'Unauthorized')
            return

        try:
            body = _read_json_body(self)
        except RequestTooLarge as exc:
            _json_response(self, 413, {'ok': False, 'error': str(exc)})
            return
        except (json.JSONDecodeError, ValueError) as exc:
            self.send_error(400, f'Bad JSON: {exc}')
            return

        events = body.get('events', [body])
        if not isinstance(events, list) or not events or len(events) > MAX_EVENT_BATCH:
            _json_response(self, 400, {
                'ok': False,
                'error': f'events doit contenir entre 1 et {MAX_EVENT_BATCH} éléments',
            })
            return
        processor = get_processor()
        results = []
        for event in events:
            if not isinstance(event, dict):
                _json_response(self, 400, {'ok': False, 'error': 'Chaque événement doit être un objet JSON'})
                return
            required = ('event_id', 'event_type')
            missing = [field for field in required if not str(event.get(field) or '').strip()]
            if missing:
                _json_response(self, 400, {
                    'ok': False,
                    'error': f"Champs requis manquants : {', '.join(missing)}",
                })
                return
            is_test = (event.get('metadata') or {}).get('test') is True
            is_verify = (event.get('metadata') or {}).get('source') == 'cybervault_verify'
            if not is_test and not is_verify:
                record_webhook_event(is_test=False, event_id=event.get('event_id'))
            decision, execution = processor.process(event)
            results.append({
                'event_id': event.get('event_id'),
                'action': decision.get('action'),
                'risk_score': decision.get('risk_score'),
                'status': execution.get('status'),
            })

        _json_response(self, 200, {'ok': True, 'results': results})


def run_http_server(host: str = '0.0.0.0', port: int = 8090):
    server = ThreadingHTTPServer((host, port), IngestHandler)
    logger.info(
        'HTTP server on %s:%s (dry_run=%s, web=%s)',
        host, port, settings.dry_run, WEB_ROOT,
    )
    server.serve_forever()


def start_http_server_background(host: str = '0.0.0.0', port: int = 8090):
    thread = threading.Thread(target=run_http_server, args=(host, port), daemon=True)
    thread.start()
    return thread
