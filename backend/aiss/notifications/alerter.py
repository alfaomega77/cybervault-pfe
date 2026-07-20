"""Email alerts for real-time security events."""

import json
import logging
import os
import smtplib
import threading
from html import escape
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid, parseaddr
from pathlib import Path
from typing import Optional

from ..config import settings
from ..pipeline.event_context import build_event_context
from ..web.config_store import load_user_config

logger = logging.getLogger('aiss.alerts')
_ALERT_LOCK = threading.RLock()

DEDUP_PATH = Path(settings.decision_log_path).parent / 'alert_dedup.json'
OUTBOX_PATH = Path(settings.decision_log_path).parent / 'alert_outbox.jsonl'


# Actions that always warrant an analyst email (MOO alert / lock / kill path).
_ALERT_ACTIONS = frozenset({
    'ALERT_ANALYST',
    'CREATE_TICKET',
    'LOCK_SESSION',
    'KILL_SESSION',
})
# Match policy risk_levels.high — benign LOG_ONLY noise (pwd/ls ~0.4) must not email.
_HIGH_RISK_SCORE = 0.75


def is_security_alert(decision: dict) -> bool:
    """True only for analyst-facing actions or high risk — not routine LOG_ONLY."""
    action = decision.get('action', '')
    if action in _ALERT_ACTIONS:
        return True
    score = float(decision.get('risk_score', 0) or 0)
    return score >= _HIGH_RISK_SCORE


def is_live_event(event: dict) -> bool:
    metadata = event.get('metadata') or {}
    if metadata.get('source') == 'log_replay':
        return False
    if metadata.get('test') is True:
        return False
    # UI smoke tests must not spam analysts; client demo simulation should notify.
    if metadata.get('source') in ('cybervault_verify', 'cybervault_ui_test'):
        return False
    return True


class AlertNotifier:
    def __init__(self):
        self._dedup = self._load_dedup()

    def _load_dedup(self) -> dict:
        if not DEDUP_PATH.exists():
            return {}
        try:
            return json.loads(DEDUP_PATH.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_dedup(self):
        with _ALERT_LOCK:
            DEDUP_PATH.parent.mkdir(parents=True, exist_ok=True)
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            self._dedup = {k: v for k, v in self._dedup.items() if v >= cutoff}
            temporary = DEDUP_PATH.with_suffix(f'{DEDUP_PATH.suffix}.tmp')
            temporary.write_text(
                json.dumps(self._dedup, ensure_ascii=False, indent=2),
                encoding='utf-8',
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, DEDUP_PATH)

    def _claim_notification(self, event_id: str) -> bool:
        """Return True once per event_id (thread-safe)."""
        if not event_id:
            return True
        with _ALERT_LOCK:
            if event_id in self._dedup:
                return False
            self._dedup[event_id] = datetime.now(timezone.utc).isoformat()
            DEDUP_PATH.parent.mkdir(parents=True, exist_ok=True)
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            self._dedup = {k: v for k, v in self._dedup.items() if v >= cutoff}
            temporary = DEDUP_PATH.with_suffix(f'{DEDUP_PATH.suffix}.tmp')
            temporary.write_text(
                json.dumps(self._dedup, ensure_ascii=False, indent=2),
                encoding='utf-8',
            )
            os.chmod(temporary, 0o600)
            os.replace(temporary, DEDUP_PATH)
            return True

    def notify_if_needed(self, event: dict, decision: dict, execution: dict) -> dict:
        cfg = load_user_config()
        if not cfg.get('notify_email', True):
            return {'sent': False, 'reason': 'notifications_disabled'}

        metadata = event.get('metadata') or {}
        # Client live simulation sends one summary email at the end (better deliverability).
        if metadata.get('demo') == 'client_live_simulation':
            return {'sent': False, 'reason': 'deferred_demo_summary'}

        if not is_live_event(event):
            return {'sent': False, 'reason': 'not_live_event'}

        if not is_security_alert(decision):
            return {'sent': False, 'reason': 'below_alert_threshold'}

        event_id = event.get('event_id') or ''
        # Claim before send so concurrent duplicate events cannot spam email.
        if not self._claim_notification(event_id):
            return {'sent': False, 'reason': 'already_notified'}

        results = {'sent': False, 'email': None}
        body = self._build_message(event, decision, execution)

        if cfg.get('notify_email', True):
            email = (cfg.get('alert_email') or '').strip()
            if email:
                results['email'] = self._send_email(email, body['subject'], body['text'], body['html'])
                if results['email'].get('ok'):
                    results['sent'] = True

        self._write_outbox(event, decision, results, body)
        return results

    def _build_message(self, event: dict, decision: dict, execution: dict) -> dict:
        ctx = build_event_context(event)
        score = int(float(decision.get('risk_score', 0) or 0) * 100)
        action = decision.get('action', 'NO_ACTION')
        reasons = ', '.join(decision.get('reasons') or []) or '—'
        user = ctx.get('user_id') or event.get('user_id') or '—'
        asset = ctx.get('asset_name') or ctx.get('asset_id') or '—'
        ip = ctx.get('remote_addr') or '—'
        cmd = ctx.get('command') or '—'
        session = event.get('session_id') or '—'

        subject_user = str(user).replace('\r', ' ').replace('\n', ' ')[:120]
        subject = f'[CyberVault] Alerte sécurité — risque {score}% — {subject_user}'
        text = f"""Alerte CyberVault — accès privilégié

Risque : {score}%
Action : {action}
Utilisateur : {user}
IP : {ip}
Serveur : {asset}
Compte : {ctx.get('account') or '—'}
Commande : {cmd}
Session : {session}
Raisons : {reasons}

Tableau de bord : {settings.public_url.rstrip('/')}/app.html
"""
        safe = {key: escape(str(value)) for key, value in {
            'action': action,
            'user': user,
            'ip': ip,
            'asset': asset,
            'account': ctx.get('account') or '—',
            'command': cmd,
            'session': session,
            'reasons': reasons,
            'dashboard': f"{settings.public_url.rstrip('/')}/app.html",
        }.items()}
        html = f"""<html><body style="font-family:Arial,sans-serif;color:#172033;">
<h2 style="color:#c62828;">Alerte CyberVault</h2>
<p><strong>Risque :</strong> {score}% &nbsp;|&nbsp; <strong>Action :</strong> {safe['action']}</p>
<table cellpadding="6">
<tr><td>Utilisateur</td><td>{safe['user']}</td></tr>
<tr><td>IP source</td><td>{safe['ip']}</td></tr>
<tr><td>Serveur</td><td>{safe['asset']}</td></tr>
<tr><td>Compte</td><td>{safe['account']}</td></tr>
<tr><td>Commande</td><td><code>{safe['command']}</code></td></tr>
<tr><td>Session</td><td>{safe['session']}</td></tr>
<tr><td>Raisons</td><td>{safe['reasons']}</td></tr>
</table>
<p><a href="{safe['dashboard']}">Ouvrir le tableau de bord</a></p>
</body></html>"""
        return {'subject': subject, 'text': text, 'html': html}

    def _send_email(self, to_addr: str, subject: str, text: str, html: str) -> dict:
        return send_transactional_email(to_addr, subject, text, html)

    def _write_outbox(self, event: dict, decision: dict, results: dict, body: dict):
        OUTBOX_PATH.parent.mkdir(parents=True, exist_ok=True)
        record = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_id': event.get('event_id'),
            'risk_score': decision.get('risk_score'),
            'action': decision.get('action'),
            'results': results,
            'subject': body['subject'],
        }
        with _ALERT_LOCK:
            with OUTBOX_PATH.open('a', encoding='utf-8') as fp:
                fp.write(json.dumps(record, ensure_ascii=False) + '\n')

    def send_test_notification(self) -> dict:
        event = {
            'event_id': f'test-alert-{datetime.now(timezone.utc).timestamp()}',
            'event_type': 'command.ingested',
            'session_id': 'test-session',
            'user_id': 'admin-test',
            'account': 'root',
            'asset_name': 'demo-server',
            'remote_addr': '203.0.113.1',
            'protocol': 'ssh',
            'payload': {'input': 'rm -rf /tmp/test-alert'},
            'metadata': {'source': 'jumpserver'},
        }
        decision = {
            'action': 'ALERT_ANALYST',
            'risk_score': 0.85,
            'reasons': ['destructive_pattern:rm\\s+-rf', 'test_notification'],
        }
        execution = {'status': 'ok', 'detail': 'test'}
        return self.notify_if_needed(event, decision, execution)


def send_transactional_email(to_addr: str, subject: str, text: str, html: str) -> dict:
    def _clean_env(value: str) -> str:
        return (value or '').strip().strip('"').strip("'").strip()

    host = _clean_env(os.getenv('AISS_SMTP_HOST', ''))
    port = int(os.getenv('AISS_SMTP_PORT', '587') or '587')
    user = _clean_env(os.getenv('AISS_SMTP_USER', ''))
    password = _clean_env(os.getenv('AISS_SMTP_PASSWORD', ''))
    from_raw = _clean_env(os.getenv('AISS_SMTP_FROM', '')) or user or 'cybervault@localhost'
    from_name, from_email = parseaddr(from_raw)
    if not from_email or '@' not in from_email:
        from_email = user or 'cybervault@localhost'
        from_name = from_name or 'CyberVault'
    if not from_name:
        from_name = 'CyberVault'

    parsed_recipient = parseaddr(to_addr)[1].strip().lower()
    if not parsed_recipient or '@' not in parsed_recipient or '\n' in to_addr or '\r' in to_addr:
        return {'ok': False, 'error': 'invalid_recipient'}

    try:
        OUTBOX_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _ALERT_LOCK:
            with OUTBOX_PATH.open('a', encoding='utf-8') as fp:
                fp.write(json.dumps({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'type': 'transactional',
                    'to': parsed_recipient,
                    'subject': subject,
                }, ensure_ascii=False) + '\n')
    except OSError:
        logger.warning('Could not write email outbox')

    if not host:
        logger.warning('SMTP not configured (AISS_SMTP_HOST) — email saved to outbox only')
        return {'ok': False, 'error': 'smtp_not_configured', 'to': parsed_recipient}

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject.replace('\n', ' ').replace('\r', ' ')[:180]
    msg['From'] = formataddr((from_name, from_email))
    msg['To'] = parsed_recipient
    msg['Reply-To'] = from_email
    msg['Date'] = formatdate(localtime=False, usegmt=True)
    msg['Message-ID'] = make_msgid(domain=from_email.split('@')[-1])
    msg['MIME-Version'] = '1.0'
    msg['X-Mailer'] = 'CyberVault'
    msg['Auto-Submitted'] = 'auto-generated'
    msg.attach(MIMEText(text, 'plain', 'utf-8'))
    msg.attach(MIMEText(html, 'html', 'utf-8'))

    try:
        with smtplib.SMTP(host, port, timeout=20) as server:
            server.ehlo()
            if os.getenv('AISS_SMTP_TLS', 'true').lower() in ('1', 'true', 'yes'):
                server.starttls()
                server.ehlo()
            if user and password:
                server.login(user, password)
            # Envelope sender must be a bare address (improves deliverability).
            server.sendmail(from_email, [parsed_recipient], msg.as_string())
        logger.info('Transactional email sent to %s', parsed_recipient)
        return {'ok': True, 'to': parsed_recipient, 'from': from_email}
    except Exception as exc:
        logger.exception('Failed to send transactional email')
        return {'ok': False, 'error': str(exc), 'to': parsed_recipient}


_notifier: Optional[AlertNotifier] = None


def get_notifier() -> AlertNotifier:
    global _notifier
    if _notifier is None:
        _notifier = AlertNotifier()
    return _notifier
