"""Integration verification checks for JumpServer ↔ CyberVault."""

import json
import ipaddress
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

from ..config import settings
from ..pipeline.processor import EventProcessor
from ..web.config_store import load_user_config

STATE_PATH = Path(settings.integration_state_path)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load_state() -> dict:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return {}


def save_integration_state(**kwargs) -> dict:
    state = _load_state()
    state.update(kwargs)
    state['updated_at'] = _now().isoformat()
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding='utf-8')
    return state


def record_webhook_event(is_test: bool = False, event_id: Optional[str] = None) -> None:
    payload = {'last_webhook_at': _now().isoformat()}
    if is_test:
        payload['last_test_event_id'] = event_id
        payload['last_test_at'] = _now().isoformat()
    else:
        payload['last_jumpserver_event_at'] = _now().isoformat()
        payload['last_jumpserver_event_id'] = event_id
    save_integration_state(**payload)


def _check(label_id: str, label: str, status: str, detail: str, **extra) -> dict:
    item = {'id': label_id, 'label': label, 'status': status, 'detail': detail}
    item.update(extra)
    return item


def validate_jumpserver_url(url: str) -> str:
    """Validate the configured PAM endpoint and block cloud metadata targets."""
    parsed = urlparse((url or '').strip())
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('URL JumpServer invalide (HTTP ou HTTPS requis)')
    if parsed.username or parsed.password:
        raise ValueError('Les identifiants ne doivent pas être inclus dans l’URL')
    hostname = parsed.hostname.lower()
    if hostname in {'metadata.google.internal', 'metadata.aws.internal'}:
        raise ValueError('Cette adresse interne est interdite')
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address and (address.is_link_local or address.is_multicast or address.is_unspecified):
        raise ValueError('Cette adresse réseau est interdite')
    if str(address) == '169.254.169.254':
        raise ValueError('L’adresse de métadonnées cloud est interdite')
    return url.rstrip('/')


def check_jumpserver_url(url: str) -> dict:
    if not url:
        return _check(
            'jumpserver_url', 'JumpServer joignable', 'pending',
            'Renseignez l\'URL JumpServer ci-dessous puis relancez la vérification.',
        )
    try:
        base = validate_jumpserver_url(url)
    except ValueError as exc:
        return _check('jumpserver_url', 'JumpServer joignable', 'error', str(exc))
    for path in ('/api/health/', '/api/v1/health/', '/'):
        try:
            resp = requests.get(f'{base}{path}', timeout=8, allow_redirects=True)
            if resp.status_code < 500:
                return _check(
                    'jumpserver_url', 'JumpServer joignable', 'ok',
                    f'Réponse HTTP {resp.status_code} sur {base}{path}',
                    url=base,
                )
        except requests.RequestException:
            continue
    return _check(
        'jumpserver_url', 'JumpServer joignable', 'error',
        f'Impossible de joindre {base} — vérifiez l\'URL, le DNS et le firewall.',
    )


def check_jumpserver_token(url: str, token: str) -> dict:
    if not url:
        return _check('jumpserver_token', 'Token API JumpServer', 'pending', 'URL JumpServer requise.')
    if not token:
        return _check(
            'jumpserver_token', 'Token API JumpServer', 'warn',
            'Token non renseigné — OK en mode test (dry-run). Requis pour couper les sessions.',
        )
    from ..actions.jumpserver_auth import is_access_key, request_auth

    base = url.rstrip('/')
    headers, auth = request_auth(token)
    label = 'Access key JumpServer' if is_access_key(token) else 'Token API JumpServer'
    try:
        resp = requests.get(
            f'{base}/api/v1/users/profile/',
            headers=headers,
            auth=auth,
            timeout=10,
        )
        if resp.status_code == 200:
            return _check('jumpserver_token', label, 'ok', 'Identifiants valides — actions kill/lock possibles.')
        if resp.status_code == 401:
            return _check(
                'jumpserver_token', label, 'error',
                'Identifiants refusés (401) — vérifiez Access key (ID:Secret) ou Private Token.',
            )
        return _check('jumpserver_token', label, 'warn', f'Réponse inattendue HTTP {resp.status_code}.')
    except requests.RequestException as exc:
        return _check('jumpserver_token', label, 'error', f'Erreur réseau : {exc}')


def run_test_event(processor: EventProcessor) -> dict:
    event_id = f'cybervault-verify-{uuid.uuid4().hex[:12]}'
    event = {
        'event_id': event_id,
        'event_type': 'command.ingested',
        'timestamp': _now().isoformat(),
        'session_id': f'verify-session-{uuid.uuid4().hex[:8]}',
        'user_id': 'verify-user',
        'account': 'root',
        'protocol': 'ssh',
        'remote_addr': '10.0.0.99',
        'payload': {'input': 'rm -rf /tmp/cybervault-verify', 'timestamp': _now().timestamp()},
        'metadata': {'source': 'cybervault_verify', 'test': True},
    }
    decision, execution = processor.process(event)
    record_webhook_event(is_test=True, event_id=event_id)
    ok = decision.get('action') in ('KILL_SESSION', 'ALERT_ANALYST', 'LOCK_SESSION')
    status = 'ok' if ok else 'warn'
    return _check(
        'pipeline',
        'Pipeline IA (événement test)',
        status,
        f"Action : {decision.get('action')} — risque {int((decision.get('risk_score') or 0) * 100)}% — {execution.get('status')}",
        event_id=event_id,
        action=decision.get('action'),
        risk_score=decision.get('risk_score'),
    )


def check_live_jumpserver_events() -> dict:
    state = _load_state()
    last = state.get('last_jumpserver_event_at')
    if not last:
        return _check(
            'live_events',
            'Événements JumpServer en direct',
            'pending',
            'Aucun événement live reçu. Après Intégrer (URL+token), ouvrez une session SSH JumpServer et tapez une commande.',
            hint='CyberVault synchronise via l’API (pas besoin de config.yml). Attendez ~10 s puis vérifiez.',
        )
    try:
        ts = datetime.fromisoformat(last.replace('Z', '+00:00'))
    except ValueError:
        ts = None
    if ts and ts > _now() - timedelta(minutes=30):
        ago = int((_now() - ts).total_seconds())
        unit = 's' if ago < 120 else 'min'
        val = ago if unit == 's' else ago // 60
        return _check(
            'live_events',
            'Événements JumpServer en direct',
            'ok',
            f'Dernier événement live il y a {val} {unit} (id: {state.get("last_jumpserver_event_id", "—")})',
            last_event_at=last,
        )
    return _check(
        'live_events',
        'Événements JumpServer en direct',
        'warn',
        f'Dernier événement live : {last} — trop ancien. Vérifiez que le webhook JumpServer pointe vers CyberVault.',
        last_event_at=last,
    )


def run_all_checks(processor: Optional[EventProcessor] = None) -> dict:
    cfg = load_user_config()
    processor = processor or EventProcessor()
    state = _load_state()

    from ..ingest.jumpserver_bridge import get_bridge

    bridge_status = {}
    bridge_poll = None
    try:
        bridge = get_bridge(lambda event: processor.process(event))
        bridge_poll = bridge.poll_once()
        bridge_status = bridge.status()
    except Exception as exc:
        bridge_poll = {'ok': False, 'error': str(exc)}
        try:
            bridge_status = get_bridge().status()
        except RuntimeError:
            bridge_status = {'running': False}

    if bridge_status.get('running') and bridge_status.get('last_poll_ok'):
        bridge_check = _check(
            'bridge',
            'Bridge API JumpServer',
            'ok',
            'Sync active — dernier poll OK'
            + (
                f" ({bridge_status.get('commands_ingested', 0)} commandes)"
                if bridge_status.get('commands_ingested')
                else ''
            ),
            last_poll_at=bridge_status.get('last_poll_at'),
            jumpserver_url=bridge_status.get('jumpserver_url'),
            commands_ingested=bridge_status.get('commands_ingested'),
        )
    elif bridge_poll and bridge_poll.get('ok'):
        bridge_check = _check(
            'bridge',
            'Bridge API JumpServer',
            'ok',
            'Poll API réussi — la surveillance continue après Intégrer.',
            commands_new=bridge_poll.get('commands_new'),
        )
    elif not (cfg.get('jumpserver_url') and cfg.get('jumpserver_token')):
        bridge_check = _check(
            'bridge',
            'Bridge API JumpServer',
            'pending',
            'Renseignez URL + token API JumpServer — CyberVault synchronise sans config.yml.',
        )
    else:
        err = (bridge_poll or {}).get('error') or bridge_status.get('last_error') or 'poll échoué'
        bridge_check = _check(
            'bridge',
            'Bridge API JumpServer',
            'error',
            f'Impossible de synchroniser : {err}',
            hint='Vérifiez que JumpServer est joignable depuis CyberVault et que le token a les droits sessions/commands.',
        )

    checks = [
        _check('service', 'CyberVault actif', 'ok', 'Service en ligne — endpoint /health OK.'),
        _check(
            'webhook',
            'Webhook /events (optionnel)',
            'ok',
            f'Disponible en secours : {settings.public_url.rstrip("/")}/events'
            + (' (token requis)' if settings.webhook_token else ''),
            webhook_url=f'{settings.public_url.rstrip("/")}/events',
        ),
        bridge_check,
        run_test_event(processor),
        check_jumpserver_url(cfg.get('jumpserver_url', '')),
        check_jumpserver_token(cfg.get('jumpserver_url', ''), cfg.get('jumpserver_token', '')),
        check_live_jumpserver_events(),
    ]

    critical = [c for c in checks if c['id'] in ('service', 'bridge', 'jumpserver_url', 'pipeline')]
    if all(c['status'] == 'ok' for c in critical):
        overall = 'ok'
    elif any(c['status'] == 'error' for c in critical):
        overall = 'error'
    else:
        overall = 'partial'

    return {
        'overall': overall,
        'checks': checks,
        'integration_state': state,
        'bridge': bridge_status,
        'ready_for_dashboard': overall in ('ok', 'partial'),
        'live_ready': overall == 'ok',
    }


def connect_pam_docker() -> dict:
    """Legacy hook — live sync is handled by the API bridge (no host scripts)."""
    return {
        'ok': True,
        'skipped': True,
        'message': 'Sync live via bridge API — pas de config.yml JumpServer requise.',
    }


def send_live_test_event(processor: Optional[EventProcessor] = None) -> dict:
    """Simulate a JumpServer command event for UI testing."""
    processor = processor or EventProcessor()
    event_id = f'cybervault-ui-test-{uuid.uuid4().hex[:12]}'
    event = {
        'event_id': event_id,
        'event_type': 'command.ingested',
        'timestamp': _now().isoformat(),
        'session_id': f'ui-test-{uuid.uuid4().hex[:8]}',
        'user_id': 'ui-test-admin',
        'account': 'root',
        'asset_id': 'demo-server',
        'asset_name': 'demo-server',
        'protocol': 'ssh',
        'remote_addr': '10.0.0.99',
        'payload': {'input': 'rm -rf /tmp/cybervault-ui-test', 'timestamp': _now().timestamp()},
        'metadata': {'source': 'cybervault_ui_test'},
    }
    decision, execution = processor.process(event)
    record_webhook_event(is_test=False, event_id=event_id)
    return {
        'event_id': event_id,
        'action': decision.get('action'),
        'risk_score': decision.get('risk_score'),
        'status': execution.get('status'),
        'message': 'Événement test envoyé — consultez le tableau de bord Temps réel.',
    }


def run_client_live_simulation(
    processor: Optional[EventProcessor] = None,
    alert_email: str = '',
) -> dict:
    """Run a realistic 3-session live PoC for client trials (no JumpServer required).

    Uses the real AI pipeline. Emails are sent when SMTP + alert_email are set.
    LOCK/KILL stay in dry-run unless AISS_DRY_RUN=false and JumpServer token exists.
    """
    import os
    import time

    from ..notifications.alerter import is_security_alert
    from ..web.config_store import load_user_config, save_user_preferences

    processor = processor or EventProcessor()
    cfg = load_user_config()
    email = (alert_email or cfg.get('alert_email') or '').strip()
    if email and email != cfg.get('alert_email'):
        save_user_preferences({'alert_email': email, 'notify_email': True})

    stamp = uuid.uuid4().hex[:8]
    scenarios = [
        {
            'label': 'Session normale',
            'user_id': 'admin-demo',
            'command': 'whoami',
            'remote_addr': '10.0.0.50',
        },
        {
            'label': 'Session sensible',
            'user_id': 'admin-demo',
            'command': 'cat /etc/shadow',
            'remote_addr': '10.0.0.50',
        },
        {
            'label': 'Session à risque',
            'user_id': 'admin-demo',
            'command': 'rm -rf /var/log/*',
            'remote_addr': '203.0.113.99',
        },
    ]

    sessions = []
    for index, scenario in enumerate(scenarios, start=1):
        event_id = f'client-demo-{stamp}-{index}'
        session_id = f'sess-demo-{stamp}-{index}'
        event = {
            'event_id': event_id,
            'event_type': 'command.ingested',
            'timestamp': _now().isoformat(),
            'session_id': session_id,
            'user_id': scenario['user_id'],
            'account': 'root',
            'asset_id': 'lab-server',
            'asset_name': 'lab-server',
            'protocol': 'ssh',
            'remote_addr': scenario['remote_addr'],
            'payload': {
                'input': scenario['command'],
                'timestamp': _now().timestamp(),
            },
            'metadata': {
                'source': 'jumpserver',
                'demo': 'client_live_simulation',
            },
        }
        decision, execution = processor.process(event)
        record_webhook_event(is_test=False, event_id=event_id)
        sessions.append({
            'label': scenario['label'],
            'command': scenario['command'],
            'event_id': event_id,
            'session_id': session_id,
            'action': decision.get('action'),
            'risk_score': decision.get('risk_score'),
            'risk_pct': int(float(decision.get('risk_score') or 0) * 100),
            'execution_status': execution.get('status'),
            'execution_detail': execution.get('detail') or '',
            'alert': is_security_alert(decision),
            'email_sent': False,
            'email_detail': {},
        })
        if index < len(scenarios):
            time.sleep(0.35)

    smtp_configured = bool(os.getenv('AISS_SMTP_HOST', '').strip())
    email_result = {'ok': False, 'error': 'no_recipient'}
    email_preview = None
    emails_sent = 0

    if email:
        from ..notifications.alerter import send_transactional_email
        from html import escape as html_escape

        lines = []
        for s in sessions:
            lines.append(
                f"- {s['label']}: `{s['command']}` → risque {s['risk_pct']}% / {s['action']}"
            )
        subject = '[CyberVault] Résultat de votre test temps réel'
        text = (
            'Bonjour,\n\n'
            'Voici le résultat de votre test CyberVault (3 sessions privilégiées) :\n\n'
            + '\n'.join(lines)
            + '\n\n'
            'Ouvrez le tableau de bord pour le détail des décisions.\n'
            f"{os.getenv('AISS_PUBLIC_URL', 'http://localhost:8090').rstrip('/')}/app.html\n\n"
            '— Équipe CyberVault\n'
        )
        rows_html = ''.join(
            f"<tr><td>{html_escape(s['label'])}</td>"
            f"<td><code>{html_escape(s['command'])}</code></td>"
            f"<td>{s['risk_pct']}%</td>"
            f"<td>{html_escape(str(s['action']))}</td></tr>"
            for s in sessions
        )
        html = f"""<html><body style="font-family:Arial,sans-serif;color:#0f172a;">
<h2 style="color:#1d4ed8;">Test CyberVault terminé</h2>
<p>Voici le résumé des 3 sessions analysées par l’IA :</p>
<table cellpadding="8" cellspacing="0" style="border-collapse:collapse;border:1px solid #e2e8f0;">
<thead><tr style="background:#f8fafc;text-align:left;">
<th>Session</th><th>Commande</th><th>Risque</th><th>Action</th>
</tr></thead>
<tbody>{rows_html}</tbody>
</table>
<p style="margin-top:1rem;">Vérifiez aussi vos dossiers <strong>Spam / Indésirables</strong> si besoin.</p>
<p><a href="{html_escape(os.getenv('AISS_PUBLIC_URL', 'http://localhost:8090').rstrip('/'))}/app.html">Ouvrir le tableau de bord</a></p>
<p style="color:#64748b;font-size:12px;">— CyberVault PAM Risk Intelligence</p>
</body></html>"""
        email_result = send_transactional_email(email, subject, text, html)
        email_preview = {'subject': subject, 'text': text, 'to': email}
        if email_result.get('ok'):
            emails_sent = 1
            for s in sessions:
                if s.get('alert'):
                    s['email_sent'] = True
                    s['email_detail'] = email_result

    from ..web.config_store import effective_dry_run

    return {
        'ok': True,
        'sessions': sessions,
        'emails_sent': emails_sent,
        'smtp_configured': smtp_configured,
        'alert_email': email,
        'email_delivery': email_result,
        'email_preview': email_preview,
        'dry_run': effective_dry_run(cfg),
        'message': (
            'Test temps réel terminé — 3 sessions analysées. '
            + (
                f'Email récapitulatif envoyé à {email}.'
                if emails_sent
                else (
                    'Aucun email envoyé — vérifiez SMTP / adresse.'
                    if email
                    else 'Ajoutez un email pour recevoir le récapitulatif.'
                )
            )
        ),
    }
