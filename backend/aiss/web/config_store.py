"""User-facing configuration persisted for the web UI."""

import json
import os
import re
import threading
from pathlib import Path
from typing import Optional

from ..config import settings

DEFAULT_CONFIG = {
    'language': 'fr',
    'dry_run': True,
    'risk_sensitivity': 'medium',
    'alert_email': '',
    'notify_email': True,
    'corporate_ips': '10.0.0.0/8\n192.168.0.0/16',
    'monitor_logins': True,
    'monitor_commands': True,
    'monitor_sessions': True,
    'show_xai': True,
    'onboarding_complete': False,
    # JumpServer cloud integration
    'deploy_env': 'cloud',
    'cloud_provider': 'aws',
    'jumpserver_url': '',
    'jumpserver_token': '',
    'integration_mode': 'http',
    'integration_complete': False,
    'pam_live_active': False,
    'pam_live_started_at': None,
    'pam_live_stopped_at': None,
}

PUBLIC_CONFIG_KEYS = {
    'language', 'dry_run', 'risk_sensitivity', 'alert_email', 'notify_email',
    'corporate_ips', 'monitor_logins', 'monitor_commands', 'monitor_sessions',
    'show_xai', 'onboarding_complete', 'deploy_env', 'cloud_provider',
    'jumpserver_url', 'integration_mode', 'integration_complete',
    'pam_live_active', 'pam_live_started_at', 'pam_live_stopped_at',
}
USER_EDITABLE_KEYS = {
    'language', 'risk_sensitivity', 'alert_email', 'notify_email',
    'corporate_ips', 'monitor_logins', 'monitor_commands', 'monitor_sessions',
    'show_xai',
}
_LOCK = threading.RLock()
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def config_path() -> Path:
    return Path(settings.user_config_path)


def load_user_config() -> dict:
    with _LOCK:
        path = config_path()
        if not path.exists():
            return dict(DEFAULT_CONFIG)
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            merged = dict(DEFAULT_CONFIG)
            merged.update({key: value for key, value in data.items() if key in DEFAULT_CONFIG})
            return merged
        except (json.JSONDecodeError, OSError):
            return dict(DEFAULT_CONFIG)


def save_user_config(data: dict) -> dict:
    with _LOCK:
        merged = load_user_config()
        merged.update({key: value for key, value in data.items() if key in DEFAULT_CONFIG})
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f'{path.suffix}.tmp')
        temporary.write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding='utf-8')
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        return merged


def env_forces_dry_run() -> bool:
    """Server env AISS_DRY_RUN=true locks the product in safe mode."""
    return bool(settings.dry_run)


def effective_dry_run(config: Optional[dict] = None) -> bool:
    """True when LOCK/KILL must stay simulated."""
    if env_forces_dry_run():
        return True
    cfg = config or load_user_config()
    return bool(cfg.get('dry_run', True))


def save_user_preferences(data: dict) -> dict:
    """Persist only settings an authenticated user may edit."""
    cleaned = {key: value for key, value in data.items() if key in USER_EDITABLE_KEYS}
    if 'dry_run' in data:
        # Users may only disable dry-run when the server env allows live actions.
        if env_forces_dry_run():
            cleaned['dry_run'] = True
        else:
            cleaned['dry_run'] = bool(data.get('dry_run'))
    if 'alert_email' in cleaned:
        email = str(cleaned['alert_email'] or '').strip().lower()
        if email and (len(email) > 254 or not _EMAIL_RE.fullmatch(email)):
            raise ValueError('Adresse email d’alerte invalide')
        cleaned['alert_email'] = email
    if 'notify_email' in cleaned:
        cleaned['notify_email'] = bool(cleaned['notify_email'])
    if 'risk_sensitivity' in cleaned and cleaned['risk_sensitivity'] not in {'low', 'medium', 'high'}:
        raise ValueError('Sensibilité de risque invalide')
    return save_user_config(cleaned)


def public_user_config(config: Optional[dict] = None) -> dict:
    """Return browser-safe settings without API credentials."""
    current = config or load_user_config()
    result = {key: current.get(key) for key in PUBLIC_CONFIG_KEYS if key in current}
    result['jumpserver_token_configured'] = bool(current.get('jumpserver_token'))
    result['dry_run'] = effective_dry_run(current)
    result['dry_run_env_locked'] = env_forces_dry_run()
    result['action_mode'] = 'test' if result['dry_run'] else 'live'
    return result


def apply_default_onboarding(extra: Optional[dict] = None) -> dict:
    """Apply recommended defaults — no manual setup wizard needed."""
    defaults = {
        'language': 'fr',
        'dry_run': True,
        'risk_sensitivity': 'medium',
        'monitor_logins': True,
        'monitor_commands': True,
        'monitor_sessions': True,
        'show_xai': True,
        'corporate_ips': DEFAULT_CONFIG['corporate_ips'],
        'onboarding_complete': True,
    }
    if extra:
        defaults.update(extra)
    return save_user_config(defaults)
