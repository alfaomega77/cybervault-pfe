"""Simple file-based auth for CyberVault web UI (MVP)."""

import hashlib
import json
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Optional

from ..config import settings

USERS_FILE = Path(settings.users_path)
SESSIONS_FILE = Path(settings.sessions_path)
RESETS_FILE = Path(settings.users_path).with_name('password_resets.json')
SESSION_TTL_HOURS = 72
RESET_TTL_MINUTES = 60
PASSWORD_ITERATIONS = 310_000
_LOCK = threading.RLock()
_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
GENERIC_RESET_MESSAGE = (
    'Si un compte existe pour cet email, un lien de réinitialisation a été envoyé.'
)


def _synchronized(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        with _LOCK:
            return func(*args, **kwargs)
    return wrapped


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('utf-8'), PASSWORD_ITERATIONS,
    )
    return f'pbkdf2_sha256${PASSWORD_ITERATIONS}${salt}${digest.hex()}'


def _verify_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split('$')
        if len(parts) == 4 and parts[0] == 'pbkdf2_sha256':
            iterations, salt, digest = int(parts[1]), parts[2], parts[3]
        elif len(parts) == 2:  # Backward compatibility with MVP accounts.
            salt, digest = parts
            iterations = 120_000
        else:
            return False
    except (ValueError, TypeError):
        return False
    check = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations,
    )
    return secrets.compare_digest(check.hex(), digest)


def _load_json(path: Path, default):
    with _LOCK:
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            return default


def _save_json(path: Path, data) -> None:
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f'{path.suffix}.tmp')
        temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)


@_synchronized
def signup_user(data: dict) -> dict:
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    if not _EMAIL_RE.fullmatch(email) or len(email) > 254:
        raise ValueError('Email invalide')
    if len(password) < 12 or len(password) > 256:
        raise ValueError('Mot de passe : 12 caractères minimum')

    store = _load_json(USERS_FILE, {'users': []})
    if any(u.get('email') == email for u in store['users']):
        raise ValueError('Un compte existe déjà avec cet email')
    allow_signup = os.getenv('AISS_ALLOW_SIGNUP', 'false').lower() in ('1', 'true', 'yes')
    if store['users'] and not allow_signup:
        raise ValueError('Les inscriptions sont fermées. Contactez votre administrateur.')

    user = {
        'id': str(uuid.uuid4()),
        'email': email,
        'first_name': (data.get('first_name') or '').strip(),
        'last_name': (data.get('last_name') or '').strip(),
        'company': (data.get('company') or '').strip(),
        'cloud_provider': data.get('cloud_provider') or 'aws',
        'query': (data.get('query') or '').strip(),
        'role': 'admin' if not store['users'] else 'analyst',
        'password_hash': _hash_password(password),
        'created_at': _now().isoformat(),
    }
    store['users'].append(user)
    _save_json(USERS_FILE, store)
    token = _create_session(user['id'])
    return {'user': _public_user(user), 'token': token}


@_synchronized
def login_user(email: str, password: str) -> dict:
    email = (email or '').strip().lower()
    store = _load_json(USERS_FILE, {'users': []})
    user = next((u for u in store['users'] if u.get('email') == email), None)
    if not user or not _verify_password(password, user.get('password_hash', '')):
        raise ValueError('Email ou mot de passe incorrect')
    token = _create_session(user['id'])
    return {'user': _public_user(user), 'token': token}


def _hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


@_synchronized
def request_password_reset(email: str) -> dict:
    """Always returns a generic success payload (no account enumeration)."""
    email = (email or '').strip().lower()
    result = {
        'ok': True,
        'message': GENERIC_RESET_MESSAGE,
        'email_sent': False,
        'smtp_configured': bool(os.getenv('AISS_SMTP_HOST', '').strip()),
    }
    if not _EMAIL_RE.fullmatch(email) or len(email) > 254:
        return result

    store = _load_json(USERS_FILE, {'users': []})
    user = next((u for u in store['users'] if u.get('email') == email), None)
    if not user:
        return result

    raw_token = secrets.token_urlsafe(32)
    resets = _load_json(RESETS_FILE, {'resets': {}})
    # Invalidate previous tokens for this user
    resets['resets'] = {
        k: v for k, v in resets.get('resets', {}).items()
        if v.get('user_id') != user['id']
    }
    resets['resets'][_hash_reset_token(raw_token)] = {
        'user_id': user['id'],
        'email': email,
        'expires_at': (_now() + timedelta(minutes=RESET_TTL_MINUTES)).isoformat(),
        'created_at': _now().isoformat(),
    }
    _save_json(RESETS_FILE, resets)

    base = (os.getenv('AISS_PUBLIC_URL') or settings.public_url or 'http://localhost:8090').rstrip('/')
    reset_url = f'{base}/reset-password.html?token={raw_token}'

    from ..notifications.alerter import send_transactional_email
    subject = 'CyberVault — réinitialisation du mot de passe'
    text = (
        f'Bonjour,\n\n'
        f'Une demande de réinitialisation a été faite pour {email}.\n'
        f'Ce lien expire dans {RESET_TTL_MINUTES} minutes :\n\n'
        f'{reset_url}\n\n'
        f'Si vous n\'êtes pas à l\'origine de cette demande, ignorez cet email.\n'
    )
    html = (
        f'<p>Bonjour,</p>'
        f'<p>Une demande de réinitialisation a été faite pour <strong>{email}</strong>.</p>'
        f'<p><a href="{reset_url}">Réinitialiser mon mot de passe</a></p>'
        f'<p>Ce lien expire dans {RESET_TTL_MINUTES} minutes.</p>'
        f'<p>Si vous n\'êtes pas à l\'origine de cette demande, ignorez cet email.</p>'
    )
    send_result = send_transactional_email(email, subject, text, html)
    result['email_sent'] = bool(send_result.get('ok'))
    # Local / demo fallback when SMTP is not configured
    if not result['smtp_configured']:
        result['reset_url'] = reset_url
        result['message'] = (
            'SMTP non configuré : utilisez le lien ci-dessous (valide 60 min). '
            'En production, configurez AISS_SMTP_* pour l’envoi par email.'
        )
    return result


@_synchronized
def reset_password(token: str, new_password: str) -> dict:
    token = (token or '').strip()
    if not token or len(token) > 200:
        raise ValueError('Lien de réinitialisation invalide ou expiré')
    if len(new_password) < 12 or len(new_password) > 256:
        raise ValueError('Mot de passe : 12 caractères minimum')

    resets = _load_json(RESETS_FILE, {'resets': {}})
    key = _hash_reset_token(token)
    entry = resets.get('resets', {}).get(key)
    if not entry:
        raise ValueError('Lien de réinitialisation invalide ou expiré')

    expires = datetime.fromisoformat(entry['expires_at'])
    if expires < _now():
        resets['resets'].pop(key, None)
        _save_json(RESETS_FILE, resets)
        raise ValueError('Lien de réinitialisation invalide ou expiré')

    store = _load_json(USERS_FILE, {'users': []})
    user = next((u for u in store['users'] if u.get('id') == entry.get('user_id')), None)
    if not user:
        raise ValueError('Lien de réinitialisation invalide ou expiré')

    user['password_hash'] = _hash_password(new_password)
    _save_json(USERS_FILE, store)

    # Consume token and drop all sessions for this user
    resets['resets'].pop(key, None)
    _save_json(RESETS_FILE, resets)
    sessions = _load_json(SESSIONS_FILE, {'sessions': {}})
    sessions['sessions'] = {
        k: v for k, v in sessions.get('sessions', {}).items()
        if v.get('user_id') != user['id']
    }
    _save_json(SESSIONS_FILE, sessions)

    return {'ok': True, 'message': 'Mot de passe mis à jour. Vous pouvez vous connecter.'}


@_synchronized
def _create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    store = _load_json(SESSIONS_FILE, {'sessions': {}})
    store['sessions'][token] = {
        'user_id': user_id,
        'expires_at': (_now() + timedelta(hours=SESSION_TTL_HOURS)).isoformat(),
    }
    _save_json(SESSIONS_FILE, store)
    return token


@_synchronized
def logout_user(token: str) -> None:
    store = _load_json(SESSIONS_FILE, {'sessions': {}})
    store['sessions'].pop(token, None)
    _save_json(SESSIONS_FILE, store)


@_synchronized
def get_user_by_token(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    store = _load_json(SESSIONS_FILE, {'sessions': {}})
    session = store['sessions'].get(token)
    if not session:
        return None
    expires = datetime.fromisoformat(session['expires_at'])
    if expires < _now():
        store['sessions'].pop(token, None)
        _save_json(SESSIONS_FILE, store)
        return None

    users = _load_json(USERS_FILE, {'users': []})['users']
    user = next((u for u in users if u.get('id') == session['user_id']), None)
    return _public_user(user) if user else None


def _public_user(user: dict) -> dict:
    return {
        'id': user.get('id'),
        'email': user.get('email'),
        'first_name': user.get('first_name'),
        'last_name': user.get('last_name'),
        'company': user.get('company'),
        'cloud_provider': user.get('cloud_provider'),
        'role': user.get('role') or 'admin',
    }
