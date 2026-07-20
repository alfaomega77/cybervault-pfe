"""JumpServer API auth: Private Token or Access key (ID:Secret + HMAC signature)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from email.utils import formatdate
from typing import Any, Optional, Tuple
from urllib.parse import urlsplit

import requests

DEFAULT_ORG = '00000000-0000-0000-0000-000000000002'

# JumpServer Access key id is a UUID
_ACCESS_KEY_ID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


def parse_access_key(token: str) -> Optional[Tuple[str, str]]:
    """Return (key_id, secret) if token looks like JumpServer Access key ID:Secret."""
    raw = (token or '').strip()
    if ':' not in raw:
        return None
    key_id, _, secret = raw.partition(':')
    key_id, secret = key_id.strip(), secret.strip()
    if not key_id or not secret:
        return None
    if not _ACCESS_KEY_ID_RE.match(key_id):
        return None
    return key_id, secret


def is_access_key(token: str) -> bool:
    return parse_access_key(token) is not None


class _AccessKeySignatureAuth(requests.auth.AuthBase):
    """HTTP Signature auth for JumpServer Access keys (hmac-sha256)."""

    def __init__(self, key_id: str, secret: str):
        self.key_id = key_id
        self.secret = secret

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        date = formatdate(timeval=None, localtime=False, usegmt=True)
        r.headers['Date'] = date
        if 'Accept' not in r.headers and 'accept' not in r.headers:
            r.headers['Accept'] = 'application/json'

        parts = urlsplit(r.url or '')
        path = parts.path or '/'
        if parts.query:
            path = f'{path}?{parts.query}'
        method = (r.method or 'GET').lower()
        signing_string = f'(request-target): {method} {path}\ndate: {date}'
        digest = hmac.new(
            self.secret.encode('utf-8'),
            signing_string.encode('utf-8'),
            hashlib.sha256,
        ).digest()
        signature = base64.b64encode(digest).decode('ascii')
        r.headers['Authorization'] = (
            f'Signature keyId="{self.key_id}",algorithm="hmac-sha256",'
            f'headers="(request-target) date",signature="{signature}"'
        )
        return r


def request_auth(token: str) -> Tuple[dict, Any]:
    """
    Build headers + optional requests auth for a JumpServer call.

    - Access key ``ID:Secret`` → HTTP Signature (hmac-sha256)
    - Otherwise → ``Authorization: Token <token>`` (Private Token)
    """
    access = parse_access_key(token)
    if access:
        key_id, secret = access
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-JMS-ORG': DEFAULT_ORG,
        }
        return headers, _AccessKeySignatureAuth(key_id, secret)

    headers = {
        'Authorization': f'Token {(token or "").strip()}',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-JMS-ORG': DEFAULT_ORG,
    }
    return headers, None
