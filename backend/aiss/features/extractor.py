"""Numerical feature vectors for ML models (privileged-access context)."""

import re
from typing import Dict, List, Optional, Tuple

from ..pipeline.behavioral import UserBaseline, event_hour_utc, normalize_remote_addr

FEATURE_NAMES = [
    'hour_norm',
    'session_command_count_norm',
    'user_total_commands_norm',
    'acl_violation',
    'destructive_command',
    'login_failed',
    'is_new_asset',
    'is_new_ip',
    'is_unusual_hour',
    'velocity_ratio',
    'lateral_asset_count_norm',
    'account_unknown',
]

_DESTRUCTIVE = re.compile(
    r'(?i)(\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?-r|\bdd\s+if=|\bmkfs\.|\bshutdown\b|\breboot\b)',
)


def _destructive(command: str) -> bool:
    return bool(_DESTRUCTIVE.search(command or ''))


def extract_feature_vector(
    event: dict,
    features: Optional[dict] = None,
    baseline: Optional[UserBaseline] = None,
) -> Tuple[List[float], Dict[str, float]]:
    features = features or {}
    hour = int(features.get('hour_utc', event_hour_utc(event)))
    session_count = int(features.get('session_command_count', 0))
    user_total = int(features.get('user_total_commands', 0))
    command = (event.get('payload') or {}).get('input', '') or ''
    asset_id = (event.get('asset_id') or '').strip()
    account = (event.get('account') or '').strip()
    remote_addr = normalize_remote_addr(event)
    event_type = event.get('event_type', '')

    is_new_asset = 0.0
    is_new_ip = 0.0
    is_unusual_hour = 0.0
    account_unknown = 0.0
    velocity_ratio = 0.0

    if baseline and baseline.event_count >= 5:
        if asset_id and baseline.assets and asset_id not in baseline.assets:
            is_new_asset = 1.0
        if remote_addr and baseline.remote_addrs and remote_addr not in baseline.remote_addrs:
            is_new_ip = 1.0
        typical = baseline.typical_hours(0.05)
        if typical and hour not in typical:
            is_unusual_hour = 1.0
        if account and baseline.accounts and account not in baseline.accounts:
            account_unknown = 1.0
        avg = baseline.avg_commands_per_session
        if avg > 0:
            velocity_ratio = min(session_count / avg, 5.0) / 5.0

    lateral_count = float(features.get('lateral_asset_count', 1))
    vector = [
        hour / 23.0,
        min(session_count / 50.0, 1.0),
        min(user_total / 500.0, 1.0),
        1.0 if features.get('is_acl_violation') else 0.0,
        1.0 if _destructive(command) else 0.0,
        1.0 if event_type == 'login.failed' else 0.0,
        is_new_asset,
        is_new_ip,
        is_unusual_hour,
        velocity_ratio,
        min(lateral_count / 6.0, 1.0),
        account_unknown,
    ]
    named = {name: value for name, value in zip(FEATURE_NAMES, vector)}
    return vector, named
