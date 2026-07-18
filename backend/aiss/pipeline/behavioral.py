"""Per-admin behavioral baselines and deviation scoring (Phase 2)."""

import ipaddress
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

from ..config import load_policy, settings


def event_hour_utc(event: dict) -> int:
    ts = event.get('timestamp')
    if ts:
        try:
            normalized = ts.replace('Z', '+00:00')
            return datetime.fromisoformat(normalized).astimezone(timezone.utc).hour
        except (ValueError, TypeError):
            pass
    return datetime.now(timezone.utc).hour


def normalize_remote_addr(event: dict) -> str:
    return (event.get('remote_addr') or '').strip()


def ip_in_whitelist(remote_addr: str, whitelist: List[str]) -> bool:
    if not remote_addr or not whitelist:
        return False
    try:
        addr = ipaddress.ip_address(remote_addr)
    except ValueError:
        return remote_addr in whitelist

    for entry in whitelist:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if '/' in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            if remote_addr == entry:
                return True
    return False


def risk_level_label(risk_score: float, policy: dict) -> str:
    levels = policy.get('risk_levels', {})
    if risk_score >= float(levels.get('high', 0.75)):
        return 'HIGH'
    if risk_score >= float(levels.get('medium', 0.55)):
        return 'MEDIUM'
    if risk_score >= float(levels.get('low', 0.25)):
        return 'LOW'
    return 'INFO'


@dataclass
class UserBaseline:
    user_id: str
    event_count: int = 0
    session_ids: Set[str] = field(default_factory=set)
    hours_histogram: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    assets: Set[str] = field(default_factory=set)
    accounts: Set[str] = field(default_factory=set)
    remote_addrs: Set[str] = field(default_factory=set)
    total_commands: int = 0
    failed_login_count: int = 0
    recent_failed_logins: int = 0
    last_failed_login_at: str = ''

    def to_dict(self) -> dict:
        return {
            'user_id': self.user_id,
            'event_count': self.event_count,
            'session_ids': sorted(self.session_ids),
            'hours_histogram': dict(self.hours_histogram),
            'assets': sorted(self.assets),
            'accounts': sorted(self.accounts),
            'remote_addrs': sorted(self.remote_addrs),
            'total_commands': self.total_commands,
            'failed_login_count': self.failed_login_count,
            'recent_failed_logins': self.recent_failed_logins,
            'last_failed_login_at': self.last_failed_login_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'UserBaseline':
        baseline = cls(user_id=data.get('user_id', 'unknown'))
        baseline.event_count = int(data.get('event_count', 0))
        baseline.session_ids = set(data.get('session_ids', []))
        baseline.hours_histogram = defaultdict(int, {
            int(k): v for k, v in (data.get('hours_histogram') or {}).items()
        })
        baseline.assets = set(data.get('assets', []))
        baseline.accounts = set(data.get('accounts', []))
        baseline.remote_addrs = set(data.get('remote_addrs', []))
        baseline.total_commands = int(data.get('total_commands', 0))
        baseline.failed_login_count = int(data.get('failed_login_count', 0))
        baseline.recent_failed_logins = int(data.get('recent_failed_logins', 0))
        baseline.last_failed_login_at = data.get('last_failed_login_at', '')
        return baseline

    @property
    def session_count(self) -> int:
        return len(self.session_ids)

    @property
    def avg_commands_per_session(self) -> float:
        if not self.session_ids:
            return 0.0
        return self.total_commands / len(self.session_ids)

    def typical_hours(self, threshold: float) -> Set[int]:
        if not self.hours_histogram:
            return set()
        total = sum(self.hours_histogram.values())
        if total <= 0:
            return set()
        return {
            hour for hour, count in self.hours_histogram.items()
            if (count / total) >= threshold
        }


class BaselineStore:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or settings.baselines_path)
        self.users: Dict[str, UserBaseline] = {}
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            for user_id, item in (data.get('users') or {}).items():
                self.users[user_id] = UserBaseline.from_dict(item)
        except (json.JSONDecodeError, OSError, TypeError, ValueError):
            pass

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            'users': {
                user_id: baseline.to_dict()
                for user_id, baseline in self.users.items()
            }
        }
        self.path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding='utf-8',
        )

    def get(self, user_id: str) -> UserBaseline:
        if user_id not in self.users:
            self.users[user_id] = UserBaseline(user_id=user_id)
        return self.users[user_id]


class BehavioralEngine:
    """Score privileged-user activity against learned per-user baselines."""

    def __init__(self, policy: Optional[dict] = None, store: Optional[BaselineStore] = None):
        self.policy = policy or load_policy()
        self.cfg = self.policy.get('behavioral', {})
        self.store = store or BaselineStore()
        self._recent_assets: Dict[str, Set[str]] = defaultdict(set)

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get('enabled', True))

    def score(self, event: dict) -> dict:
        if not self.enabled:
            return self._empty_assessment()

        user_id = event.get('user_id') or 'unknown'
        baseline = self.store.get(user_id)
        features = event.get('features') or {}
        event_type = event.get('event_type', '')
        hour = int(features.get('hour_utc', event_hour_utc(event)))
        asset_id = (event.get('asset_id') or '').strip()
        account = (event.get('account') or '').strip()
        session_id = event.get('session_id') or ''
        session_commands = int(features.get('session_command_count', 0))
        remote_addr = normalize_remote_addr(event)

        whitelist_ips = self.cfg.get('whitelist_ips', [])
        if remote_addr and ip_in_whitelist(remote_addr, whitelist_ips):
            return {
                'risk_score': 0.0,
                'confidence': 0.9,
                'reasons': ['corporate_ip_whitelist'],
                'model': 'behavioral_v1',
                'baseline_ready': True,
                'whitelisted': True,
            }

        min_events = int(self.cfg.get('min_events_for_scoring', 5))
        if baseline.event_count < min_events:
            return {
                'risk_score': 0.0,
                'confidence': 0.3,
                'reasons': ['baseline_warming_up'],
                'model': 'behavioral_v1',
                'baseline_ready': False,
            }

        signals = self.cfg.get('signals', {})
        risk = 0.0
        reasons: List[str] = []

        if event_type == 'login.failed':
            risk = max(risk, float(signals.get('login_failed', 0.55)))
            reasons.append('login_failed')
            if baseline.recent_failed_logins >= int(self.cfg.get('failed_login_burst_count', 3)):
                risk = max(risk, float(signals.get('login_failed_burst', 0.70)))
                reasons.append('login_failed_burst')

        typical_hours = baseline.typical_hours(float(self.cfg.get('hour_activity_threshold', 0.05)))
        if typical_hours and hour not in typical_hours:
            risk = max(risk, float(signals.get('unusual_hour', 0.50)))
            reasons.append(f'unusual_hour:{hour}')

        if asset_id and baseline.assets and asset_id not in baseline.assets:
            risk = max(risk, float(signals.get('unusual_asset', 0.55)))
            reasons.append(f'unusual_asset:{asset_id}')

        if account and baseline.accounts and account not in baseline.accounts:
            risk = max(risk, float(signals.get('unusual_account', 0.45)))
            reasons.append(f'unusual_account:{account}')

        if remote_addr and baseline.remote_addrs and remote_addr not in baseline.remote_addrs:
            risk = max(risk, float(signals.get('unusual_ip', 0.52)))
            reasons.append(f'unusual_ip:{remote_addr}')

        avg_commands = baseline.avg_commands_per_session
        velocity_multiplier = float(self.cfg.get('velocity_multiplier', 3.0))
        if avg_commands > 0 and session_commands > avg_commands * velocity_multiplier:
            risk = max(risk, float(signals.get('high_velocity_vs_baseline', 0.40)))
            reasons.append('high_velocity_vs_baseline')

        if asset_id and session_id:
            user_assets = self._recent_assets[user_id]
            user_assets.add(asset_id)
            max_assets = int(self.cfg.get('lateral_movement_assets', 4))
            if len(user_assets) > max_assets:
                risk = max(risk, float(signals.get('lateral_movement', 0.65)))
                reasons.append('lateral_movement')

        confidence = 0.75 if reasons and reasons != ['baseline_warming_up'] else 0.5
        if 'unusual_asset' in ''.join(reasons) or 'unusual_hour' in ''.join(reasons):
            confidence = 0.82
        if any(r.startswith('unusual_ip:') for r in reasons):
            confidence = max(confidence, 0.80)

        return {
            'risk_score': min(risk, 1.0),
            'confidence': confidence,
            'reasons': reasons,
            'model': 'behavioral_v1',
            'baseline_ready': True,
            'baseline_events': baseline.event_count,
            'risk_level': risk_level_label(min(risk, 1.0), self.policy),
        }

    def learn(self, event: dict, combined_risk: float):
        if not self.enabled:
            return

        learn_max_risk = float(self.cfg.get('learn_max_risk', 0.40))
        if combined_risk > learn_max_risk:
            return

        user_id = event.get('user_id') or 'unknown'
        baseline = self.store.get(user_id)
        features = event.get('features') or {}
        event_type = event.get('event_type', '')
        hour = int(features.get('hour_utc', event_hour_utc(event)))
        asset_id = (event.get('asset_id') or '').strip()
        account = (event.get('account') or '').strip()
        session_id = event.get('session_id') or ''
        remote_addr = normalize_remote_addr(event)

        baseline.event_count += 1
        baseline.hours_histogram[hour] += 1

        if session_id:
            baseline.session_ids.add(session_id)
        if asset_id:
            baseline.assets.add(asset_id)
        if account:
            baseline.accounts.add(account)
        if remote_addr:
            baseline.remote_addrs.add(remote_addr)

        command = (event.get('payload') or {}).get('input', '')
        if command:
            baseline.total_commands += 1

        if event_type == 'login.failed':
            baseline.failed_login_count += 1
            baseline.recent_failed_logins += 1
            baseline.last_failed_login_at = event.get('timestamp') or ''
        elif event_type == 'login.success':
            baseline.recent_failed_logins = 0

    def save(self):
        self.store.save()

    def _empty_assessment(self) -> dict:
        return {
            'risk_score': 0.0,
            'confidence': 0.0,
            'reasons': [],
            'model': 'behavioral_v1',
            'baseline_ready': False,
        }


def combine_assessments(*assessments: dict, policy: Optional[dict] = None) -> dict:
    risk = 0.0
    confidence = 0.0
    reasons: List[str] = []
    models: List[str] = []

    for assessment in assessments:
        if not assessment:
            continue
        risk = max(risk, float(assessment.get('risk_score', 0)))
        confidence = max(confidence, float(assessment.get('confidence', 0)))
        reasons.extend(assessment.get('reasons') or [])
        model = assessment.get('model')
        if model:
            models.append(model)

    model_label = '+'.join(models) if models else 'unknown'
    if len(models) > 1:
        model_label = 'ensemble_v1'

    return {
        'risk_score': min(risk, 1.0),
        'confidence': confidence,
        'reasons': reasons,
        'model': model_label,
        'risk_level': risk_level_label(min(risk, 1.0), policy or {}),
    }
