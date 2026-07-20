import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional

from ..config import load_policy, settings
from .behavioral import event_hour_utc, normalize_remote_addr


@dataclass
class SessionContext:
    commands: Deque[str] = field(default_factory=lambda: deque(maxlen=50))
    event_count: int = 0
    last_seen: str = ''


class FeatureStore:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path or settings.feature_store_path)
        self.sessions: Dict[str, SessionContext] = defaultdict(SessionContext)
        self.user_command_counts: Dict[str, int] = defaultdict(int)
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding='utf-8'))
            for session_id, item in data.get('sessions', {}).items():
                ctx = SessionContext()
                ctx.commands = deque(item.get('commands', []), maxlen=50)
                ctx.event_count = item.get('event_count', 0)
                ctx.last_seen = item.get('last_seen', '')
                self.sessions[session_id] = ctx
            self.user_command_counts.update(data.get('user_command_counts', {}))
        except (json.JSONDecodeError, OSError):
            pass

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            'sessions': {
                sid: {
                    'commands': list(ctx.commands),
                    'event_count': ctx.event_count,
                    'last_seen': ctx.last_seen,
                }
                for sid, ctx in self.sessions.items()
            },
            'user_command_counts': dict(self.user_command_counts),
        }
        self.path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')

    def enrich(self, event: dict) -> dict:
        session_id = event.get('session_id') or 'unknown'
        user_id = event.get('user_id') or 'unknown'
        ctx = self.sessions[session_id]
        ctx.event_count += 1
        ctx.last_seen = event.get('timestamp') or datetime.now(timezone.utc).isoformat()

        command_input = (event.get('payload') or {}).get('input', '')
        if command_input:
            ctx.commands.append(command_input)
            self.user_command_counts[user_id] += 1

        enriched = dict(event)
        enriched['features'] = {
            'session_command_count': len(ctx.commands),
            'session_event_count': ctx.event_count,
            'user_total_commands': self.user_command_counts[user_id],
            'recent_commands': list(ctx.commands)[-10:],
            'is_acl_violation': event.get('event_type') == 'command.acl_violation',
            'hour_utc': event_hour_utc(event),
            'remote_addr': normalize_remote_addr(event),
        }
        return enriched


class RulesEngine:
    def __init__(self, policy: Optional[dict] = None):
        self.policy = policy or load_policy()
        patterns = self.policy.get('destructive_patterns', [])
        self._compiled = [re.compile(p) for p in patterns]

    def score(self, event: dict) -> dict:
        payload = event.get('payload') or {}
        features = event.get('features') or {}
        command = payload.get('input', '') or ''
        risk = 0.0
        reasons: List[str] = []

        if event.get('event_type') == 'command.acl_violation':
            risk = max(risk, 0.85)
            reasons.append('acl_violation')

        for pattern in self._compiled:
            if pattern.search(command):
                risk = max(risk, 0.92)
                reasons.append(f'destructive_pattern:{pattern.pattern}')
                break

        if features.get('session_command_count', 0) > 30:
            risk = max(risk, 0.25)
            reasons.append('high_session_velocity')

        risk_level = payload.get('risk_level')
        if isinstance(risk_level, int) and risk_level >= 4:
            risk = max(risk, 0.70)
            reasons.append('high_acl_risk_level')

        # User-defined abnormal-behavior rules (command / custom regex)
        try:
            from ..web.behavior_rules_store import score_custom_rules

            custom = score_custom_rules(event, types={'command', 'custom'})
            for reason in custom.get('reasons') or []:
                if reason not in reasons:
                    reasons.append(reason)
            risk = max(risk, float(custom.get('risk_score') or 0.0))
        except Exception:
            pass

        return {
            'risk_score': min(risk, 1.0),
            'confidence': 0.8 if reasons else 0.5,
            'reasons': reasons,
            'model': 'rules_v0',
        }
