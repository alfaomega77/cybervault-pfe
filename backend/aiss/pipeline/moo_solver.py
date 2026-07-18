from typing import Dict, List, Optional

from .behavioral import risk_level_label

ACTIONS = [
    'NO_ACTION',
    'LOG_ONLY',
    'ALERT_ANALYST',
    'CREATE_TICKET',
    'LOCK_SESSION',
    'KILL_SESSION',
]

# Privilege levels for (MO-A): min risk, min privilege, max availability
PRIVILEGE_LEVELS = [
    'DENY_ACCESS',
    'READ_ONLY',
    'STANDARD_ADMIN',
    'JIT_TIME_LIMITED',
    'ELEVATED',
    'FULL_ROOT',
]

DEFAULT_PRIVILEGE_COEFFS = {
    'DENY_ACCESS': {'risk': 0.05, 'privilege': 0.00, 'availability': 0.10},
    'READ_ONLY': {'risk': 0.15, 'privilege': 0.20, 'availability': 0.85},
    'STANDARD_ADMIN': {'risk': 0.35, 'privilege': 0.45, 'availability': 0.95},
    'JIT_TIME_LIMITED': {'risk': 0.40, 'privilege': 0.55, 'availability': 0.90},
    'ELEVATED': {'risk': 0.65, 'privilege': 0.75, 'availability': 0.80},
    'FULL_ROOT': {'risk': 0.95, 'privilege': 1.00, 'availability': 0.70},
}


class MOOSolver:
    """Weighted multi-objective solver for security response actions (MO)/(P)."""

    def __init__(self, policy: dict):
        self.policy = policy
        self.weights = policy.get('moo_weights', {})
        self.thresholds = policy.get('thresholds', {})
        self.action_costs = policy.get('action_costs', {})
        self.constraints = policy.get('constraints', {})

    def _security_loss(self, action: str, risk_score: float) -> float:
        severity = {
            'NO_ACTION': 1.0,
            'LOG_ONLY': 0.9,
            'ALERT_ANALYST': 0.6,
            'CREATE_TICKET': 0.5,
            'LOCK_SESSION': 0.2,
            'KILL_SESSION': 0.05,
        }
        return risk_score * severity.get(action, 1.0)

    def _disruption_cost(self, action: str) -> float:
        return float(self.action_costs.get(action, 0.5))

    def _alert_fatigue_cost(self, action: str) -> float:
        if action in ('ALERT_ANALYST', 'CREATE_TICKET'):
            return 1.0
        if action == 'LOG_ONLY':
            return 0.2
        return 0.0

    def _passes_constraints(self, action: str, event: dict, assessment: dict) -> bool:
        account = (event.get('account') or '').lower()
        protected = {a.lower() for a in self.constraints.get('protected_accounts', [])}
        if action == 'KILL_SESSION' and account in protected:
            return False
        if action == 'KILL_SESSION':
            min_conf = float(self.constraints.get('min_confidence_for_kill', 0.7))
            if assessment.get('confidence', 0) < min_conf:
                return False
        return True

    def decide(self, event: dict, assessment: dict) -> dict:
        risk_score = float(assessment.get('risk_score', 0))
        confidence = float(assessment.get('confidence', 0.5))

        # Fast path: pre-computed policy thresholds
        if risk_score >= float(self.thresholds.get('kill', 0.9)):
            candidate = 'KILL_SESSION'
        elif risk_score >= float(self.thresholds.get('lock', 0.75)):
            candidate = 'LOCK_SESSION'
        elif risk_score >= float(self.thresholds.get('alert', 0.55)):
            candidate = 'ALERT_ANALYST'
        elif risk_score >= 0.25:
            candidate = 'LOG_ONLY'
        else:
            candidate = 'NO_ACTION'

        if self._passes_constraints(candidate, event, assessment):
            return self._result(candidate, risk_score, confidence, assessment, fast_path=True)

        # Full weighted scalarization across allowed actions
        alpha = float(self.weights.get('security', 0.55))
        beta = float(self.weights.get('disruption', 0.30))
        gamma = float(self.weights.get('alert_fatigue', 0.15))

        best_action = 'NO_ACTION'
        best_score = float('inf')
        breakdown: Dict[str, float] = {}

        for action in ACTIONS:
            if not self._passes_constraints(action, event, assessment):
                continue
            objective = (
                alpha * self._security_loss(action, risk_score)
                + beta * self._disruption_cost(action)
                + gamma * self._alert_fatigue_cost(action)
            )
            breakdown[action] = round(objective, 4)
            if objective < best_score:
                best_score = objective
                best_action = action

        return self._result(best_action, risk_score, confidence, assessment,
                            breakdown=breakdown, fast_path=False)

    def _result(self, action, risk_score, confidence, assessment, breakdown=None, fast_path=False):
        return {
            'action': action,
            'risk_score': risk_score,
            'confidence': confidence,
            'risk_level': assessment.get('risk_level', risk_level_label(risk_score, self.policy)),
            'reasons': assessment.get('reasons', []),
            'model': assessment.get('model', 'rules_v0'),
            'objective_breakdown': breakdown or {},
            'fast_path': fast_path,
        }


class PrivilegeMOOSolver:
    """
    Privilege-assignment MOO (MO-A)/(P-A):
      min Z1 = sum Risk_ell * y_ell      (cyber risk)
      min Z2 = sum Priv_ell * y_ell      (granted privileges)
      max Z3 = sum Avail_ell * y_ell     (operational continuity)
    Online scalarization: minimize W = mu1*Z1 + mu2*Z2 + mu3*(1-Z3).
    """

    def __init__(self, policy: dict):
        self.policy = policy
        priv = policy.get('privilege_moo', {}) or {}
        self.enabled = bool(priv.get('enabled', True))
        self.weights = priv.get('weights', {})
        self.coeffs = {**DEFAULT_PRIVILEGE_COEFFS, **(priv.get('coefficients') or {})}
        self.forbidden = {
            str(x).upper() for x in (priv.get('forbidden_levels') or [])
        }
        self.kill_threshold = float(
            policy.get('thresholds', {}).get('kill', 0.90)
        )

    def _passes(self, level: str, event: dict, assessment: dict) -> bool:
        if level.upper() in self.forbidden:
            return False
        risk = float(assessment.get('risk_score', 0) or 0)
        # High fused risk forbids FULL_ROOT (constraint in (MO-A))
        if level == 'FULL_ROOT' and risk >= self.kill_threshold:
            return False
        account = (event.get('account') or '').lower()
        protected = {
            a.lower()
            for a in self.policy.get('constraints', {}).get('protected_accounts', [])
        }
        # Break-glass accounts may keep elevated access but not unrestricted root via MO-A
        if account in protected and level == 'FULL_ROOT':
            return False
        return True

    def _objective(self, level: str) -> float:
        c = self.coeffs.get(level, DEFAULT_PRIVILEGE_COEFFS.get(level, {}))
        mu1 = float(self.weights.get('risk', 0.45))
        mu2 = float(self.weights.get('privilege', 0.30))
        mu3 = float(self.weights.get('availability', 0.25))
        risk = float(c.get('risk', 0.5))
        priv = float(c.get('privilege', 0.5))
        avail = float(c.get('availability', 0.5))
        # max Z3  <=>  min (1 - Z3)
        return mu1 * risk + mu2 * priv + mu3 * (1.0 - avail)

    def decide(self, event: dict, assessment: dict,
               requested_level: Optional[str] = None) -> dict:
        if not self.enabled:
            return {
                'privilege_level': requested_level or 'STANDARD_ADMIN',
                'enabled': False,
                'model': 'privilege_moo_disabled',
            }

        levels: List[str] = list(PRIVILEGE_LEVELS)
        best = 'DENY_ACCESS'
        best_score = float('inf')
        breakdown: Dict[str, float] = {}
        z_components: Dict[str, dict] = {}

        for level in levels:
            if not self._passes(level, event, assessment):
                continue
            score = self._objective(level)
            c = self.coeffs.get(level, {})
            breakdown[level] = round(score, 4)
            z_components[level] = {
                'Z1_risk': float(c.get('risk', 0)),
                'Z2_privilege': float(c.get('privilege', 0)),
                'Z3_availability': float(c.get('availability', 0)),
                'W': round(score, 4),
            }
            if score < best_score:
                best_score = score
                best = level

        # Prefer requested level if it is feasible and within a small gap of optimum
        if requested_level and requested_level in breakdown:
            if breakdown[requested_level] <= best_score + 0.05:
                best = requested_level

        return {
            'privilege_level': best,
            'objective_W': round(best_score, 4) if best_score < float('inf') else None,
            'objective_breakdown': breakdown,
            'z_components': z_components,
            'requested_level': requested_level,
            'model': 'privilege_moo_v1',
            'enabled': True,
        }
