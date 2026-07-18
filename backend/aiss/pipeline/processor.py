import logging

from ..actions.executor import ActionExecutor, JumpServerClient
from ..config import load_policy, settings
from ..web.config_store import load_user_config
from .behavioral import BehavioralEngine, combine_assessments
from .dl_gnn import GNNEngine
from .dl_sequence import SequenceDLEngine
from .enrichment import FeatureStore, RulesEngine
from .ml_engine import MLEngine
from .moo_solver import MOOSolver, PrivilegeMOOSolver

logger = logging.getLogger('aiss.processor')


def _engine_snapshot(assessment: dict) -> dict:
    return {
        'risk_score': float(assessment.get('risk_score', 0) or 0),
        'confidence': float(assessment.get('confidence', 0) or 0),
        'reasons': list(assessment.get('reasons') or []),
        'model': assessment.get('model') or '',
    }


def _build_executor() -> ActionExecutor:
    cfg = load_user_config()
    # Safety: AISS_DRY_RUN=true always wins. Real LOCK/KILL only when env is false.
    if settings.dry_run:
        dry_run = True
    else:
        dry_run = False
    url = cfg.get('jumpserver_url') or settings.jumpserver_url
    token = cfg.get('jumpserver_token') or settings.jumpserver_token
    return ActionExecutor(
        client=JumpServerClient(base_url=url, token=token),
        dry_run=bool(dry_run),
    )


class EventProcessor:
    def __init__(self):
        self.policy = load_policy()
        self.feature_store = FeatureStore()
        self.behavioral = BehavioralEngine(self.policy)
        self.rules = RulesEngine(self.policy)
        self.ml = MLEngine(self.policy)
        self.sequence_dl = SequenceDLEngine(self.policy)
        self.gnn = GNNEngine(self.policy)
        self.moo = MOOSolver(self.policy)
        self.privilege_moo = PrivilegeMOOSolver(self.policy)
        self.executor = _build_executor()

    def process(self, event: dict):
        self.executor = _build_executor()
        enriched = self.feature_store.enrich(event)
        command_assessment = self.rules.score(enriched)
        behavioral_assessment = self.behavioral.score(enriched)
        ml_assessment = self.ml.score(enriched)
        seq_assessment = self.sequence_dl.score(enriched)
        gnn_assessment = self.gnn.score(enriched)
        assessment = combine_assessments(
            command_assessment,
            behavioral_assessment,
            ml_assessment,
            seq_assessment,
            gnn_assessment,
            policy=self.policy,
        )
        decision = self.moo.decide(enriched, assessment)
        privilege = self.privilege_moo.decide(
            enriched,
            assessment,
            requested_level=enriched.get('requested_privilege') or enriched.get('privilege_level'),
        )
        decision['privilege_assignment'] = privilege
        decision['privilege_level'] = privilege.get('privilege_level')
        decision['engines'] = {
            'rules': _engine_snapshot(command_assessment),
            'ueba': _engine_snapshot(behavioral_assessment),
            'ml': _engine_snapshot(ml_assessment),
            'dl_sequence': _engine_snapshot(seq_assessment),
            'dl_gnn': _engine_snapshot(gnn_assessment),
        }
        if ml_assessment.get('explanation'):
            decision['explainability'] = ml_assessment['explanation']
        elif ml_assessment.get('explainability'):
            decision['explainability'] = ml_assessment['explainability']
        result = self.executor.execute(enriched, decision)
        self.behavioral.learn(enriched, assessment.get('risk_score', 0))
        self.feature_store.save()
        self.behavioral.save()
        logger.info(
            'event=%s user=%s session=%s risk=%.2f action=%s model=%s status=%s',
            event.get('event_type'),
            event.get('user_id'),
            event.get('session_id'),
            decision.get('risk_score', 0),
            decision.get('action'),
            assessment.get('model'),
            result.get('status'),
        )
        return decision, result
