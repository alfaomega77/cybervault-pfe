"""ML models for privileged-access anomaly detection (Phase 3)."""

import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from ..config import load_policy, settings
from ..explainability.explainer import ModelExplainer
from ..features.extractor import FEATURE_NAMES, extract_feature_vector
from .behavioral import BaselineStore, UserBaseline

logger = logging.getLogger('aiss.ml')

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    IsolationForest = None
    RandomForestClassifier = None


class MLEngine:
    """Unsupervised (Isolation Forest) + supervised (Random Forest) scoring."""

    def __init__(self, policy: Optional[dict] = None, model_dir: Optional[str] = None):
        self.policy = policy or load_policy()
        self.cfg = self.policy.get('ml', {})
        self.model_dir = Path(model_dir or settings.ml_model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_store = BaselineStore()
        self._isolation_forest = None
        self._random_forest = None
        self._if_min = 0.0
        self._if_max = 1.0
        self._background_matrix = None
        self._explainer: Optional[ModelExplainer] = None
        self._load_models()

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get('enabled', True)) and SKLEARN_AVAILABLE

    def _model_path(self, name: str) -> Path:
        return self.model_dir / f'{name}.pkl'

    def _load_models(self):
        if not self.enabled:
            return
        if self._model_path('isolation_forest').exists():
            with self._model_path('isolation_forest').open('rb') as fp:
                self._isolation_forest = pickle.load(fp)
        if self._model_path('if_calibration').exists():
            with self._model_path('if_calibration').open('rb') as fp:
                cal = pickle.load(fp)
                self._if_min = cal.get('min', 0.0)
                self._if_max = cal.get('max', 1.0)
        if self._model_path('random_forest').exists():
            with self._model_path('random_forest').open('rb') as fp:
                self._random_forest = pickle.load(fp)
        bg_path = self.model_dir / 'background_matrix.npy'
        if bg_path.exists():
            self._background_matrix = np.load(bg_path)
            self._init_explainer()

    def _init_explainer(self):
        xplain_cfg = self.policy.get('explainability', {})
        if not xplain_cfg.get('enabled', True):
            return
        if self._random_forest is None or self._background_matrix is None:
            return
        self._explainer = ModelExplainer(
            self._random_forest,
            self._background_matrix,
            cfg=xplain_cfg,
        )

    def _should_explain(self, risk: float) -> bool:
        xplain_cfg = self.policy.get('explainability', {})
        if not xplain_cfg.get('enabled', True):
            return False
        if xplain_cfg.get('explain_all', False):
            return True
        min_risk = float(xplain_cfg.get('min_risk_to_explain', 0.25))
        return risk >= min_risk

    def _baseline_for(self, user_id: str) -> UserBaseline:
        return self.baseline_store.get(user_id or 'unknown')

    def build_matrix(
        self,
        events: List[dict],
        baselines: Optional[Dict[str, UserBaseline]] = None,
    ) -> np.ndarray:
        rows = []
        for event in events:
            user_id = event.get('user_id') or 'unknown'
            baseline = (baselines or {}).get(user_id) or self._baseline_for(user_id)
            features = event.get('features') or {}
            vector, _ = extract_feature_vector(event, features, baseline)
            rows.append(vector)
        return np.array(rows, dtype=float)

    def train(
        self,
        train_events: List[dict],
        labels: Optional[List[int]] = None,
        baselines: Optional[Dict[str, UserBaseline]] = None,
    ) -> Dict[str, object]:
        if not SKLEARN_AVAILABLE:
            raise RuntimeError('scikit-learn required: pip install scikit-learn numpy')

        X = self.build_matrix(train_events, baselines)
        metrics: Dict[str, object] = {'samples': len(train_events), 'features': FEATURE_NAMES}

        if_cfg = self.cfg.get('isolation_forest', {})
        self._isolation_forest = IsolationForest(
            n_estimators=int(if_cfg.get('n_estimators', 200)),
            contamination=float(if_cfg.get('contamination', 0.08)),
            random_state=int(if_cfg.get('random_state', 42)),
        )
        normal_mask = [lbl == 0 for lbl in labels] if labels else [True] * len(train_events)
        X_normal = X[normal_mask] if any(normal_mask) else X
        self._isolation_forest.fit(X_normal)
        if_scores = -self._isolation_forest.decision_function(X_normal)
        self._if_min = float(np.min(if_scores))
        self._if_max = float(np.max(if_scores))
        with self._model_path('isolation_forest').open('wb') as fp:
            pickle.dump(self._isolation_forest, fp)
        with self._model_path('if_calibration').open('wb') as fp:
            pickle.dump({'min': self._if_min, 'max': self._if_max}, fp)
        metrics['isolation_forest_trained_on'] = len(X_normal)

        if labels and self.cfg.get('supervised_enabled', True):
            rf_cfg = self.cfg.get('random_forest', {})
            self._random_forest = RandomForestClassifier(
                n_estimators=int(rf_cfg.get('n_estimators', 200)),
                max_depth=rf_cfg.get('max_depth'),
                random_state=int(rf_cfg.get('random_state', 42)),
                class_weight='balanced',
            )
            self._random_forest.fit(X, np.array(labels))
            with self._model_path('random_forest').open('wb') as fp:
                pickle.dump(self._random_forest, fp)
            metrics['random_forest_classes'] = sorted(set(labels))

        meta_path = self.model_dir / 'training_meta.json'
        meta_path.write_text(json.dumps(metrics, indent=2), encoding='utf-8')

        self._background_matrix = X
        np.save(self.model_dir / 'background_matrix.npy', X)
        self._init_explainer()
        return metrics

    def _if_score(self, vector: List[float]) -> float:
        if self._isolation_forest is None:
            return 0.0
        X = np.array([vector], dtype=float)
        raw = float(-self._isolation_forest.decision_function(X)[0])
        if self._if_max > self._if_min:
            return max(0.0, min(1.0, (raw - self._if_min) / (self._if_max - self._if_min)))
        return 0.0

    def _rf_score(self, vector: List[float]) -> float:
        if self._random_forest is None:
            return 0.0
        X = np.array([vector], dtype=float)
        proba = self._random_forest.predict_proba(X)[0]
        classes = list(self._random_forest.classes_)
        if 1 in classes:
            return float(proba[classes.index(1)])
        return float(max(proba))

    def score(self, event: dict) -> dict:
        if not self.enabled:
            return self._empty('ml_disabled')

        if self._isolation_forest is None and self._random_forest is None:
            return self._empty('ml_not_trained')

        user_id = event.get('user_id') or 'unknown'
        baseline = self._baseline_for(user_id)
        features = event.get('features') or {}
        vector, feature_map = extract_feature_vector(event, features, baseline)

        if_score = self._if_score(vector)
        rf_score = self._rf_score(vector)
        blend = float(self.cfg.get('blend_weight_rf', 0.6))
        if self._random_forest is not None and self._isolation_forest is not None:
            risk = blend * rf_score + (1.0 - blend) * if_score
            model = 'ml_hybrid_if_rf'
            reasons = [f'if_score:{if_score:.2f}', f'rf_score:{rf_score:.2f}']
        elif self._random_forest is not None:
            risk = rf_score
            model = 'ml_random_forest'
            reasons = [f'rf_score:{rf_score:.2f}']
        elif self._isolation_forest is not None:
            risk = if_score
            model = 'ml_isolation_forest'
            reasons = [f'if_score:{if_score:.2f}']
        else:
            return self._empty('ml_not_trained')

        result = {
            'risk_score': min(risk, 1.0),
            'confidence': 0.85 if risk >= 0.55 else 0.65,
            'reasons': reasons,
            'model': model,
            'feature_vector': feature_map,
            'if_score': if_score,
            'rf_score': rf_score,
        }

        if self._explainer and self._should_explain(result['risk_score']):
            explanation = self._explainer.explain(vector)
            result['explanation'] = explanation
            if explanation.get('consensus'):
                top = explanation['consensus'][0]['feature']
                result['reasons'].append(f'xai_top_feature:{top}')

        return result

    def _empty(self, reason: str) -> dict:
        return {
            'risk_score': 0.0,
            'confidence': 0.0,
            'reasons': [reason],
            'model': 'ml_none',
        }
