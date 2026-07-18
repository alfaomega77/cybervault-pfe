"""SHAP + LIME explainability for privileged-access ML models."""

import logging
from typing import Dict, List, Optional, Tuple

import numpy as np

from ..features.extractor import FEATURE_NAMES

logger = logging.getLogger('aiss.explainability')

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    shap = None

try:
    from lime.lime_tabular import LimeTabularExplainer
    LIME_AVAILABLE = True
except ImportError:
    LIME_AVAILABLE = False
    LimeTabularExplainer = None


def _top_contributions(
    values: Dict[str, float],
    limit: int = 5,
) -> List[Dict[str, float]]:
    ranked = sorted(values.items(), key=lambda item: abs(item[1]), reverse=True)
    return [
        {'feature': name, 'contribution': round(float(value), 4)}
        for name, value in ranked[:limit]
    ]


def _human_summary(top: List[Dict[str, float]], method: str) -> str:
    if not top:
        return f'No {method} contributors available.'
    parts = [f"{item['feature']} ({item['contribution']:+.3f})" for item in top[:3]]
    return f'{method} top drivers: ' + ', '.join(parts)


class ModelExplainer:
    """Local explanations for Random Forest anomaly scores."""

    def __init__(
        self,
        random_forest,
        background_matrix: np.ndarray,
        cfg: Optional[dict] = None,
    ):
        self.cfg = cfg or {}
        self.feature_names = FEATURE_NAMES
        self.background = background_matrix
        self.random_forest = random_forest
        self._shap_explainer = None
        self._lime_explainer = None

        if SHAP_AVAILABLE and random_forest is not None:
            try:
                self._shap_explainer = shap.TreeExplainer(random_forest)
            except Exception as exc:
                logger.warning('SHAP TreeExplainer init failed: %s', exc)

        if LIME_AVAILABLE and random_forest is not None and len(background_matrix) > 0:
            self._lime_explainer = LimeTabularExplainer(
                background_matrix,
                feature_names=self.feature_names,
                class_names=['normal', 'anomaly'],
                mode='classification',
                discretize_continuous=True,
            )

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get('enabled', True))

    def _predict_proba_lime(self, data) -> np.ndarray:
        arr = np.asarray(data, dtype=float)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return self.random_forest.predict_proba(arr)

    def explain(self, vector: List[float]) -> Dict[str, object]:
        if not self.enabled or self.random_forest is None:
            return {'available': False, 'reason': 'explainer_disabled'}

        x = np.array(vector, dtype=float).reshape(1, -1)
        shap_top: List[Dict[str, float]] = []
        lime_top: List[Dict[str, float]] = []
        shap_values_raw = None
        lime_score = None

        if self._shap_explainer is not None:
            try:
                shap_values = self._shap_explainer.shap_values(x, check_additivity=False)
                if isinstance(shap_values, list):
                    idx = 1 if len(shap_values) > 1 else 0
                    shap_values_raw = np.ravel(shap_values[idx][0])
                else:
                    shap_values_raw = np.ravel(shap_values[0])
                shap_map = {
                    name: float(value)
                    for name, value in zip(self.feature_names, shap_values_raw)
                }
                shap_top = _top_contributions(shap_map, int(self.cfg.get('top_k', 5)))
            except Exception as exc:
                logger.warning('SHAP explain failed: %s', exc)

        if self._lime_explainer is not None:
            try:
                lime_exp = self._lime_explainer.explain_instance(
                    np.array(vector, dtype=float),
                    self._predict_proba_lime,
                    num_features=int(self.cfg.get('top_k', 5)),
                )
                lime_map = {name: float(weight) for name, weight in lime_exp.as_list()}
                lime_top = _top_contributions(lime_map, int(self.cfg.get('top_k', 5)))
                if len(lime_exp.predict_proba) > 1:
                    lime_score = float(lime_exp.predict_proba[1])
            except Exception as exc:
                logger.warning('LIME explain failed: %s', exc)

        if not shap_top and self.random_forest is not None:
            # Fallback: impurity-based attribution
            importances = getattr(self.random_forest, 'feature_importances_', None)
            if importances is not None:
                shap_map = {
                    name: float(imp * val)
                    for name, imp, val in zip(self.feature_names, importances, vector)
                }
                shap_top = _top_contributions(shap_map, int(self.cfg.get('top_k', 5)))

        combined = {}
        for item in shap_top + lime_top:
            combined[item['feature']] = combined.get(item['feature'], 0.0) + item['contribution']
        consensus_top = _top_contributions(combined, int(self.cfg.get('top_k', 5)))

        return {
            'available': bool(shap_top or lime_top),
            'shap': shap_top,
            'lime': lime_top,
            'consensus': consensus_top,
            'summary': ' | '.join([
                _human_summary(shap_top, 'SHAP'),
                _human_summary(lime_top, 'LIME'),
            ]),
            'lime_anomaly_probability': lime_score,
        }
