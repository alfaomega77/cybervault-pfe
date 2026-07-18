#!/usr/bin/env bash
# Demo SHAP + LIME explainability on a privileged-access anomaly.
# Usage: bash scripts/09-run-explainability-demo.sh

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AI_DIR="$ROOT/backend"
OUT="$AI_DIR/data/research/EXPLAINABILITY_REPORT.md"

cd "$AI_DIR"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt

export EXPLAIN_OUT="$OUT"
python3 <<'PY'
import os
from pathlib import Path

from aiss.evaluation.benchmark import _build_baselines
from aiss.evaluation.dataset import generate_pam_dataset
from aiss.pipeline.enrichment import FeatureStore
from aiss.pipeline.ml_engine import MLEngine

out = Path(os.environ["EXPLAIN_OUT"])
events, counts = generate_pam_dataset(seed=42)
split = int(len(events) * 0.7)
train_events = events[:split]
test_events = [e for e in events[split:] if e.get('label') == 1][:3]

baselines = _build_baselines(train_events)
baseline_map = {uid: baselines.get(uid) for uid in baselines.users}
model_dir = Path('/tmp/aiss_explain_models')
if model_dir.exists():
    for p in model_dir.glob('*'):
        p.unlink()
model_dir.mkdir(parents=True, exist_ok=True)

ml = MLEngine(model_dir=str(model_dir))
ml.train(train_events, labels=[e.get('label', 0) for e in train_events], baselines=baseline_map)

feature_store = FeatureStore(path='/tmp/aiss_explain_features.json')
lines = [
    '# Explainability Report — SHAP + LIME',
    '',
    'Example explanations for privileged-access anomalies.',
    '',
]

for event in test_events:
    enriched = feature_store.enrich(event)
    assessment = ml.score(enriched)
    explanation = assessment.get('explanation', {})
    lines.append(f"## Event: `{event.get('anomaly_type')}` — `{event.get('payload', {}).get('input', event.get('event_type'))}`")
    lines.append('')
    lines.append(f"- Risk score: **{assessment.get('risk_score', 0):.2f}**")
    lines.append(f"- Model: `{assessment.get('model')}`")
    lines.append('')
    if explanation.get('summary'):
        lines.append(f"**Summary:** {explanation['summary']}")
        lines.append('')
    if explanation.get('shap'):
        lines.append('### SHAP top contributors')
        lines.append('')
        lines.append('| Feature | Contribution |')
        lines.append('| --- | --- |')
        for item in explanation['shap']:
            lines.append(f"| {item['feature']} | {item['contribution']:+.4f} |")
        lines.append('')
    if explanation.get('lime'):
        lines.append('### LIME top contributors')
        lines.append('')
        lines.append('| Feature | Contribution |')
        lines.append('| --- | --- |')
        for item in explanation['lime']:
            lines.append(f"| {item['feature']} | {item['contribution']:+.4f} |")
        lines.append('')
    lines.append('---')
    lines.append('')

out.parent.mkdir(parents=True, exist_ok=True)
out.write_text('\n'.join(lines), encoding='utf-8')
print(out)
PY

echo ""
echo "=== Explainability demo complete ==="
head -50 "$OUT"
