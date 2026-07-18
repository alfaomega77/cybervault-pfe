#!/usr/bin/env bash
# Process one sample event through the AI pipeline (no JumpServer).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AI_DIR="$ROOT/backend"
EXPORTS="$ROOT/data/exports"
SAMPLE="$ROOT/data/datasets/samples/privileged_events_sample.json"

echo "=== CyberVault beginner test (no JumpServer) ==="
mkdir -p "$EXPORTS"

cd "$AI_DIR"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

export AISS_DRY_RUN=true
export AISS_DECISION_LOG_PATH="$EXPORTS/decisions.jsonl"
export AISS_FEATURE_STORE_PATH="$EXPORTS/feature_store.json"
export AISS_BASELINES_PATH="$EXPORTS/user_baselines.json"
export AISS_ML_MODEL_DIR="$ROOT/data/models"

python3 - <<PY
import json
from pathlib import Path
from aiss.pipeline.processor import EventProcessor

sample = Path("$SAMPLE")
events = json.loads(sample.read_text(encoding="utf-8"))
if isinstance(events, dict):
    events = [events]
processor = EventProcessor()
decision, execution = processor.process(events[0])
print("SUCCESS - Decision written to:", "$EXPORTS/decisions.jsonl")
print(json.dumps({"action": decision.get("action"), "risk_score": decision.get("risk_score"), "status": execution.get("status")}, indent=2))
print("=== Part 1 complete ===")
PY
