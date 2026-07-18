#!/usr/bin/env bash
# Demo Phase 2: behavioral baseline + privileged-user deviation detection.
# Run: bash scripts/06-demo-behavioral.sh

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVENTS="$ROOT/data/ai_security/events-behavioral-demo.jsonl"
AI_DIR="$ROOT/backend"
BASELINES="$AI_DIR/data/user_baselines.json"
DECISIONS="$AI_DIR/data/decisions-behavioral-demo.jsonl"

mkdir -p "$(dirname "$EVENTS")"
rm -f "$EVENTS" "$BASELINES" "$DECISIONS"

cd "$AI_DIR"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt

export AISS_DRY_RUN=true
export AISS_EVENTS_FILE="$EVENTS"
export AISS_BASELINES_PATH="$BASELINES"
export AISS_DECISION_LOG_PATH="$DECISIONS"

echo "=== Phase 2 demo: privileged admin behavioral detection ==="
echo ""
echo "Scenario:"
echo "  1. admin-alice builds a baseline (prod-web, business hours)"
echo "  2. admin-alice connects at 3am to prod-db (never seen before)"
echo ""

python -m aiss.consumer.main &
CONSUMER_PID=$!
sleep 1

export DEMO_EVENTS_FILE="$EVENTS"
python3 <<'PY'
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

events_path = Path(os.environ["DEMO_EVENTS_FILE"])

def send(user, asset, hour, command, session):
    ts = datetime(2026, 7, 9, hour, 0, 0, tzinfo=timezone.utc).isoformat()
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "command.ingested",
        "timestamp": ts,
        "session_id": session,
        "user_id": user,
        "asset_id": asset,
        "account": "ubuntu",
        "protocol": "ssh",
        "payload": {"input": command, "timestamp": 1751796000.0},
        "metadata": {"source": "behavioral_demo"},
    }
    with events_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event) + "\n")
    print(f"  → {user} @ {asset} h{hour:02d}: {command}")

print("Building baseline (6 normal commands)...")
for i in range(6):
    send("admin-alice", "prod-web", 10, f"ls /var/log/app{i}", "baseline-session")

print("")
print("Anomalous privileged access (new asset + unusual hour)...")
send("admin-alice", "prod-db", 3, "whoami", "anomaly-session")
PY

sleep 3
kill $CONSUMER_PID 2>/dev/null || true

echo ""
echo "=== Results ==="
if [ -f "$DECISIONS" ]; then
  tail -1 "$DECISIONS" | python3 -c "
import json, sys
d = json.load(sys.stdin)
dec = d['decision']
print('  Last event risk=%.2f action=%s' % (dec['risk_score'], dec['action']))
print('  Reasons:', ', '.join(dec.get('reasons') or []))
print('  Model:', dec.get('model'))
"
else
  echo "  No decisions file — check consumer logs above"
fi

if [ -f "$BASELINES" ]; then
  echo ""
  echo "Baseline learned for admin-alice:"
  python3 -c "
import json
b = json.load(open('$BASELINES'))
u = b['users'].get('admin-alice', {})
print('  assets:', u.get('assets'))
print('  typical hours:', sorted(u.get('hours_histogram', {}).keys()))
"
fi

echo ""
echo "Expected: unusual_asset + unusual_hour → ALERT_ANALYST or higher"
echo "=== Phase 2 demo complete ==="
