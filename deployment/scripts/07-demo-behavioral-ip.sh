#!/usr/bin/env bash
# Demo: unusual IP detection for privileged admins.
# Run: bash scripts/07-demo-behavioral-ip.sh

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVENTS="$ROOT/data/ai_security/events-ip-demo.jsonl"
AI_DIR="$ROOT/backend"
BASELINES="$AI_DIR/data/user_baselines-ip-demo.json"
DECISIONS="$AI_DIR/data/decisions-ip-demo.jsonl"

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

echo "=== Demo: unusual IP for privileged admin ==="
echo ""
echo "Scenario:"
echo "  1. admin-bob always connects from 203.0.113.10 (office)"
echo "  2. admin-bob connects from 198.51.100.99 (unknown IP)"
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

def send(ip, command, idx):
    ts = datetime(2026, 7, 9, 10, 0, idx, tzinfo=timezone.utc).isoformat()
    event = {
        "event_id": str(uuid.uuid4()),
        "event_type": "command.ingested",
        "timestamp": ts,
        "session_id": "office-session",
        "user_id": "admin-bob",
        "asset_id": "prod-web",
        "account": "ubuntu",
        "protocol": "ssh",
        "remote_addr": ip,
        "payload": {"input": command, "timestamp": 1751796000.0},
        "metadata": {"source": "ip_demo"},
    }
    with events_path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event) + "\n")
    print(f"  → IP {ip}: {command}")

print("Building baseline from office IP (6 commands)...")
for i in range(6):
    send("203.0.113.10", f"ls /app/{i}", i)

print("")
print("Connection from unknown IP...")
send("198.51.100.99", "whoami", 7)
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
print('  risk=%.2f level=%s action=%s' % (dec['risk_score'], dec.get('risk_level', '?'), dec['action']))
print('  Reasons:', ', '.join(dec.get('reasons') or []))
"
fi

if [ -f "$BASELINES" ]; then
  echo ""
  python3 -c "
import json
u = json.load(open('$BASELINES'))['users'].get('admin-bob', {})
print('  Known IPs for admin-bob:', u.get('remote_addrs'))
"
fi

echo ""
echo "Expected: unusual_ip:198.51.100.99 → MEDIUM + ALERT_ANALYST"
echo "=== IP demo complete ==="
