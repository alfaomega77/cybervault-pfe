#!/usr/bin/env bash
# Demo: simulate JumpServer sending commands → AI consumer reacts.
# No full JumpServer needed. Run: bash scripts/05-demo-pipeline.sh

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVENTS="$ROOT/data/ai_security/events.jsonl"
AI_DIR="$ROOT/backend"

mkdir -p "$(dirname "$EVENTS")"
touch "$EVENTS"

cd "$AI_DIR"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt

export AISS_DRY_RUN=true
export AISS_EVENTS_FILE="$EVENTS"

echo "=== Demo: simulated JumpServer commands → AI decisions ==="
echo ""
echo "Starting AI consumer in background..."
python -m aiss.consumer.main &
CONSUMER_PID=$!
sleep 1

echo "Sending 3 simulated commands..."
echo ""

send_event() {
  local input="$1"
  local session="$2"
  python3 -c "
import json, uuid
from datetime import datetime, timezone
event = {
    'event_id': str(uuid.uuid4()),
    'event_type': 'command.ingested',
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'session_id': '$session',
    'user_id': 'demo-user',
    'account': 'ubuntu',
    'protocol': 'ssh',
    'payload': {'input': '''$input''', 'timestamp': 1751796000.0},
    'metadata': {'source': 'demo_simulator'},
}
print(json.dumps(event))
" >> "$EVENTS"
  echo "  → sent: $input"
  sleep 2
}

send_event "whoami" "demo-session-1"
send_event "ls -la /var/log" "demo-session-1"
send_event "rm -rf /var/log/*" "demo-session-1"

sleep 2
kill $CONSUMER_PID 2>/dev/null || true

echo ""
echo "=== Done ==="
echo ""
echo "Decisions written to:"
echo "  $AI_DIR/data/decisions.jsonl"
echo ""
echo "View last 3 decisions:"
tail -3 "$AI_DIR/data/decisions.jsonl" | while read -r line; do
  echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  cmd risk=%.2f action=%s' % (d['decision']['risk_score'], d['decision']['action']))" 2>/dev/null || echo "  $line"
done
echo ""
echo "This is the full AI pipeline working without JumpServer UI."
echo "Real JumpServer install needs Python 3.14+ (see scripts/04-install-jumpserver.sh)."
