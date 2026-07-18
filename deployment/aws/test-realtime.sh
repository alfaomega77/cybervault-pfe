#!/usr/bin/env bash
# Real-time smoke test against CyberVault HTTP ingest + health.
set -euo pipefail

BASE="${1:-http://127.0.0.1:8090}"
BASE="${BASE%/}"

echo "=== CyberVault real-time test ==="
echo "Target: $BASE"
echo ""

echo "1) Health"
curl -sf "$BASE/health" | tee /tmp/aiss_health.json
echo ""
echo ""

TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EVENT=$(cat <<EOF
{
  "event_id": "aws-poc-$(date +%s)",
  "event_type": "command.ingested",
  "timestamp": "$TS",
  "session_id": "aws-poc-session-1",
  "user_id": "aws-demo-admin",
  "asset_id": "prod-db-01",
  "account": "root",
  "protocol": "ssh",
  "remote_addr": "198.51.100.50",
  "payload": {"input": "rm -rf /var/log/*"},
  "metadata": {"source": "aws_poc_test"}
}
EOF
)

echo "2) Inject destructive command event (HTTP ingest POST /events)"
OK=0
for path in /events /events/; do
  CODE=$(curl -s -o /tmp/aiss_ingest_out.txt -w "%{http_code}" \
    -X POST "$BASE$path" \
    -H 'Content-Type: application/json' \
    -d "$EVENT" || true)
  if [[ "$CODE" =~ ^2 ]]; then
    echo "  POST $path → HTTP $CODE"
    cat /tmp/aiss_ingest_out.txt 2>/dev/null || true
    echo ""
    OK=1
    break
  else
    echo "  POST $path → HTTP $CODE"
  fi
done

if [[ "$OK" -ne 1 ]]; then
  echo ""
  echo "HTTP ingest path may differ — falling back to docker redis/file inject."
  if docker ps --format '{{.Names}}' | grep -q aiss-consumer; then
    echo "$EVENT" | docker exec -i aiss-consumer sh -c 'cat >> /app/data/events_injected.jsonl' 2>/dev/null || true
    echo "  Wrote events_injected.jsonl inside container (if volume mounted)."
  fi
  echo "  Prefer a real JumpServer SSH session for end-to-end proof."
fi

echo ""
echo "3) Tips"
echo "  - Open dashboard: $BASE/app.html  or  $BASE/"
echo "  - Follow logs:    docker logs -f aiss-consumer"
echo "  - From JumpServer web SSH, run:  rm -rf /tmp/cybervault-test"
echo "  - Expect decision within ~1–2 seconds (real-time path)"
echo ""
echo "Done."
