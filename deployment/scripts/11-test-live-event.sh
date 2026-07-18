#!/usr/bin/env bash
# Smoke-test a running CyberVault instance (default http://127.0.0.1:8090).
set -euo pipefail
BASE="${1:-http://127.0.0.1:8090}"
TOKEN="${AISS_WEBHOOK_TOKEN:-cybervault-local-demo-token}"

echo "== health =="
curl -fsS "$BASE/health" | python3 -m json.tool

echo "== UI =="
code=$(curl -fsS -o /dev/null -w '%{http_code}' "$BASE/app.html")
echo "app.html -> $code"

echo "== webhook event =="
curl -fsS -X POST "$BASE/events" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"event_id":"smoke-'"$(date +%s)"'","event_type":"command.ingested","session_id":"smoke","user_id":"demo","payload":{"input":"whoami"},"metadata":{"source":"jumpserver"}}' \
  | python3 -m json.tool

echo "OK"
