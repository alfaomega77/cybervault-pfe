#!/usr/bin/env bash
# Démo commerciale live : 3 sessions → décisions + alertes dans CyberVault.
# Usage: bash deployment/scripts/13-demo-sales-live.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

BASE="${1:-http://127.0.0.1:${CYBERVAULT_PORT:-8090}}"
TOKEN="${AISS_WEBHOOK_TOKEN:-}"
TS=$(date +%s)

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: AISS_WEBHOOK_TOKEN manquant dans .env"
  exit 1
fi

post_event() {
  local id="$1"
  local sid="$2"
  local user="$3"
  local cmd="$4"
  curl -fsS -X POST "$BASE/events" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"event_id\":\"${id}\",\"event_type\":\"command.ingested\",\"session_id\":\"${sid}\",\"user_id\":\"${user}\",\"account\":\"root\",\"asset_name\":\"lab-server\",\"remote_addr\":\"10.0.0.50\",\"protocol\":\"ssh\",\"payload\":{\"input\":\"${cmd}\"},\"metadata\":{\"source\":\"jumpserver\",\"demo\":\"sales\"}}" \
    | python3 -m json.tool
  echo ""
}

echo "=== Démo live CyberVault (3 sessions) ==="
echo "Cible: $BASE"
echo ""
echo "Ouvre en parallèle: $BASE/app.html  (Décisions)"
echo ""

echo "— Session 1 : activité normale —"
post_event "demo-${TS}-1" "sess-demo-1" "admin-demo" "whoami"
sleep 1

echo "— Session 2 : activité sensible —"
post_event "demo-${TS}-2" "sess-demo-2" "admin-demo" "cat /etc/shadow"
sleep 1

echo "— Session 3 : commande destructrice (alerte / kill en dry-run) —"
post_event "demo-${TS}-3" "sess-demo-3" "admin-demo" "rm -rf /var/log/*"

echo "OK"
echo ""
echo "Vérifie dans Décisions :"
echo "  1) whoami     → risque faible / journal"
echo "  2) cat shadow → alerte possible"
echo "  3) rm -rf     → risque élevé / LOCK ou KILL (status dry_run si AISS_DRY_RUN=true)"
echo ""
echo "Email: configure AISS_SMTP_* puis Mon PAM → Tester l'alerte"
echo "Kill réel: AISS_DRY_RUN=false + token API JumpServer dans Mon PAM"
