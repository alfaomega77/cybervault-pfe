#!/usr/bin/env bash
# Deploy CyberVault for public Internet access (any user, anywhere).
# Usage:
#   bash deployment/scripts/15-deploy-public.sh
#   CYBERVAULT_DOMAIN=app.example.com CADDY_ACME_EMAIL=you@example.com bash deployment/scripts/15-deploy-public.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.public.yml)

upsert() {
  local key="$1" val="$2"
  python3 - "$key" "$val" <<'PY'
import pathlib, sys
key, val = sys.argv[1], sys.argv[2]
path = pathlib.Path('.env')
lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
out, found = [], False
for line in lines:
    if line.startswith(key + '='):
        out.append(f'{key}={val}')
        found = True
    else:
        out.append(line)
if not found:
    out.append(f'{key}={val}')
path.write_text('\n'.join(out) + '\n', encoding='utf-8')
PY
}

echo "==> CyberVault public deploy"
echo "    repo: $ROOT"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is required." >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose v2 plugin is required." >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  echo "==> Creating .env from .env.public.example"
  cp .env.public.example .env
fi

# Strong webhook token if missing / placeholder
CURRENT_TOKEN="$(grep '^AISS_WEBHOOK_TOKEN=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)"
if [[ -z "$CURRENT_TOKEN" \
   || "$CURRENT_TOKEN" == replace-with* \
   || "$CURRENT_TOKEN" == "cybervault-local-demo-token" ]]; then
  TOKEN="$(openssl rand -hex 32 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(32))')"
  upsert AISS_WEBHOOK_TOKEN "$TOKEN"
  echo "==> Generated AISS_WEBHOOK_TOKEN"
fi

DOMAIN="${CYBERVAULT_DOMAIN:-}"
if [[ -z "$DOMAIN" ]] && grep -q '^CYBERVAULT_DOMAIN=' .env; then
  DOMAIN="$(grep '^CYBERVAULT_DOMAIN=' .env | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'" | tr -d ' ')"
fi

if [[ -n "$DOMAIN" ]]; then
  SITE_ADDRESS="$DOMAIN"
  PUBLIC_URL="https://${DOMAIN}"
  echo "==> HTTPS mode: ${PUBLIC_URL} (Let's Encrypt)"
  echo "    DNS A/AAAA for ${DOMAIN} must point here; open ports 80 and 443."
else
  SITE_ADDRESS="${SITE_ADDRESS:-http://:80}"
  echo "==> HTTP mode on port 80 (set CYBERVAULT_DOMAIN for automatic HTTPS)"
fi

upsert SITE_ADDRESS "$SITE_ADDRESS"
upsert CYBERVAULT_BIND_ADDRESS "127.0.0.1"
upsert AISS_ALLOW_SIGNUP "${AISS_ALLOW_SIGNUP:-true}"

if [[ -n "$DOMAIN" ]]; then
  upsert AISS_PUBLIC_URL "$PUBLIC_URL"
  upsert CYBERVAULT_DOMAIN "$DOMAIN"
fi

if [[ -n "${CADDY_ACME_EMAIL:-}" ]]; then
  upsert CADDY_ACME_EMAIL "$CADDY_ACME_EMAIL"
fi

if ! grep -q '^AISS_DRY_RUN=' .env; then
  upsert AISS_DRY_RUN true
fi

echo "==> Building and starting stack (redis + backend + frontend + caddy)"
"${COMPOSE[@]}" up --build -d --wait

echo
echo "==> Status"
"${COMPOSE[@]}" ps

if curl -fsS --max-time 8 "http://127.0.0.1:8090/health" >/dev/null 2>&1; then
  echo "==> Health OK (local :8090)"
elif curl -fsS --max-time 8 "http://127.0.0.1/health" >/dev/null 2>&1; then
  echo "==> Health OK (edge :80)"
else
  echo "WARN: health check failed — run: ${COMPOSE[*]} logs" >&2
fi

echo
echo "============================================================"
echo " CyberVault is deployed for public access"
echo "============================================================"
if [[ -n "$DOMAIN" ]]; then
  echo " Open:  https://${DOMAIN}"
else
  echo " Open:  http://<this-server-public-IP>"
  echo " Tip:   CYBERVAULT_DOMAIN=app.example.com bash deployment/scripts/15-deploy-public.sh"
fi
echo
echo " Anyone can: sign up → Mon PAM → JumpServer URL + Access key (ID:Secret)"
echo " JumpServer must be reachable FROM this server (public URL or VPN)."
echo " Dry-run is ON by default (no lock/kill until AISS_DRY_RUN=false)."
echo "============================================================"
