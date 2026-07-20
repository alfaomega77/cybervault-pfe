#!/usr/bin/env bash
# Deploy public CyberVault + JumpServer lab reachable from ANY machine.
#
# Clients → CyberVault → their own JumpServer
# You (demo from any PC/phone) → CyberVault → YOUR JumpServer on :8085 (public IP)
#
# Usage on a cloud VPS / AWS:
#   bash deployment/scripts/16-deploy-public-with-lab.sh
#   PUBLIC_IP=1.2.3.4 bash deployment/scripts/16-deploy-public-with-lab.sh
#   CYBERVAULT_DOMAIN=app.example.com bash deployment/scripts/16-deploy-public-with-lab.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

HTTP_PORT="${JUMPSERVER_HTTP_PORT:-8085}"
SSH_PORT="${JUMPSERVER_SSH_PORT:-2222}"

detect_public_ip() {
  if [[ -n "${PUBLIC_IP:-}" ]]; then
    echo "$PUBLIC_IP"
    return
  fi
  local ip=""
  ip="$(curl -4 -fsS --max-time 4 https://checkip.amazonaws.com 2>/dev/null || true)"
  ip="${ip//$'\n'/}"
  if [[ -z "$ip" ]]; then
    ip="$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null || true)"
    ip="${ip//$'\n'/}"
  fi
  echo "$ip"
}

echo "============================================================"
echo " CyberVault public + JumpServer lab (any machine)"
echo "============================================================"
echo ""
echo "  Clients (anywhere) → CyberVault → THEIR JumpServer"
echo "  You (any PC)       → CyberVault → YOUR JumpServer :${HTTP_PORT}"
echo ""

bash "$ROOT/deployment/scripts/15-deploy-public.sh"

PUB_IP="$(detect_public_ip)"
EXTRA=""
if [[ -n "$PUB_IP" ]]; then
  EXTRA="${PUB_IP}:${HTTP_PORT}"
  echo "==> Public IP detected: ${PUB_IP}"
else
  echo "WARN: could not detect public IP — set PUBLIC_IP=x.x.x.x" >&2
fi
if [[ -n "${CYBERVAULT_DOMAIN:-}" ]]; then
  EXTRA="${EXTRA:+$EXTRA,}jumpserver.${CYBERVAULT_DOMAIN},${CYBERVAULT_DOMAIN}"
fi
export JUMPSERVER_HTTP_PORT="$HTTP_PORT"
export JUMPSERVER_SSH_PORT="$SSH_PORT"
export JUMPSERVER_EXTRA_DOMAINS="${EXTRA}${JUMPSERVER_EXTRA_DOMAINS:+,${JUMPSERVER_EXTRA_DOMAINS}}"
export JUMPSERVER_RECREATE_FOR_PUBLIC="${JUMPSERVER_RECREATE_FOR_PUBLIC:-1}"

echo ""
echo "==> Starting JumpServer lab (reachable from the Internet on :${HTTP_PORT})"
bash "$ROOT/deployment/scripts/12-start-jumpserver-allinone.sh"

# URL that works from ANY browser AND from CyberVault on the same server
if [[ -n "$PUB_IP" ]]; then
  JS_PUBLIC_URL="http://${PUB_IP}:${HTTP_PORT}"
elif [[ -n "${CYBERVAULT_DOMAIN:-}" ]]; then
  JS_PUBLIC_URL="http://jumpserver.${CYBERVAULT_DOMAIN}:${HTTP_PORT}"
else
  JS_PUBLIC_URL="http://<SERVER_PUBLIC_IP>:${HTTP_PORT}"
fi

if [[ -n "${CYBERVAULT_DOMAIN:-}" ]]; then
  CV_URL="https://${CYBERVAULT_DOMAIN}"
elif [[ -n "$PUB_IP" ]]; then
  CV_URL="http://${PUB_IP}"
else
  CV_URL="http://<SERVER_PUBLIC_IP>"
fi

echo ""
echo "============================================================"
echo " Access from ANY machine (not only your Mac)"
echo "============================================================"
echo ""
echo " 1) Open CyberVault on phone / other PC / café Wi‑Fi:"
echo "      ${CV_URL}"
echo ""
echo " 2) Sign up / log in → Mon PAM"
echo ""
echo " 3) Connect YOUR lab JumpServer:"
echo "      URL   : ${JS_PUBLIC_URL}"
echo "      Token : Access key ID:Secret"
echo "              (JumpServer UI → Avatar → Personal Settings → Access key)"
echo ""
echo " 4) JumpServer admin UI (any browser):"
echo "      ${JS_PUBLIC_URL}"
echo ""
echo " AWS / firewall — open inbound:"
echo "   • 80, 443  → CyberVault (clients + you)"
echo "   • ${HTTP_PORT}     → JumpServer lab UI/API (your tests)"
echo "   • ${SSH_PORT}    → optional JumpServer SSH"
echo ""
echo " Clients still use THEIR JumpServer URL — not ${JS_PUBLIC_URL}"
echo "============================================================"
