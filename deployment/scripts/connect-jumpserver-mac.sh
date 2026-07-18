#!/usr/bin/env bash
# Connect JumpServer (Docker on Mac) → CyberVault on host :8090
# Usage: bash deployment/scripts/connect-jumpserver-mac.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PLUGIN_SRC="$ROOT/integrations/jumpserver/ai_security"
SETTINGS_SRC="$ROOT/integrations/jumpserver/ai_security_settings.py"

# Load root .env if present
if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

WEBHOOK_HOST="${CYBERVAULT_WEBHOOK_HOST:-host.docker.internal}"
WEBHOOK_PORT="${CYBERVAULT_PORT:-8090}"
WEBHOOK_URL="http://${WEBHOOK_HOST}:${WEBHOOK_PORT}/events"
TOKEN="${AISS_WEBHOOK_TOKEN:-}"

if [[ -z "$TOKEN" ]]; then
  echo "ERROR: AISS_WEBHOOK_TOKEN manquant. Définis-le dans .env à la racine."
  exit 1
fi

if [[ ! -d "$PLUGIN_SRC" ]]; then
  echo "ERROR: plugin introuvable: $PLUGIN_SRC"
  exit 1
fi

echo "=== JumpServer (Mac) → CyberVault ==="
echo "    Webhook: ${WEBHOOK_URL}"
echo ""

CORE=$(docker ps --format '{{.Names}}' | grep -E 'jms_all|jms_core|^core$' | head -1 || true)
if [[ -z "$CORE" ]]; then
  echo "ERROR: aucun conteneur JumpServer trouvé."
  echo "Lance d'abord:"
  echo "  bash deployment/scripts/12-start-jumpserver-allinone.sh"
  exit 1
fi

echo "Conteneur: $CORE"

# Detect apps root inside container
APPS=""
for candidate in /opt/jumpserver/apps /opt/jumpserver/apps /home/jumpserver/apps; do
  if docker exec "$CORE" test -d "$candidate" 2>/dev/null; then
    APPS="$candidate"
    break
  fi
done

if [[ -z "$APPS" ]]; then
  APPS=$(docker exec "$CORE" sh -c 'ls -d /opt/jumpserver/apps 2>/dev/null || ls -d /opt/*/apps 2>/dev/null | head -1' || true)
fi

if [[ -z "$APPS" ]]; then
  echo "ERROR: impossible de trouver le dossier apps/ dans $CORE"
  echo "Inspecte avec: docker exec -it $CORE bash"
  exit 1
fi

SETTINGS_DIR=$(docker exec "$CORE" sh -c 'ls -d '"$APPS"'/jumpserver/settings 2>/dev/null | head -1' || true)
if [[ -z "$SETTINGS_DIR" ]]; then
  echo "ERROR: settings JumpServer introuvables sous $APPS"
  exit 1
fi

echo "Apps: $APPS"
echo "Copie du plugin CyberVault..."
docker cp "$PLUGIN_SRC" "$CORE:$APPS/ai_security"
docker cp "$SETTINGS_SRC" "$CORE:$SETTINGS_DIR/ai_security_settings.py"

docker exec "$CORE" bash -c "
set -e
BASE=$SETTINGS_DIR/base.py
CUSTOM=$SETTINGS_DIR/custom.py
if [ -f \"\$BASE\" ] && ! grep -q \"ai_security.apps.AiSecurityConfig\" \"\$BASE\"; then
  sed -i.bak \"/INSTALLED_APPS = \\[/a\\    'ai_security.apps.AiSecurityConfig',\" \"\$BASE\" || true
fi
if [ -f \"\$CUSTOM\" ] && ! grep -q ai_security_settings \"\$CUSTOM\"; then
  printf '\nfrom .ai_security_settings import *  # CyberVault\n' >> \"\$CUSTOM\"
fi
"

# Config.yml / config.txt
docker exec "$CORE" bash -c "
set -e
for CONFIG in /opt/jumpserver/config.yml /opt/jumpserver/config/config.yml /opt/jumpserver/config/config.txt /opt/data/config.yml; do
  DIR=\$(dirname \"\$CONFIG\")
  [ -d \"\$DIR\" ] || continue
  touch \"\$CONFIG\"
  if ! grep -q '^AI_SECURITY_ENABLED' \"\$CONFIG\" 2>/dev/null; then
    cat >> \"\$CONFIG\" <<EOF

# CyberVault AI Security
AI_SECURITY_ENABLED: true
AI_SECURITY_PUBLISHER: http
AI_SECURITY_WEBHOOK_URL: ${WEBHOOK_URL}
AI_SECURITY_WEBHOOK_TOKEN: ${TOKEN}
EOF
  else
    sed -i.bak 's/^AI_SECURITY_ENABLED:.*/AI_SECURITY_ENABLED: true/' \"\$CONFIG\" 2>/dev/null || true
    sed -i.bak 's/^AI_SECURITY_PUBLISHER:.*/AI_SECURITY_PUBLISHER: http/' \"\$CONFIG\" 2>/dev/null || true
    sed -i.bak 's|^AI_SECURITY_WEBHOOK_URL:.*|AI_SECURITY_WEBHOOK_URL: ${WEBHOOK_URL}|' \"\$CONFIG\" 2>/dev/null || true
    sed -i.bak 's/^AI_SECURITY_WEBHOOK_TOKEN:.*/AI_SECURITY_WEBHOOK_TOKEN: ${TOKEN}/' \"\$CONFIG\" 2>/dev/null || true
  fi
  echo \"--- \$CONFIG ---\"
  grep AI_SECURITY \"\$CONFIG\" | sed 's/WEBHOOK_TOKEN:.*/WEBHOOK_TOKEN: ***/' || true
  break
done
"

echo "Redémarrage de $CORE..."
docker restart "$CORE"

echo ""
echo "OK — plugin installé. Attends ~1 min que JumpServer remonte."
echo ""
echo "Prochaines étapes :"
echo "  1. Ouvre JumpServer : http://localhost (port ${JUMPSERVER_HTTP_PORT:-80})"
echo "  2. CyberVault Mon PAM → Intégrer (URL http://localhost)"
echo "  3. Démo 3 sessions : bash deployment/scripts/13-demo-sales-live.sh"
echo ""
echo "Note: les commandes shell détaillées passent mieux via le script démo"
echo "      tant que le hook terminal JumpServer n'est pas patché."
