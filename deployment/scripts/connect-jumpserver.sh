#!/usr/bin/env bash
# Connect official JumpServer (Docker) to AI Security Service.
# Run AFTER JumpServer is installed and running.
#
# Usage: bash deploy/scripts/connect-jumpserver.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== Connecting JumpServer to AI Security Service ==="

CORE=$(docker ps --format '{{.Names}}' | grep -E 'jms_core|core' | head -1 || true)
if [ -z "$CORE" ]; then
  echo "ERROR: JumpServer core container not found."
  echo "Install JumpServer first:"
  echo "  curl -sSL https://github.com/jumpserver/installer/releases/latest/download/quick_start.sh | bash"
  exit 1
fi

echo "Found JumpServer core container: $CORE"

# Copy ai_security plugin + JumpServer config patches
echo "Copying ai_security plugin into container..."
docker cp "$ROOT/apps/ai_security" "$CORE:/opt/jumpserver/apps/ai_security"
docker cp "$ROOT/apps/jumpserver/conf.py" "$CORE:/opt/jumpserver/apps/jumpserver/conf.py"
docker cp "$ROOT/apps/jumpserver/settings/custom.py" "$CORE:/opt/jumpserver/apps/jumpserver/settings/custom.py"
docker cp "$ROOT/apps/jumpserver/settings/base.py" "$CORE:/opt/jumpserver/apps/jumpserver/settings/base.py"

# Copy patched terminal hooks (command.py, session.py changes)
echo "Copying API hooks..."
docker cp "$ROOT/apps/terminal/api/session/command.py" \
  "$CORE:/opt/jumpserver/apps/terminal/api/session/command.py"
docker cp "$ROOT/apps/terminal/api/session/session.py" \
  "$CORE:/opt/jumpserver/apps/terminal/api/session/session.py"

# Enable in config.yml inside container
echo "Enabling AI_SECURITY in config..."
docker exec "$CORE" bash -c '
CONFIG=/opt/jumpserver/config.yml
if [ ! -f "$CONFIG" ]; then CONFIG=/opt/jumpserver/config/config.yml; fi
grep -q AI_SECURITY_ENABLED "$CONFIG" 2>/dev/null || cat >> "$CONFIG" <<EOF

# AI Security Layer
AI_SECURITY_ENABLED: true
AI_SECURITY_PUBLISHER: redis
AI_SECURITY_REDIS_CHANNEL: fm.security_events
EOF
'

# Point Redis to AISS redis on host (port 6380 mapped from aiss stack)
# JumpServer redis is internal; use HTTP webhook to aiss instead if redis isolated
HOST_IP=$(hostname -I 2>/dev/null | awk "{print \$1}" || echo "172.17.0.1")
docker exec "$CORE" bash -c "
CONFIG=/opt/jumpserver/config.yml
[ ! -f \"\$CONFIG\" ] && CONFIG=/opt/jumpserver/config/config.yml
sed -i 's/^AI_SECURITY_PUBLISHER:.*/AI_SECURITY_PUBLISHER: http/' \"\$CONFIG\" 2>/dev/null || true
grep -q AI_SECURITY_WEBHOOK_URL \"\$CONFIG\" || echo 'AI_SECURITY_WEBHOOK_URL: http://${HOST_IP}:8090/events' >> \"\$CONFIG\"
sed -i 's|^AI_SECURITY_WEBHOOK_URL:.*|AI_SECURITY_WEBHOOK_URL: http://${HOST_IP}:8090/events|' \"\$CONFIG\"
"

echo "Restarting JumpServer core..."
docker restart "$CORE"

echo ""
echo "SUCCESS — JumpServer should now send events to AI Security Service."
echo ""
echo "Test:"
echo "  1. Open an SSH session in JumpServer UI"
echo "  2. Run: rm -rf /tmp/test"
echo "  3. Check AI logs:"
echo "     docker logs -f aiss-consumer"
echo ""
echo "To enable LIVE kill (not dry-run), edit deploy/.env:"
echo "  AISS_DRY_RUN=false"
echo "  AISS_JUMPSERVER_URL=http://${HOST_IP}"
echo "  AISS_JUMPSERVER_TOKEN=<your-api-token>"
echo "Then: cd deploy && docker compose -f docker-compose.aiss.yml up -d"
