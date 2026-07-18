#!/usr/bin/env bash
# Start CyberVault (AISS) on this host for AWS real-time POC.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEPLOY="$ROOT/deploy"
AWS_DIR="$ROOT/deploy/aws"

echo "=============================================="
echo " CyberVault AWS POC — start AI Security"
echo " ROOT=$ROOT"
echo "=============================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker missing. Run: sudo bash deploy/aws/user-data.sh"
  exit 1
fi

COMPOSE="docker compose"
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
  else
    echo "Install docker compose plugin first."
    exit 1
  fi
fi

# Env for compose
if [[ ! -f "$DEPLOY/.env" ]]; then
  cp "$AWS_DIR/env.aws.example" "$DEPLOY/.env"
  echo "Created deploy/.env from env.aws.example (DRY_RUN=true)."
fi

cd "$DEPLOY"
$COMPOSE -f docker-compose.aiss.yml up -d --build

echo ""
echo "Waiting for health…"
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8090/health >/dev/null 2>&1; then
    echo "AISS healthy: $(curl -sf http://127.0.0.1:8090/health)"
    break
  fi
  sleep 2
  if [[ "$i" -eq 30 ]]; then
    echo "WARN: health not ready yet. Check: docker logs aiss-consumer"
  fi
done

echo ""
docker ps --filter name=aiss --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo ""
echo "NEXT:"
echo "  1) Install JumpServer:"
echo "       curl -sSL https://github.com/jumpserver/installer/releases/latest/download/quick_start.sh | bash"
echo "  2) Connect plugin:"
echo "       bash $ROOT/deploy/scripts/connect-jumpserver.sh"
echo "  3) Live test:"
echo "       bash $AWS_DIR/test-realtime.sh"
echo "  4) Open dashboard: http://$(curl -s ifconfig.me 2>/dev/null || echo EC2_IP):8090"
echo ""
