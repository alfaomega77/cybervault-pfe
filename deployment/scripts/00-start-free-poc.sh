#!/usr/bin/env bash
# CyberVault — free local PoC (dry-run).
# Usage: bash deployment/scripts/00-start-free-poc.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "=============================================="
echo " CyberVault FREE POC"
echo " Mode: dry-run (no live session kill)"
echo "=============================================="

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo ">>> Starting stack with Docker Compose..."
  docker compose up --build -d --wait
  echo ""
  echo "OK — open http://localhost:8090"
  echo "Health: $(curl -sf http://127.0.0.1:8090/health || echo unavailable)"
  echo "Smoke:  bash deployment/scripts/11-test-live-event.sh"
  exit 0
fi

echo "Docker unavailable — starting local Python server..."
bash "$ROOT/deployment/scripts/10-start-web-ui.sh"
