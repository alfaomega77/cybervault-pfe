#!/usr/bin/env bash
# Start CyberVault on this host for an AWS / VPS real-time POC.
# Thin wrapper around the public Internet deploy script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

echo "=============================================="
echo " CyberVault AWS POC — start AI Security"
echo " ROOT=$ROOT"
echo "=============================================="

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker missing. Run: sudo bash deployment/aws/user-data.sh"
  exit 1
fi

# Prefer public edge (Caddy :80/:443). Pass through domain/email if set.
exec bash "$ROOT/deployment/scripts/15-deploy-public.sh"
