#!/usr/bin/env bash
# Bootstrap Docker on Ubuntu EC2 (also used as reference for manual Path B).
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Re-run with sudo: sudo bash deploy/aws/user-data.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y curl git unzip ca-certificates jq
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi
systemctl enable --now docker
# Add default ubuntu user to docker group when present
if id ubuntu >/dev/null 2>&1; then
  usermod -aG docker ubuntu || true
fi
mkdir -p /opt/cybervault
echo "bootstrap ok $(date -Is)" | tee /opt/cybervault/bootstrap.log
docker --version
echo "Done. Log out/in if needed for docker group, then: bash deploy/aws/run-poc.sh"
