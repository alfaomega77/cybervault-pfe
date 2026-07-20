#!/usr/bin/env bash
# Run from your Mac after the EC2 instance is up.
# Usage:
#   bash deployment/scripts/18-aws-beginner-remote-deploy.sh <PUBLIC_IP> [path-to-pem]
# Example:
#   bash deployment/scripts/18-aws-beginner-remote-deploy.sh 54.1.2.3 ~/Downloads/cybervault-key.pem
set -euo pipefail

IP="${1:-}"
KEY="${2:-$HOME/Downloads/cybervault-key.pem}"
USER_NAME="${AWS_EC2_USER:-ubuntu}"

if [[ -z "$IP" ]]; then
  echo "Usage: $0 <PUBLIC_IP> [path-to-pem]" >&2
  exit 1
fi
if [[ ! -f "$KEY" ]]; then
  echo "ERROR: key not found: $KEY" >&2
  exit 1
fi

chmod 400 "$KEY" 2>/dev/null || true
SSH=(ssh -i "$KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "${USER_NAME}@${IP}")

echo "==> Checking SSH to ${USER_NAME}@${IP}"
"${SSH[@]}" 'echo SSH_OK && uname -a'

echo "==> Installing Docker (if needed)"
"${SSH[@]}" 'bash -s' <<'REMOTE'
set -euo pipefail
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sudo sh
fi
sudo usermod -aG docker ubuntu || true
sudo systemctl enable --now docker
docker --version
sudo docker compose version
REMOTE

echo "==> Cloning / updating CyberVault and deploying (public HTTP)"
"${SSH[@]}" 'bash -s' <<'REMOTE'
set -euo pipefail
# new shell after usermod often still lacks group until re-login; use sg/docker via sudo where needed
cd ~
if [[ ! -d cybervault-pfe/.git ]]; then
  git clone https://github.com/alfaomega77/cybervault-pfe.git
fi
cd cybervault-pfe
git pull --ff-only || true
# ensure docker usable without re-login
if ! docker info >/dev/null 2>&1; then
  echo "Using sg docker for this session"
  sg docker -c 'bash deployment/scripts/15-deploy-public.sh'
else
  bash deployment/scripts/15-deploy-public.sh
fi
# Named volume is root-owned by default; backend runs as uid 10001.
vol="$(docker volume ls -q | grep cybervault-data | head -1 || true)"
if [[ -n "$vol" ]]; then
  docker run --rm -v "${vol}:/data" alpine chown -R 10001:10001 /data
  docker compose -f docker-compose.yml -f docker-compose.public.yml restart backend || true
  sleep 3
fi
curl -fsS http://127.0.0.1/health || curl -fsS http://127.0.0.1:8090/health || true
REMOTE

echo
echo "============================================================"
echo " Deploy finished. Open from any device:"
echo "   http://${IP}"
echo " Health from your Mac:"
echo "   curl -fsS http://${IP}/health"
echo " Stop the EC2 instance in AWS Console when not demoing."
echo "============================================================"
