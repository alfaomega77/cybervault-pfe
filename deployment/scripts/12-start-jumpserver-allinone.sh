#!/usr/bin/env bash
# Démarre JumpServer all-in-one (Docker) pour une démo locale.
# Usage: bash deployment/scripts/12-start-jumpserver-allinone.sh
set -euo pipefail

NAME="${JUMPSERVER_CONTAINER_NAME:-jms_all}"
IMAGE="${JUMPSERVER_IMAGE:-jumpserver/jms_all:latest}"
HTTP_PORT="${JUMPSERVER_HTTP_PORT:-8085}"
SSH_PORT="${JUMPSERVER_SSH_PORT:-2222}"

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker n'est pas démarré. Ouvre Docker Desktop puis réessaie."
  exit 1
fi

if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "OK — JumpServer déjà démarré: $NAME"
  echo "UI:  http://localhost:${HTTP_PORT}"
  exit 0
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  echo "Redémarrage du conteneur existant $NAME..."
  docker start "$NAME"
  echo "UI:  http://localhost:${HTTP_PORT}"
  exit 0
fi

echo "=== JumpServer all-in-one ==="
echo "Image : $IMAGE"
echo "Ports : http://localhost:${HTTP_PORT}  ssh://localhost:${SSH_PORT}"
echo "Note  : sur Mac 8 Go RAM, ferme les apps lourdes. Premier pull = long."
echo ""

docker volume create jsdata >/dev/null
docker volume create pgdata >/dev/null

# Secrets locaux de démo (changer en prod)
SECRET_KEY="${JUMPSERVER_SECRET_KEY:-CyberVaultDemoSecretKeyChangeMe32chars}"
BOOTSTRAP_TOKEN="${JUMPSERVER_BOOTSTRAP_TOKEN:-CyberVaultBootstrapTok}"

docker pull "$IMAGE"

docker run -d --name "$NAME" \
  --restart unless-stopped \
  -e SECRET_KEY="$SECRET_KEY" \
  -e BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
  -v jsdata:/opt/data \
  -v pgdata:/var/lib/postgresql \
  -p "${HTTP_PORT}:80" \
  -p "${SSH_PORT}:2222" \
  "$IMAGE"

echo ""
echo "JumpServer démarre (1–3 min au premier boot)."
echo "  UI : http://localhost:${HTTP_PORT}"
echo "  Login initial souvent : admin / ChangeMe (vérifie la doc de l'image)"
echo ""
echo "Ensuite :"
echo "  bash deployment/scripts/connect-jumpserver-mac.sh"
