#!/usr/bin/env bash
# Démarre JumpServer all-in-one (Docker) — local ou lab public.
# Usage:
#   bash deployment/scripts/12-start-jumpserver-allinone.sh
#   JUMPSERVER_EXTRA_DOMAINS=1.2.3.4:8085 JUMPSERVER_RECREATE_FOR_PUBLIC=1 \
#     bash deployment/scripts/12-start-jumpserver-allinone.sh
set -euo pipefail

NAME="${JUMPSERVER_CONTAINER_NAME:-jms_all}"
IMAGE="${JUMPSERVER_IMAGE:-jumpserver/jms_all:latest}"
HTTP_PORT="${JUMPSERVER_HTTP_PORT:-8085}"
SSH_PORT="${JUMPSERVER_SSH_PORT:-2222}"

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker n'est pas démarré. Ouvre Docker Desktop puis réessaie."
  exit 1
fi

DOMAINS="localhost:${HTTP_PORT},127.0.0.1:${HTTP_PORT}"
if [[ -n "${JUMPSERVER_EXTRA_DOMAINS:-}" ]]; then
  DOMAINS="${DOMAINS},${JUMPSERVER_EXTRA_DOMAINS}"
fi

start_new() {
  echo "=== JumpServer all-in-one ==="
  echo "Image : $IMAGE"
  echo "Ports : 0.0.0.0:${HTTP_PORT} (HTTP)  0.0.0.0:${SSH_PORT} (SSH)"
  echo "DOMAINS=${DOMAINS}"
  echo ""

  docker volume create jsdata >/dev/null
  docker volume create pgdata >/dev/null

  SECRET_KEY="${JUMPSERVER_SECRET_KEY:-CyberVaultDemoSecretKeyChangeMe32chars}"
  BOOTSTRAP_TOKEN="${JUMPSERVER_BOOTSTRAP_TOKEN:-CyberVaultBootstrapTok}"

  docker pull "$IMAGE"

  docker run -d --name "$NAME" \
    --restart unless-stopped \
    -e SECRET_KEY="$SECRET_KEY" \
    -e BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
    -e "DOMAINS=${DOMAINS}" \
    -v jsdata:/opt/data \
    -v pgdata:/var/lib/postgresql \
    -p "${HTTP_PORT}:80" \
    -p "${SSH_PORT}:2222" \
    "$IMAGE"

  echo ""
  echo "JumpServer démarre (1–3 min au premier boot)."
  echo "  UI : http://localhost:${HTTP_PORT}  (et http://<PUBLIC_IP>:${HTTP_PORT} si le firewall ouvre le port)"
}

if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  if [[ "${JUMPSERVER_RECREATE_FOR_PUBLIC:-0}" == "1" ]]; then
    echo "==> Recreating $NAME with public DOMAINS (${DOMAINS})"
    docker rm -f "$NAME" >/dev/null
    start_new
    exit 0
  fi
  if docker ps --format '{{.Names}}' | grep -qx "$NAME"; then
    echo "OK — JumpServer déjà démarré: $NAME"
  else
    echo "Redémarrage du conteneur existant $NAME..."
    docker start "$NAME"
  fi
  echo "UI:  http://localhost:${HTTP_PORT}"
  echo "(Pour forcer DOMAINS publics: JUMPSERVER_RECREATE_FOR_PUBLIC=1)"
  exit 0
fi

start_new
