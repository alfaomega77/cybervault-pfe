#!/usr/bin/env bash
# Create a 5-server SSH lab + register them in JumpServer for Luna / CyberVault tests.
# Usage: bash deployment/scripts/17-create-jumpserver-lab.sh
set -euo pipefail

LAB_PASS="${LAB_PASS:-CyberVaultLab1!}"
LAB_USER="${LAB_USER:-root}"
IMAGE="${LAB_SSH_IMAGE:-panubo/sshd:1.5.0}"
JMS_NAME="${JUMPSERVER_CONTAINER_NAME:-jms_all}"

SERVERS=(
  "lab-web:cv-lab-web"
  "lab-db:cv-lab-db"
  "lab-app:cv-lab-app"
  "lab-bastion:cv-lab-bastion"
  "lab-backup:cv-lab-backup"
)

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running" >&2
  exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -qx "$JMS_NAME"; then
  echo "ERROR: JumpServer container '$JMS_NAME' is not running." >&2
  echo "Start it with: bash deployment/scripts/12-start-jumpserver-allinone.sh" >&2
  exit 1
fi

echo "==> Pull image $IMAGE"
docker pull "$IMAGE" >/dev/null

echo "==> Create / recreate 5 lab SSH servers"
MAP_LINES=()
for entry in "${SERVERS[@]}"; do
  name="${entry%%:*}"
  cname="${entry##*:}"
  docker rm -f "$cname" >/dev/null 2>&1 || true
  docker run -d \
    --name "$cname" \
    --hostname "$name" \
    --restart unless-stopped \
    -e SSH_ENABLE_PASSWORD_AUTH=true \
    -e SSH_ENABLE_ROOT=true \
    "$IMAGE" >/dev/null
done

sleep 3
for entry in "${SERVERS[@]}"; do
  name="${entry%%:*}"
  cname="${entry##*:}"
  for _ in $(seq 1 15); do
    if docker exec "$cname" true >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  docker exec "$cname" sh -c "
    echo 'root:${LAB_PASS}' | chpasswd
    if ! id ${LAB_USER} >/dev/null 2>&1; then
      useradd -m -s /bin/bash ${LAB_USER} || true
    fi
    echo '${LAB_USER}:${LAB_PASS}' | chpasswd
    if [ -f /etc/ssh/sshd_config ]; then
      sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
      sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
      pkill -HUP sshd || true
    fi
  " >/dev/null 2>&1 || true
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cname" | awk '{print $1}')"
  if [[ -z "$ip" ]]; then
    echo "ERROR: no IP for $cname" >&2
    exit 1
  fi
  echo "  ✓ $name  container=$cname  ip=$ip"
  MAP_LINES+=("${name}|${ip}")
done

PY_SERVERS="$(printf "'%s'," "${MAP_LINES[@]}")"
PY_SERVERS="[${PY_SERVERS%,}]"

echo "==> Register assets + accounts + permission in JumpServer"
docker exec \
  -e LAB_PASS="$LAB_PASS" \
  -e LAB_USER="$LAB_USER" \
  -e PY_SERVERS="$PY_SERVERS" \
  "$JMS_NAME" bash -lc '
source /opt/py3/bin/activate
export REDIS_PASSWORD=PleaseChangeMe REDIS_HOST=127.0.0.1
export DB_PASSWORD=PleaseChangeMe SECRET_KEY=CyberVaultDemoSecretKeyChangeMe32chars
export DB_ENGINE=postgresql DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=postgres DB_NAME=jumpserver
cd /opt/jumpserver/apps
python manage.py shell <<'"'"'EOF'"'"'
import os
from datetime import timedelta
from django.utils import timezone
from orgs.models import Organization
from orgs.utils import tmp_to_org
from assets.models import Asset, Platform, Node, Protocol
from accounts.models import Account
from accounts.const import SecretType
from perms.models import AssetPermission
from perms.const import ActionChoices
from users.models import User

lab_user = os.environ.get("LAB_USER", "root")
lab_pass = os.environ.get("LAB_PASS", "CyberVaultLab1!")
servers = [s.split("|", 1) for s in eval(os.environ["PY_SERVERS"])]
ORG = Organization.objects.get(id="00000000-0000-0000-0000-000000000002")
ALL = sum(ActionChoices.values)

with tmp_to_org(ORG):
    platform = Platform.objects.filter(name="Linux").first()
    node = Node.org_root() if hasattr(Node, "org_root") else Node.objects.first()
    admin = User.objects.get(username="admin")
    created = []
    for name, ip in servers:
        asset = Asset.objects.filter(name=name).first()
        if not asset:
            asset = Asset(name=name)
        asset.address = ip
        asset.platform = platform
        asset.is_active = True
        asset.comment = "CyberVault lab"
        asset.save()
        asset.nodes.set([node])
        Protocol.objects.filter(asset=asset).delete()
        Protocol.objects.create(asset=asset, name="ssh", port=22)
        Protocol.objects.create(asset=asset, name="sftp", port=22)
        acc = Account.objects.filter(asset=asset, name="root").first()
        if not acc:
            acc = Account(asset=asset, name="root")
        acc.username = lab_user
        acc.secret_type = SecretType.PASSWORD
        acc.privileged = True
        acc.is_active = True
        acc.secret = lab_pass
        acc.save()
        created.append(asset)
        print("ASSET_OK", name, ip)

    perm = AssetPermission.objects.filter(name="CyberVault Lab — admin all servers").first()
    if not perm:
        perm = AssetPermission(name="CyberVault Lab — admin all servers")
    perm.is_active = True
    perm.date_start = timezone.now() - timedelta(days=1)
    perm.date_expired = timezone.now() + timedelta(days=3650)
    perm.accounts = ["@ALL"]
    perm.protocols = ["all"]
    perm.actions = ALL
    perm.save()
    perm.users.set([admin])
    perm.assets.set(created)
    print("PERM_OK", len(created))
    print("DONE")
EOF
'

echo ""
echo "============================================================"
echo " Lab ready — 5 servers in JumpServer"
echo "============================================================"
echo " JumpServer UI : http://localhost:8085"
echo " Luna (web)    : http://localhost:8085/luna/"
echo ""
echo " Servers: lab-web, lab-db, lab-app, lab-bastion, lab-backup"
echo " SSH login   : user=${LAB_USER}  password=${LAB_PASS}"
echo ""
echo " How to test:"
echo "   1. Open Luna → Refresh → click a server → Connect (SSH)"
echo "   2. Type commands (whoami, ls, rm -rf /tmp/x ...)"
echo "   3. Watch CyberVault Temps réel (Mon PAM connected)"
echo "============================================================"
