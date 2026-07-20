# CyberVault deployment guide

This guide covers production-style deployment of CyberVault with Docker Compose.

The stack starts with:

```bash
docker compose up --build
```

from the **repository root**.

---

## Prerequisites

- Linux, macOS, or Windows with Docker Desktop / Docker Engine
- Docker Compose v2 (`docker compose` plugin)
- At least 2 vCPU / 4 GB RAM for a comfortable demo
- Open outbound SMTP if you need live email delivery

Verify:

```bash
docker version
docker compose version
```

---

## Docker installation

### macOS / Windows

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Wait until the status is **Running**
3. Enable the Compose V2 plugin (default on recent Desktop builds)

### Linux

Follow the official Docker Engine docs for your distribution, then install the Compose plugin.

---

## Environment variables

```bash
cp .env.example .env
```

Important keys:

| Variable | Notes |
|----------|--------|
| `AISS_WEBHOOK_TOKEN` | **Required** for any real JumpServer traffic |
| `AISS_PUBLIC_URL` | Must match the URL users open in the browser |
| `AISS_ALLOW_SIGNUP` | `true` for first admin, then set `false` |
| `AISS_SMTP_*` | Optional email delivery |
| `CYBERVAULT_BIND_ADDRESS` | Keep `127.0.0.1` locally; use `0.0.0.0` only with a firewall |
| `CYBERVAULT_PORT` | Host port (default `8090`) |

Never commit `.env`. Rotate any credential that was previously committed or shared.

---

## First deployment (local)

```bash
cd /path/to/cybervault
cp .env.example .env
docker compose up --build --wait
```

Checks:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8090/health
curl -fsS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8090/
bash deployment/scripts/11-test-live-event.sh
```

Open `http://localhost:8090`, create an account, configure JumpServer in **Mon PAM**.

---

## Public Internet deployment (anyone, anywhere)

Exposes CyberVault on **port 80** (and **443** with a domain) via Caddy. Signup stays open.

### 1. Server prerequisites

- Linux VPS / cloud VM with a **public IP**
- Docker + Compose v2
- Firewall: allow **80** (and **443** if using a domain)
- Optional: DNS `A` record → your server IP

### 2. One-command deploy

```bash
cd /path/to/cybervault
bash deployment/scripts/15-deploy-public.sh
```

With automatic HTTPS (Let's Encrypt):

```bash
CYBERVAULT_DOMAIN=app.example.com \
CADDY_ACME_EMAIL=admin@example.com \
bash deployment/scripts/15-deploy-public.sh
```

Open:

- Domain: `https://app.example.com`
- IP only: `http://YOUR_PUBLIC_IP`

### 3. What users do

1. Open the public URL from anywhere  
2. **Sign up**  
3. **Mon PAM** → JumpServer URL + Access key (`ID:Secret`)  
4. JumpServer must be reachable **from the CyberVault server** (public URL or VPN)

### 4. Compose files

| File | Role |
|------|------|
| `docker-compose.yml` | Core stack (works without JumpServer Docker) |
| `docker-compose.public.yml` | Caddy edge proxy for Internet |
| `docker-compose.jms-lab.yml` | Optional local JumpServer Docker network |

Local JumpServer lab only:

```bash
docker compose -f docker-compose.yml -f docker-compose.jms-lab.yml up -d
```

### 6. Local 5-server lab (for Luna / CyberVault tests)

If Luna shows **Favorite (0)** / no assets, create a ready lab:

```bash
bash deployment/scripts/17-create-jumpserver-lab.sh
```

This starts 5 SSH containers and registers them in JumpServer:

- `lab-web`, `lab-db`, `lab-app`, `lab-bastion`, `lab-backup`
- Login: `root` / `CyberVaultLab1!`
- Permission granted to `admin`

Then open `http://localhost:8085/luna/` → Refresh → Connect.

---

### 7. Public CyberVault + your JumpServer lab (live from any machine)

Deploy on a **cloud VPS / AWS** (not only your Mac):

```bash
bash deployment/scripts/16-deploy-public-with-lab.sh
```

Then from **any** computer / phone:

1. Open CyberVault → `http://SERVER_PUBLIC_IP` (or your domain)
2. Mon PAM → URL `http://SERVER_PUBLIC_IP:8085` + Access key `ID:Secret`
3. JumpServer UI → same `http://SERVER_PUBLIC_IP:8085`

Open firewall ports **80**, **443**, and **8085**.

- **Clients** still paste *their* JumpServer in Mon PAM.  
- **You** use `:8085` on this server for demos / live tests from anywhere.

---

### 5. After go-live

- Set `AISS_PUBLIC_URL` to the real public URL (emails)
- Configure SMTP in `.env` for alerts
- Keep `AISS_DRY_RUN=true` until lock/kill is validated, then set `false` and recreate backend
- Open cloud security group / firewall for 80/443 only (not Redis)

---

## Docker Compose services

| Service | Role |
|---------|------|
| `redis` | Event channel + AOF persistence |
| `backend` | AI consumer, HTTP API, webhooks |
| `frontend` | nginx UI + reverse proxy to backend |

Network: `analytics` (bridge).  
Volumes: `cybervault-data` (runtime exports), `cybervault-redis`.

---

## Updating the application

```bash
git pull
docker compose up --build --force-recreate --wait
```

Or rebuild a single service:

```bash
docker compose build backend --no-cache
docker compose up -d backend
```

---

## Stopping / restarting

```bash
# Stop (keep volumes)
docker compose stop

# Start again
docker compose start

# Restart one service
docker compose restart backend

# Full teardown (keeps named volumes by default)
docker compose down

# Teardown including data volumes (destructive)
docker compose down -v
```

---

## Rebuilding containers

```bash
docker compose build --no-cache
docker compose up -d --force-recreate --wait
```

---

## Viewing logs

```bash
docker compose logs -f
docker compose logs -f backend
docker compose logs --since=10m frontend
```

---

## Backup strategy

### Application state

Named volume `cybervault-data` stores users, sessions, config, decisions, and alert outbox.

```bash
# Example backup
docker run --rm \
  -v cybervault_cybervault-data:/data:ro \
  -v "$(pwd)/backups:/backup" \
  alpine tar czf /backup/cybervault-data-$(date +%F).tgz -C /data .
```

### Redis

Volume `cybervault-redis` holds AOF. Back it up the same way if you rely on Redis-buffered events.

### Configuration

Keep a secure copy of `.env` and JumpServer webhook settings outside the repository.

---

## Restoring data

```bash
docker compose down
docker run --rm \
  -v cybervault_cybervault-data:/data \
  -v "$(pwd)/backups:/backup" \
  alpine sh -c 'cd /data && tar xzf /backup/cybervault-data-YYYY-MM-DD.tgz'
docker compose up -d --wait
```

Adjust the volume name with `docker volume ls` if your Compose project prefix differs.

---

## AWS EC2 notes

Helpers live under `deployment/aws/`:

1. Restrict the security group to your IP (`/32`)
2. Prefer SSH tunnel or reverse proxy with TLS over exposing `8090` publicly
3. Set `CYBERVAULT_BIND_ADDRESS=0.0.0.0` only when the host firewall is locked down
4. Set `AISS_PUBLIC_URL` to the public HTTPS URL users will open
5. Delete the CloudFormation stack when the PoC is finished to stop costs

See `deployment/aws/README.md` for the PoC template.

---

## JumpServer connection scripts

```bash
bash deployment/scripts/connect-jumpserver.sh
# or on macOS Docker Desktop:
bash deployment/scripts/connect-jumpserver-mac.sh
```

Plugin code: `integrations/jumpserver/`.

---

## Troubleshooting

| Issue | Action |
|-------|--------|
| Daemon not running | Start Docker Desktop / `systemctl start docker` |
| Port conflict | Change `CYBERVAULT_PORT` |
| Backend unhealthy | `docker compose logs backend` — often Redis URL or permissions |
| Frontend 502 | Backend not ready yet; wait for healthcheck |
| Webhook rejected | Empty or mismatched `AISS_WEBHOOK_TOKEN` |
| Email not received | Verify SMTP vars; check outbox in data volume |
| Disk growth | Rotate / truncate `decisions.jsonl` and Redis AOF periodically |

---

## Security checklist before public exposure

- [ ] Strong unique `AISS_WEBHOOK_TOKEN` (auto-generated by `15-deploy-public.sh`)
- [ ] TLS via `CYBERVAULT_DOMAIN` (recommended) or terminate TLS at your cloud LB
- [ ] Firewall: only 80/443 (and SSH) open to the world
- [ ] Keep `AISS_DRY_RUN=true` until actions are validated
- [ ] SMTP credentials stored only in `.env` / secret store
- [ ] JumpServer Access keys treated as secrets
