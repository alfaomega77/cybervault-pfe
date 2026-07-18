# CyberVault — AWS real-time POC (client cloud)

Deploy **JumpServer + AI Security (CyberVault)** on an EC2 instance in the
client VPC and test privileged sessions **in real time**.

```
Admin SSH / Web terminal
        │
        ▼
   JumpServer (Docker on EC2)
        │  HTTP webhook (temps réel)
        ▼
   ai-security-service :8090
   (rules + UEBA + ML + MOO)
        │
        ├─► Dashboard http://EC2_IP:8090
        └─► dry-run LOCK/KILL (safe by default)
```

> **Safety:** `AISS_DRY_RUN=true` by default. Do not disable on a production
> bastion without a change window and a service account token.

---

## Files in this folder

| File | Purpose |
|------|---------|
| `README.md` | This guide |
| `cloudformation-ec2-poc.yaml` | One-click VPC SG + EC2 |
| `user-data.sh` | Bootstrap Docker on first boot |
| `env.aws.example` | Environment for compose |
| `jumpserver-ai-security.snippet.yml` | JumpServer config keys |
| `test-realtime.sh` | Health + live event injection |
| `run-poc.sh` | Install AISS + connect helpers |

---

## Prerequisites (client AWS)

- AWS account with rights to create EC2, SG, key pair
- Region e.g. `eu-west-1` / `us-east-1`
- Key pair `.pem` for SSH
- Optional: elastic IP

**Instance size:** `t3.xlarge` (4 vCPU / 16 GB) recommended. Minimum `t3.large`.

---

## Path A — CloudFormation (recommended)

### 1. Create stack

Console → **CloudFormation** → Create stack → Upload  
`deploy/aws/cloudformation-ec2-poc.yaml`

Parameters:

- `KeyName` — your EC2 key pair  
- `AllowedCidr` — **your IP/32** (not `0.0.0.0/0` in real client env)  
- `InstanceType` — `t3.xlarge`

Or CLI:

```bash
aws cloudformation create-stack \
  --stack-name cybervault-poc \
  --template-body file://deploy/aws/cloudformation-ec2-poc.yaml \
  --parameters \
    ParameterKey=KeyName,ParameterValue=YOUR_KEY \
    ParameterKey=AllowedCidr,ParameterValue=YOUR.IP.ADDR/32 \
  --capabilities CAPABILITY_NAMED_IAM
```

### 2. Wait & note Public IP

Outputs → `PublicIP`, `SSHCommand`, `DashboardURL`.

### 3. SSH & deploy code

```bash
ssh -i YOUR_KEY.pem ubuntu@EC2_PUBLIC_IP

# On EC2 — get the project (pick one)
# A) scp zip from your Mac
# B) git clone YOUR_REPO

cd jumpserver-dev   # or wherever you unpacked
bash deploy/aws/run-poc.sh
```

`run-poc.sh` installs Docker (if needed), starts Redis + CyberVault consumer,
prints next steps for JumpServer.

### 4. Install JumpServer (official)

```bash
curl -sSL https://github.com/jumpserver/installer/releases/latest/download/quick_start.sh | bash
cd /opt/jumpserver-installer-*
./jmsctl.sh start
```

Open `http://EC2_PUBLIC_IP` → login `admin` / change password.

### 5. Connect JumpServer → CyberVault (real-time webhook)

```bash
cd ~/jumpserver-dev   # project root on EC2
bash deploy/scripts/connect-jumpserver.sh
```

Or manually merge keys from `jumpserver-ai-security.snippet.yml` into JumpServer
`config.yml`, then restart core.

### 6. Live test

```bash
bash deploy/aws/test-realtime.sh http://127.0.0.1:8090
```

Then in JumpServer UI: open SSH session → run `rm -rf /tmp/cybervault-test` →
watch:

```bash
docker logs -f aiss-consumer
# browser: http://EC2_PUBLIC_IP:8090/app.html
```

---

## Path B — Existing EC2 (no CloudFormation)

```bash
# On Ubuntu 22.04 EC2
sudo apt update && sudo apt install -y git unzip
# copy project, then:
bash deploy/aws/user-data.sh          # docker if missing
bash deploy/aws/run-poc.sh
# JumpServer installer + connect-jumpserver.sh (same as above)
```

Open SG ports: **22**, **80**, **443**, **2222**, **8090** (source = your IP).

---

## Real-time flow checklist

| Step | Expected |
|------|----------|
| `curl http://127.0.0.1:8090/health` | `{"status":"ok"}` |
| JumpServer command ingest | Event reaches AISS &lt; 1–2 s |
| Dashboard `/app.html` | Risk + action visible |
| `docker logs aiss-consumer` | `risk=… action=…` |
| Destructive command | HIGH / ALERT or LOCK (dry-run) |

---

## Optional: enable live LOCK/KILL (staging only)

```bash
cd deploy
cp aws/env.aws.example .env
# edit: AISS_DRY_RUN=false
#       AISS_JUMPSERVER_URL=http://127.0.0.1:8080
#       AISS_JUMPSERVER_TOKEN=<service account token>
docker compose -f docker-compose.aiss.yml up -d
```

Create a JumpServer API user with **session terminate** permission.

---

## Optional later: Kinesis (multi-AZ / scale)

Publisher type `kinesis` exists in `apps/ai_security/`. Full CDK stack is
still roadmap (`ai-security-service/infra/`). For client POC, **HTTP webhook
on the same EC2** is enough and simpler to debug.

---

## Tear down

```bash
aws cloudformation delete-stack --stack-name cybervault-poc
```

---

## What to show the client

1. Architecture diagram (this README)  
2. Live SSH → dangerous command → dashboard alert in seconds  
3. Decision log (`dry-run` actions)  
4. Roadmap: Kinesis + S3 archive + IAM roles when they greenlight Phase 2  
