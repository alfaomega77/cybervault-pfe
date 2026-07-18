# CyberVault

**AI-powered Privileged Access Management (PAM) Risk Intelligence**

CyberVault analyses privileged sessions from JumpServer in near real time, scores risk with rules + UEBA + machine learning, and recommends actions (log, alert, lock, or kill) while keeping **dry-run** enabled by default.

---

## Features

- Real-time security event ingestion (HTTP webhook / Redis)
- Hybrid detection: deterministic rules, behavioural baselines (UEBA), ML ensemble
- Optional deep-learning sequence / GNN engines
- Multi-objective response selection (security vs disruption vs alert fatigue)
- Email-only administrator alerts (SMTP)
- Web dashboard: live decisions, historical log replay, JumpServer integration
- Docker Compose one-command deployment
- JumpServer Django plugin for event publishing

---

## Technology stack

| Layer | Stack |
|-------|--------|
| Backend | Python 3.12, Redis, scikit-learn, SHAP/LIME |
| Frontend | Static HTML/CSS/JS + nginx |
| Notifications | SMTP (email only) |
| Integration | JumpServer HTTP webhook / REST API |
| Deployment | Docker, Docker Compose |

---

## Architecture overview

```text
Admin SSH / RDP
      │
      ▼
 JumpServer  ──webhook──►  CyberVault backend (AI pipeline)
      ▲                         │
      │                         ├── decisions log
      └── lock / kill (opt.)    ├── email alerts
                                └── nginx UI (dashboard)
```

Default mode is **dry-run**: decisions are recorded and can trigger emails, but sessions are not terminated until you explicitly disable dry-run and configure JumpServer credentials.

---

## Folder structure

```text
.
├── backend/                 # AI service (API, pipeline, auth, alerts)
├── frontend/                # Web UI + nginx image
├── integrations/
│   └── jumpserver/          # Django plugin to publish PAM events
├── deployment/              # Deploy guides, scripts, AWS helpers
├── data/
│   ├── datasets/samples/    # Sample events for demos
│   ├── models/              # Trained model artefacts
│   ├── uploads/             # Local upload workspace
│   └── exports/             # Runtime state (gitignored)
├── documentation/           # Final Master's thesis + scientific article
├── docker-compose.yml       # One-command stack
├── .env.example
├── README.md
└── LICENSE                  # Apache 2.0
```

---

## Installation

### Prerequisites

- Docker Desktop 4.x+ (or Docker Engine + Compose plugin)
- 4 GB RAM available for containers
- Optional for local (non-Docker) runs: Python 3.11+

### Clone and configure

```bash
cd /path/to/cybervault
cp .env.example .env
# Edit .env — at least set AISS_WEBHOOK_TOKEN for production
```

---

## Running with Docker (recommended)

```bash
docker compose up --build --wait
```

Open **http://localhost:8090**

Create the first account (admin). Then explore:

- **Mon espace** — replay historical JSON/JSONL logs  
- **Mon PAM** — configure JumpServer + email alerts  
- **Temps réel** — live decision dashboard  

Health check:

```bash
curl http://localhost:8090/health
```

Stop:

```bash
docker compose down
```

Rebuild after code changes:

```bash
docker compose up --build --force-recreate
```

Full deployment details: [deployment/DEPLOYMENT.md](deployment/DEPLOYMENT.md)

---

## Running locally (without Docker)

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd ..
bash deployment/scripts/10-start-web-ui.sh
```

UI and API: **http://localhost:8090**

Smoke test:

```bash
bash deployment/scripts/11-test-live-event.sh
```

---

## Configuration

Copy `.env.example` to `.env` at the repository root. Compose loads these variables automatically.

### Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AISS_PUBLIC_URL` | Base URL in email links | `http://localhost:8090` |
| `AISS_WEBHOOK_TOKEN` | Bearer token for `POST /events` | demo token in Compose |
| `AISS_ALLOW_SIGNUP` | Allow new user registration | `true` |
| `AISS_DRY_RUN` | Do not call JumpServer lock/kill | `true` |
| `AISS_SMTP_*` | SMTP host/user/password/from | empty (outbox only) |
| `AISS_JUMPSERVER_URL` | JumpServer base URL | empty |
| `AISS_JUMPSERVER_TOKEN` | JumpServer API token | empty |
| `CYBERVAULT_PORT` | Host port for the UI | `8090` |
| `CYBERVAULT_BIND_ADDRESS` | Bind address | `127.0.0.1` |

---

## Backend setup

```bash
cd backend
pip install -r requirements.txt
# Optional deep learning extras:
# pip install -r requirements-deep-learning.txt
python -m unittest discover -s tests -v
```

Policy file: `backend/config/default_policy.yaml`

---

## Frontend setup

Static assets live in `frontend/`. No Node build step is required.

Docker image: nginx serves HTML/JS/CSS and reverse-proxies `/api` and `/events` to the backend.

---

## AI / ML models

Models under `data/models/` are loaded at runtime when present:

- Isolation Forest / Random Forest ensembles  
- Optional sequence LSTM and GNN weights (when deep-learning deps are installed)

If models are missing, the pipeline still runs rules + UEBA and reports `ml_not_trained` where applicable.

---

## Email notifications

1. Set `AISS_SMTP_HOST`, `AISS_SMTP_USER`, `AISS_SMTP_PASSWORD`, `AISS_SMTP_FROM` in `.env`
2. Restart Compose
3. In **Mon PAM**, set the admin email and click **Tester l'alerte**

Without SMTP, alerts are written to the local outbox under `data/exports/`.

SMS / Twilio support has been removed; email is the only channel.

---

## JumpServer integration

Plugin sources: `integrations/jumpserver/`

1. Deploy CyberVault and note the public webhook URL: `https://your-host/events`
2. Configure JumpServer with `AI_SECURITY_ENABLED`, webhook URL and token (see `deployment/jumpserver-ai-security.env.example`)
3. Copy or mount the plugin into JumpServer's `apps` and restart Core/Celery
4. Keep CyberVault in dry-run until you validate decisions

Helper scripts: `deployment/scripts/connect-jumpserver.sh`

---

## Documentation (academic)

| File | Description |
|------|-------------|
| `documentation/Memoire_Final.tex` | Master's thesis (final) |
| `documentation/Scientific_Article_Final.tex` | IEEE Access–style article (final) |
| `documentation/references.bib` | Bibliography for the article |

Compile the article with an IEEE Access / IEEEtran TeX environment. The thesis file is a single-file French edition.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `Cannot connect to the Docker daemon` | Start Docker Desktop |
| UI 502 / API unreachable | `docker compose ps` and `docker compose logs backend` |
| Signup rejected | Set `AISS_ALLOW_SIGNUP=true` |
| Webhook 401 | Match `AISS_WEBHOOK_TOKEN` and JumpServer token |
| No emails | Configure SMTP; check outbox in volume `cybervault-data` |
| Port already in use | Change `CYBERVAULT_PORT` in `.env` |

---

## Future improvements

- Multi-tenant isolation and role-based access control
- Durable database instead of JSON/JSONL stores
- Automated CI (tests + image publish)
- TLS termination and hardened public exposure
- Model training pipeline with versioned artefacts

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

JumpServer itself remains a separate upstream project (GPLv3). This repository focuses on CyberVault and the optional integration plugin.
