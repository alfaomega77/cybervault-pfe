# AI Agent — Ava (CyberVault)

Assistant in-app for **CyberVault product + engineering** (code, ML/AI pipeline, APIs).

## What Ava answers (no calculator focus)

- Product: dry-run, JumpServer, simulation, alerts…
- **Code / ML / AI of THIS app**: `EventProcessor`, Rules, UEBA, MLEngine, DL, MOO, train, APIs, frontend

## Modes

| Mode | Needs | Use |
|------|--------|-----|
| FAQ technique | nothing | corpus in `knowledge.json` (code + ML) |
| LLM (optional) | API key / Ollama | questions plus libres autour du code |

## Enable optional LLM

```bash
# .env
AISS_AGENT_LLM_URL=https://api.openai.com/v1/chat/completions
AISS_AGENT_LLM_API_KEY=sk-...
AISS_AGENT_LLM_MODEL=gpt-4o-mini
```

Or Ollama: see comments in `.env.example`.

## Layout

```text
frontend/ai-agent/
├── README.md
├── knowledge.json   ← product + architecture ML/code
├── agent.css
└── agent.js
```

Backend mirror: `backend/aiss/web/agent_knowledge.json` + `agent_chat.py`.
