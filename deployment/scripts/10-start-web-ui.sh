#!/usr/bin/env bash
# Start CyberVault locally without Docker (API + static UI on one port).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/backend"

export AISS_HTTP_INGEST="${AISS_HTTP_INGEST:-true}"
export AISS_HTTP_INGEST_PORT="${AISS_HTTP_INGEST_PORT:-8090}"
export AISS_PUBLIC_URL="${AISS_PUBLIC_URL:-http://localhost:8090}"
export AISS_WEB_ROOT="${AISS_WEB_ROOT:-$ROOT/frontend}"
export AISS_DECISION_LOG_PATH="${AISS_DECISION_LOG_PATH:-$ROOT/data/exports/decisions.jsonl}"
export AISS_FEATURE_STORE_PATH="${AISS_FEATURE_STORE_PATH:-$ROOT/data/exports/feature_store.json}"
export AISS_BASELINES_PATH="${AISS_BASELINES_PATH:-$ROOT/data/exports/user_baselines.json}"
export AISS_USER_CONFIG_PATH="${AISS_USER_CONFIG_PATH:-$ROOT/data/exports/user_config.json}"
export AISS_USERS_PATH="${AISS_USERS_PATH:-$ROOT/data/exports/users.json}"
export AISS_SESSIONS_PATH="${AISS_SESSIONS_PATH:-$ROOT/data/exports/sessions.json}"
export AISS_INTEGRATION_STATE_PATH="${AISS_INTEGRATION_STATE_PATH:-$ROOT/data/exports/integration_state.json}"
export AISS_ML_MODEL_DIR="${AISS_ML_MODEL_DIR:-$ROOT/data/models}"
export AISS_ALLOW_SIGNUP="${AISS_ALLOW_SIGNUP:-true}"
export AISS_DRY_RUN="${AISS_DRY_RUN:-true}"

if [[ -f "$ROOT/.env" ]]; then
  # shellcheck disable=SC1091
  set -a
  source "$ROOT/.env"
  set +a
fi

mkdir -p "$ROOT/data/exports"
python3 -m aiss.consumer.main
