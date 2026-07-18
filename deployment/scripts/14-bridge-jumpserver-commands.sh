#!/usr/bin/env bash
# Bridge: poll JumpServer commands → CyberVault /events (lab Mac).
# Usage: bash deployment/scripts/14-bridge-jumpserver-commands.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck disable=SC1091
[[ -f "$ROOT/.env" ]] && set -a && source "$ROOT/.env" && set +a

JS_TOKEN="${AISS_JUMPSERVER_TOKEN:?missing AISS_JUMPSERVER_TOKEN}"
WH_TOKEN="${AISS_WEBHOOK_TOKEN:?missing AISS_WEBHOOK_TOKEN}"
JS_URL="${JUMPSERVER_BRIDGE_URL:-http://127.0.0.1}"
CV_URL="${AISS_PUBLIC_URL:-http://127.0.0.1:8090}"
ORG="00000000-0000-0000-0000-000000000002"
SEEN_FILE="${TMPDIR:-/tmp}/cybervault-js-bridge-seen.txt"
touch "$SEEN_FILE"

echo "Bridge JumpServer → CyberVault"
echo "  JS: $JS_URL"
echo "  CV: $CV_URL"
echo "  Poll every 0.5s (Ctrl+C to stop)"
echo ""

export JS_TOKEN JS_URL CV_URL WH_TOKEN ORG SEEN_FILE

python3 - <<'PY'
import json, os, time, urllib.request, urllib.error

js_url = os.environ["JS_URL"].rstrip("/")
cv_url = os.environ["CV_URL"].rstrip("/")
js_token = os.environ["JS_TOKEN"]
wh_token = os.environ["WH_TOKEN"]
org = os.environ["ORG"]
seen_path = os.environ["SEEN_FILE"]

def js_get(path):
    req = urllib.request.Request(
        f"{js_url}{path}",
        headers={
            "Authorization": f"Token {js_token}",
            "X-JMS-ORG": org,
        },
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode())

def load_seen():
    try:
        with open(seen_path, encoding="utf-8") as fh:
            return {line.strip() for line in fh if line.strip()}
    except OSError:
        return set()

def save_seen(seen, new_ids):
    if not new_ids:
        return
    with open(seen_path, "a", encoding="utf-8") as fh:
        for cid in new_ids:
            fh.write(cid + "\n")
            seen.add(cid)

seen = load_seen()
print("ready", flush=True)

while True:
    loop_start = time.time()
    try:
        # Prefer unfinished sessions first (active kill path).
        sessions = js_get("/api/v1/terminal/sessions/?limit=15")
        results = sessions.get("results") or []
        open_ids = [s["id"] for s in results if not s.get("is_finished")]
        closed_ids = [s["id"] for s in results if s.get("is_finished")]
        session_ids = open_ids + closed_ids
        commands = []
        for sid in session_ids[:8]:
            try:
                data = js_get(f"/api/v1/terminal/commands/?session_id={sid}&limit=30&order=-timestamp")
                commands.extend(data.get("results") or [])
            except Exception as exc:
                print(f"! commands {sid[:8]}: {exc}", flush=True)
        new_ids = []
        for cmd in commands:
            cid = str(cmd.get("id") or "")
            if not cid or cid in seen:
                continue
            inp = (cmd.get("input") or "").strip()
            if not inp:
                continue
            event = {
                "event_id": f"js-cmd-{cid}",
                "event_type": "command.ingested",
                "session_id": cmd.get("session") or "",
                "user_id": cmd.get("user") or "",
                "account": cmd.get("account") or "",
                "asset_name": (cmd.get("asset") or "").split("(")[0],
                "remote_addr": cmd.get("remote_addr") or "",
                "protocol": "ssh",
                "payload": {"input": inp, "timestamp": cmd.get("timestamp")},
                "metadata": {"source": "jumpserver", "bridge": "14-bridge"},
            }
            req = urllib.request.Request(
                f"{cv_url}/events",
                data=json.dumps(event).encode(),
                headers={
                    "Authorization": f"Bearer {wh_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = json.loads(resp.read().decode())
                result = (body.get("results") or [{}])[0]
                print(
                    f"→ {inp[:60]!r} action={result.get('action')} status={result.get('status')}",
                    flush=True,
                )
                new_ids.append(cid)
            except Exception as exc:
                print(f"! post {inp[:40]!r}: {exc}", flush=True)
        save_seen(seen, new_ids)
    except Exception as exc:
        print(f"! loop: {exc}", flush=True)
    # Fast poll for near real-time lab demo (JumpServer itself may still buffer ~1s).
    elapsed = time.time() - loop_start
    time.sleep(max(0.2, 0.5 - elapsed))
PY
