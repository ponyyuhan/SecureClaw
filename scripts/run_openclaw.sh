#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"
if ! command -v "$OPENCLAW_BIN" >/dev/null 2>&1; then
  echo "[run_openclaw] Could not find OpenClaw CLI: $OPENCLAW_BIN"
  echo "[run_openclaw] Install OpenClaw first, then rerun this script."
  exit 2
fi

MESSAGE="Use secureclaw_act exactly once with caller='openclaw' and intent_id='FetchResource' to fetch resource_id='https://api.github.com' with constraints={}. Then summarize the returned status and reason_code."
SESSION_ID="secureclaw-openclaw"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --message)
      MESSAGE="$2"
      shift 2
      ;;
    --session-id)
      SESSION_ID="$2"
      shift 2
      ;;
    *)
      echo "Usage: bash scripts/run_openclaw.sh [--message <text>] [--session-id <id>]"
      exit 2
      ;;
  esac
done

STARTED_STACK=0
if ! stack_is_healthy >/dev/null 2>&1; then
  bash "$ROOT/scripts/dev_up.sh"
  STARTED_STACK=1
fi

OC_PORT="${OPENCLAW_GATEWAY_PORT:-8787}"
OC_TOKEN="${OPENCLAW_GATEWAY_TOKEN:-secureclaw-openclaw-token}"
STATE_DIR="${OPENCLAW_STATE_DIR:-$SECURECLAW_RUNTIME_DIR/openclaw_state}"
CFG="${STATE_DIR}/openclaw.secureclaw.json"
PLUGIN_FILE="$ROOT/integrations/openclaw_plugin/mirage_ogpp.ts"
WORKSPACE_DIR="$ROOT/integrations/openclaw_workspace"
MODEL_PRIMARY="${OPENCLAW_MODEL_PRIMARY:-openai-codex/gpt-5.4}"
mkdir -p "$STATE_DIR"

cat >"$CFG" <<JSON
{
  "gateway": {
    "mode": "local",
    "port": $OC_PORT,
    "bind": "loopback",
    "auth": { "mode": "token", "token": "$OC_TOKEN" }
  },
  "plugins": {
    "enabled": true,
    "load": { "paths": ["$PLUGIN_FILE"] },
    "entries": {
      "mirage_ogpp": {
        "enabled": true,
        "config": {
          "gateway_http_url": "http://${MIRAGE_HTTP_BIND}:${MIRAGE_HTTP_PORT}",
          "http_token": "$MIRAGE_HTTP_TOKEN",
          "session_id": "$SESSION_ID"
        }
      }
    }
  },
  "tools": {
    "profile": "minimal",
    "alsoAllow": ["secureclaw_act", "mirage_act"]
  },
  "agents": {
    "defaults": {
      "workspace": "$WORKSPACE_DIR",
      "model": {
        "primary": "$MODEL_PRIMARY"
      }
    }
  }
}
JSON

OPENCLAW_LOG="$SECURECLAW_LOG_DIR/openclaw_gateway.log"
OPENCLAW_STATE_DIR="$STATE_DIR" OPENCLAW_CONFIG_PATH="$CFG" \
  "$OPENCLAW_BIN" gateway run --force --port "$OC_PORT" --bind loopback --auth token --token "$OC_TOKEN" \
  >"$OPENCLAW_LOG" 2>&1 &
OCGW=$!

wait_gateway() {
  local tries="${1:-80}"
  local i=0
  while [[ "$i" -lt "$tries" ]]; do
    if OPENCLAW_STATE_DIR="$STATE_DIR" OPENCLAW_CONFIG_PATH="$CFG" \
      "$OPENCLAW_BIN" gateway health --timeout 250 >/dev/null 2>&1; then
      return 0
    fi
    i=$((i+1))
    sleep 0.25
  done
  return 1
}

cleanup() {
  if [[ -n "${OCGW:-}" ]]; then
    kill "$OCGW" >/dev/null 2>&1 || true
  fi
  if [[ "$STARTED_STACK" == "1" ]]; then
    bash "$ROOT/scripts/dev_down.sh" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if ! wait_gateway 120; then
  echo "[run_openclaw] OpenClaw gateway did not become healthy."
  echo "[run_openclaw] Log: $OPENCLAW_LOG"
  exit 1
fi

echo "[run_openclaw] Using config: $CFG"
echo "[run_openclaw] If OpenClaw fails on model auth, authenticate it first in your normal OpenClaw install."
echo "[run_openclaw] Model: $MODEL_PRIMARY"

OPENCLAW_STATE_DIR="$STATE_DIR" OPENCLAW_CONFIG_PATH="$CFG" \
  "$OPENCLAW_BIN" agent --session-id "$SESSION_ID" --message "$MESSAGE" --json
