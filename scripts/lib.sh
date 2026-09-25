#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SECURECLAW_ROOT="$ROOT"
cd "$ROOT"

if [[ -n "${PYTHONPATH:-}" ]]; then
  export PYTHONPATH="$ROOT:$PYTHONPATH"
else
  export PYTHONPATH="$ROOT"
fi

export SECURECLAW_RUNTIME_DIR="${SECURECLAW_RUNTIME_DIR:-$ROOT/.runtime}"
export SECURECLAW_LOG_DIR="${SECURECLAW_LOG_DIR:-$SECURECLAW_RUNTIME_DIR/logs}"
export SECURECLAW_PID_DIR="${SECURECLAW_PID_DIR:-$SECURECLAW_RUNTIME_DIR/pids}"
mkdir -p "$SECURECLAW_RUNTIME_DIR" "$SECURECLAW_LOG_DIR" "$SECURECLAW_PID_DIR"

export P0_PORT="${P0_PORT:-9001}"
export P1_PORT="${P1_PORT:-9002}"
export EXECUTOR_PORT="${EXECUTOR_PORT:-9100}"
export MIRAGE_HTTP_PORT="${MIRAGE_HTTP_PORT:-8765}"
export MIRAGE_HTTP_BIND="${MIRAGE_HTTP_BIND:-127.0.0.1}"

export POLICY0_URL="${POLICY0_URL:-http://127.0.0.1:${P0_PORT}}"
export POLICY1_URL="${POLICY1_URL:-http://127.0.0.1:${P1_PORT}}"
export EXECUTOR_URL="${EXECUTOR_URL:-http://127.0.0.1:${EXECUTOR_PORT}}"

export POLICY0_MAC_KEY="${POLICY0_MAC_KEY:-1111111111111111111111111111111111111111111111111111111111111111}"
export POLICY1_MAC_KEY="${POLICY1_MAC_KEY:-2222222222222222222222222222222222222222222222222222222222222222}"

export FSS_DOMAIN_SIZE="${FSS_DOMAIN_SIZE:-4096}"
export MAX_TOKENS_PER_MESSAGE="${MAX_TOKENS_PER_MESSAGE:-32}"
export DLP_MODE="${DLP_MODE:-dfa}"
export SIGNED_PIR="${SIGNED_PIR:-1}"

export MIRAGE_HTTP_TOKEN="${MIRAGE_HTTP_TOKEN:-secureclaw-dev-token}"
export HANDLE_DB_PATH="${HANDLE_DB_PATH:-$SECURECLAW_RUNTIME_DIR/handles.sqlite3}"
export EXECUTOR_REPLAY_DB_PATH="${EXECUTOR_REPLAY_DB_PATH:-$SECURECLAW_RUNTIME_DIR/executor_replay.sqlite3}"
export LEAKAGE_BUDGET_DB_PATH="${LEAKAGE_BUDGET_DB_PATH:-$SECURECLAW_RUNTIME_DIR/leakage_budget.sqlite3}"
export AUDIT_LOG_PATH="${AUDIT_LOG_PATH:-$SECURECLAW_RUNTIME_DIR/audit.jsonl}"

pid_file() {
  local name="$1"
  echo "$SECURECLAW_PID_DIR/${name}.pid"
}

log_file() {
  local name="$1"
  echo "$SECURECLAW_LOG_DIR/${name}.log"
}

is_pid_live() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

is_service_running() {
  local name="$1"
  local pidf
  pidf="$(pid_file "$name")"
  if [[ ! -f "$pidf" ]]; then
    return 1
  fi
  local pid
  pid="$(cat "$pidf" 2>/dev/null || true)"
  if [[ -z "$pid" ]]; then
    return 1
  fi
  is_pid_live "$pid"
}

stop_service() {
  local name="$1"
  local pidf
  pidf="$(pid_file "$name")"
  if [[ ! -f "$pidf" ]]; then
    return 0
  fi
  local pid
  pid="$(cat "$pidf" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && is_pid_live "$pid"; then
    kill "$pid" >/dev/null 2>&1 || true
    sleep 0.2
    if is_pid_live "$pid"; then
      kill -9 "$pid" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$pidf"
}

wait_http_ok() {
  local url="$1"
  local tries="${2:-80}"
  python - <<PY
import sys
import time
import requests

url = "${url}"
tries = int("${tries}")
for _ in range(tries):
    try:
        r = requests.get(url, timeout=0.5)
        if r.status_code == 200:
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(0.25)
raise SystemExit(1)
PY
}

stack_is_healthy() {
  wait_http_ok "${POLICY0_URL}/health" 2 && \
  wait_http_ok "${POLICY1_URL}/health" 2 && \
  wait_http_ok "${EXECUTOR_URL}/health" 2 && \
  wait_http_ok "http://${MIRAGE_HTTP_BIND}:${MIRAGE_HTTP_PORT}/health" 2
}
