#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

MODE="${1:-both}"

if [[ -z "${ANTHROPIC_API_KEY:-}" && -z "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]]; then
  echo "[run_nanoclaw] Missing credentials: set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN."
  exit 2
fi

STARTED_STACK=0
if ! stack_is_healthy >/dev/null 2>&1; then
  bash "$ROOT/scripts/dev_up.sh"
  STARTED_STACK=1
fi

cleanup() {
  if [[ "$STARTED_STACK" == "1" ]]; then
    bash "$ROOT/scripts/dev_down.sh" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

if [[ ! -d "$ROOT/integrations/nanoclaw_runner/node_modules" ]]; then
  (cd "$ROOT/integrations/nanoclaw_runner" && npm install)
fi

node "$ROOT/integrations/nanoclaw_runner/mirage_demo.mjs" "$MODE"

