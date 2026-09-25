#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

MODE="${1:-both}"
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

case "$MODE" in
  benign)
    python -m agent.nanoclaw_agent benign
    ;;
  malicious)
    python -m agent.nanoclaw_agent malicious
    ;;
  both)
    python -m agent.nanoclaw_agent benign
    python -m agent.nanoclaw_agent malicious
    ;;
  *)
    echo "Usage: bash scripts/run_agent_demo.sh [benign|malicious|both]"
    exit 2
    ;;
esac

