#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
cd "$ROOT"

# Desktop MCP clients do not inherit an activated shell's virtual environment.
if [[ -n "${SECURECLAW_PYTHON:-}" ]]; then
  PYTHON_BIN="$SECURECLAW_PYTHON"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON_BIN="$ROOT/.venv/bin/python"
else
  PYTHON_BIN=python
fi
exec "$PYTHON_BIN" -m gateway.mcp_server
