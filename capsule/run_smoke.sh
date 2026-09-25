#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"

SB="$(command -v sandbox-exec || true)"
if [[ -z "${SB}" ]]; then
  echo "[capsule] sandbox-exec not found (macOS only)."
  exit 2
fi

CAPSULE_TRANSPORT="${CAPSULE_TRANSPORT:-uds}"  # uds (recommended) | http (legacy)

pick_port () {
  python - <<'PY'
import socket
s=socket.socket()
s.bind(("",0))
print(s.getsockname()[1])
s.close()
PY
}

wait_http_ok () {
  local url="$1"
  local tries="${2:-80}"
  python - <<PY
import time, sys
import requests
url="${url}"
tries=int("${tries}")
for _ in range(tries):
    try:
        r = requests.get(url, timeout=0.5)
        if r.status_code == 200:
            sys.exit(0)
    except Exception:
        pass
    time.sleep(0.1)
sys.exit(1)
PY
}

wait_uds_ok () {
  local sock="$1"
  local tries="${2:-120}"
  python - <<PY
import sys
from common.uds_http import wait_uds_http_ok
wait_uds_http_ok(uds_path="${sock}", path="/health", tries=int("${tries}"))
print("ok")
PY
}

cleanup () {
  if [[ -n "${GW:-}" ]]; then kill "$GW" 2>/dev/null || true; fi
  if [[ -n "${EX:-}" ]]; then kill "$EX" 2>/dev/null || true; fi
  if [[ -n "${P0:-}" ]]; then kill "$P0" 2>/dev/null || true; fi
  if [[ -n "${P1:-}" ]]; then kill "$P1" 2>/dev/null || true; fi
  if [[ -n "${EXFIL:-}" ]]; then kill "$EXFIL" 2>/dev/null || true; fi
  if [[ -n "${CAPSULE_SECRET_PATH:-}" ]]; then rm -f "$CAPSULE_SECRET_PATH" 2>/dev/null || true; fi
}
trap cleanup EXIT

python -m policy_server.build_dbs

P0_PORT="${P0_PORT:-$(pick_port)}"
P1_PORT="${P1_PORT:-$(pick_port)}"
EX_PORT="${EX_PORT:-$(pick_port)}"
GW_PORT="${GW_PORT:-$(pick_port)}"

export POLICY0_URL="http://127.0.0.1:${P0_PORT}"
export POLICY1_URL="http://127.0.0.1:${P1_PORT}"
export EXECUTOR_URL="http://127.0.0.1:${EX_PORT}"
export SIGNED_PIR="${SIGNED_PIR:-1}"
export DLP_MODE="${DLP_MODE:-dfa}"
export MIRAGE_HTTP_TOKEN="${MIRAGE_HTTP_TOKEN:-$(python -c 'import secrets; print(secrets.token_hex(16))')}"
export MIRAGE_SESSION_ID="${MIRAGE_SESSION_ID:-capsule-smoke}"
export POLICY0_MAC_KEY="${POLICY0_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"
export POLICY1_MAC_KEY="${POLICY1_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"

SERVER_ID=0 PORT="${P0_PORT}" POLICY_MAC_KEY="${POLICY0_MAC_KEY}" python -m policy_server.server &
P0=$!
SERVER_ID=1 PORT="${P1_PORT}" POLICY_MAC_KEY="${POLICY1_MAC_KEY}" python -m policy_server.server &
P1=$!
EXECUTOR_PORT="${EX_PORT}" POLICY0_MAC_KEY="${POLICY0_MAC_KEY}" POLICY1_MAC_KEY="${POLICY1_MAC_KEY}" python -m executor_server.server &
EX=$!

wait_http_ok "${POLICY0_URL}/health" 120
wait_http_ok "${POLICY1_URL}/health" 120
wait_http_ok "${EXECUTOR_URL}/health" 120

OUT_DIR="${OUT_DIR:-$ROOT/artifact_out}"
mkdir -p "$OUT_DIR"

CAPSULE_WORKSPACE="$OUT_DIR/capsule_workspace"
CAPSULE_STATE="$OUT_DIR/capsule_state"
mkdir -p "$CAPSULE_WORKSPACE" "$CAPSULE_STATE"

# Start a deterministic local "exfil server" on loopback. In legacy HTTP transport mode the capsule
# can reach localhost (so this would be a bypass); in UDS netless mode it must fail.
EXFIL_PORT="${EXFIL_PORT:-$(pick_port)}"
python -m http.server "${EXFIL_PORT}" --bind 127.0.0.1 >/dev/null 2>&1 &
EXFIL=$!
export MIRAGE_EXFIL_URL="http://127.0.0.1:${EXFIL_PORT}/exfil"

if [[ "${CAPSULE_TRANSPORT}" == "uds" ]]; then
  GW_SOCK="${GW_SOCK:-/tmp/mirage_ogpp_gateway.sock}"
  export MIRAGE_HTTP_UDS="$GW_SOCK"
  python -m gateway.http_server &
  GW=$!
  wait_uds_ok "$GW_SOCK" 180
  unset MIRAGE_GATEWAY_HTTP_URL || true
  export MIRAGE_GATEWAY_UDS_PATH="$GW_SOCK"
else
  export MIRAGE_HTTP_BIND="127.0.0.1"
  export MIRAGE_HTTP_PORT="${GW_PORT}"
  python -m gateway.http_server &
  GW=$!
  wait_http_ok "http://127.0.0.1:${GW_PORT}/health" 120
  export MIRAGE_GATEWAY_HTTP_URL="http://127.0.0.1:${GW_PORT}"
  unset MIRAGE_GATEWAY_UDS_PATH || true
fi

# Create a deterministic "host secret" outside the sandbox allowlist, so the smoke test
# proves we get a permission denial (not just FileNotFoundError).
CAPSULE_SECRET_PATH="${CAPSULE_SECRET_PATH:-$HOME/.mirage_capsule_secret_test_$(python -c 'import secrets; print(secrets.token_hex(4))')}"
echo "capsule-host-secret" > "$CAPSULE_SECRET_PATH"
chmod 600 "$CAPSULE_SECRET_PATH" 2>/dev/null || true
export MIRAGE_CAPSULE_SECRET_PATH="$CAPSULE_SECRET_PATH"

TMPDIR="${TMPDIR:-/tmp}"

PY_BIN="$(python -c 'import sys; print(sys.executable)')"
PY_REAL_BIN="$(python -c 'import os, sys; print(os.path.realpath(sys.executable))')"
PY_PREFIX="$(python -c 'import sys; print(sys.prefix)')"
PY_BASE_PREFIX="$(python -c 'import os, sys; print(os.path.realpath(sys.base_prefix))')"
NODE_BIN="$(command -v node || true)"
NODE_REAL_BIN="$(python - <<'PY' 2>/dev/null || true
import os, shutil
p = shutil.which("node")
print(os.path.realpath(p) if p else "")
PY
)"

echo "[capsule] running sandboxed smoke..."
"$SB" -f "$ROOT/capsule/capsule.sb" \
  -D "REPO_ROOT=$ROOT" \
  -D "CAPSULE_WORKSPACE=$CAPSULE_WORKSPACE" \
  -D "STATE_DIR=$CAPSULE_STATE" \
  -D "ALLOW_LOOPBACK_NET=$([[ \"${CAPSULE_TRANSPORT}\" == \"http\" ]] && echo 1 || echo 0)" \
  -D "PY_BIN=$PY_BIN" \
  -D "PY_REAL_BIN=$PY_REAL_BIN" \
  -D "PY_PREFIX=$PY_PREFIX" \
  -D "PY_BASE_PREFIX=$PY_BASE_PREFIX" \
  -D "NODE_BIN=$NODE_BIN" \
  -D "NODE_REAL_BIN=$NODE_REAL_BIN" \
  -D "TMPDIR=$TMPDIR" \
  "$PY_BIN" -m capsule.smoke | tee "$OUT_DIR/capsule_smoke.json"

echo "[capsule] wrote: $OUT_DIR/capsule_smoke.json"

echo "[capsule] verifying capsule mediation contract..."
python -m capsule.verify_contract \
  --contract "$ROOT/spec/secureclaw_capsule_contract_v1.json" \
  --report "$OUT_DIR/capsule_smoke.json" \
  --out "$OUT_DIR/capsule_contract_verdict.json"
echo "[capsule] wrote: $OUT_DIR/capsule_contract_verdict.json"
