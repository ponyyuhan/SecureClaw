#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT"

if [[ "$(uname -s | tr '[:upper:]' '[:lower:]')" != "linux" ]]; then
  echo "[capsule-linux] not on Linux; skipping."
  exit 2
fi

BWRAP="$(command -v bwrap || true)"
if [[ -z "${BWRAP}" ]]; then
  echo "[capsule-linux] bwrap not found. Install bubblewrap."
  exit 2
fi

pick_port () {
  python - <<'PY'
import socket
s=socket.socket()
s.bind(("",0))
print(s.getsockname()[1])
s.close()
PY
}

wait_uds_ok () {
  local sock="$1"
  local tries="${2:-180}"
  python - <<PY
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
}
trap cleanup EXIT

python -m policy_server.build_dbs

P0_PORT="${P0_PORT:-$(pick_port)}"
P1_PORT="${P1_PORT:-$(pick_port)}"
EX_PORT="${EX_PORT:-$(pick_port)}"

export POLICY0_URL="http://127.0.0.1:${P0_PORT}"
export POLICY1_URL="http://127.0.0.1:${P1_PORT}"
export EXECUTOR_URL="http://127.0.0.1:${EX_PORT}"
export SIGNED_PIR="${SIGNED_PIR:-1}"
export DLP_MODE="${DLP_MODE:-dfa}"
export MIRAGE_HTTP_TOKEN="${MIRAGE_HTTP_TOKEN:-$(python -c 'import secrets; print(secrets.token_hex(16))')}"
export MIRAGE_SESSION_ID="${MIRAGE_SESSION_ID:-capsule-smoke-linux}"
export POLICY0_MAC_KEY="${POLICY0_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"
export POLICY1_MAC_KEY="${POLICY1_MAC_KEY:-$(python -c 'import secrets; print(secrets.token_hex(32))')}"

SERVER_ID=0 PORT="${P0_PORT}" POLICY_MAC_KEY="${POLICY0_MAC_KEY}" python -m policy_server.server &
P0=$!
SERVER_ID=1 PORT="${P1_PORT}" POLICY_MAC_KEY="${POLICY1_MAC_KEY}" python -m policy_server.server &
P1=$!
EXECUTOR_PORT="${EX_PORT}" POLICY0_MAC_KEY="${POLICY0_MAC_KEY}" POLICY1_MAC_KEY="${POLICY1_MAC_KEY}" python -m executor_server.server &
EX=$!

OUT_DIR="${OUT_DIR:-$ROOT/artifact_out}"
mkdir -p "$OUT_DIR"

CAPSULE_STATE="$OUT_DIR/capsule_state"
mkdir -p "$CAPSULE_STATE"
GW_SOCK="${GW_SOCK:-$CAPSULE_STATE/gateway.sock}"
export MIRAGE_HTTP_UDS="$GW_SOCK"

python -m gateway.http_server &
GW=$!
wait_uds_ok "$GW_SOCK" 180

EXFIL_PORT="${EXFIL_PORT:-$(pick_port)}"
python -m http.server "${EXFIL_PORT}" --bind 127.0.0.1 >/dev/null 2>&1 &
EXFIL=$!

echo "[capsule-linux] running bwrap smoke..."
REPO_IN="/repo"
OUT_IN="/out"
GW_SOCK_IN="$OUT_IN/$(python - <<PY
from pathlib import Path
print(str(Path("${GW_SOCK}").resolve().relative_to(Path("${OUT_DIR}").resolve())))
PY
)"

"$BWRAP" --unshare-net --die-with-parent \
  --ro-bind /usr /usr \
  --ro-bind /usr/local /usr/local \
  --ro-bind /bin /bin \
  --ro-bind /lib /lib \
  --ro-bind /etc /etc \
  --ro-bind /opt /opt \
  $( [[ -e /lib64 ]] && echo "--ro-bind /lib64 /lib64" ) \
  --proc /proc --dev /dev --tmpfs /tmp \
  --ro-bind "$ROOT" "$REPO_IN" \
  --bind "$OUT_DIR" "$OUT_IN" \
  --chdir "$REPO_IN" \
  --setenv PYTHONPATH "$REPO_IN" \
  --setenv MIRAGE_GATEWAY_UDS_PATH "$GW_SOCK_IN" \
  --setenv MIRAGE_HTTP_TOKEN "$MIRAGE_HTTP_TOKEN" \
  --setenv MIRAGE_SESSION_ID "$MIRAGE_SESSION_ID" \
  --setenv MIRAGE_EXFIL_URL "http://127.0.0.1:${EXFIL_PORT}/exfil" \
  --setenv MIRAGE_CAPSULE_SECRET_PATH "/home/host/.ssh/id_rsa" \
  --setenv MIRAGE_EXPECT_EXEC_BLOCK "0" \
  python -m capsule.smoke | tee "$OUT_DIR/capsule_smoke_linux.json"

echo "[capsule-linux] wrote: $OUT_DIR/capsule_smoke_linux.json"

echo "[capsule-linux] verifying capsule mediation contract..."
python -m capsule.verify_contract \
  --contract "$ROOT/spec/secureclaw_capsule_contract_v1.json" \
  --report "$OUT_DIR/capsule_smoke_linux.json" \
  --out "$OUT_DIR/capsule_contract_verdict_linux.json"
echo "[capsule-linux] wrote: $OUT_DIR/capsule_contract_verdict_linux.json"
