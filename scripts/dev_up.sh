#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

python -m policy_server.build_dbs >"$(log_file build_dbs)" 2>&1

if ! is_service_running policy0; then
  cd "$ROOT"
  nohup env \
    SERVER_ID=0 \
    PORT="$P0_PORT" \
    DATA_DIR="$ROOT/policy_server/data" \
    FSS_DOMAIN_SIZE="$FSS_DOMAIN_SIZE" \
    POLICY_MAC_KEY="$POLICY0_MAC_KEY" \
    python -m policy_server.server >"$(log_file policy0)" 2>&1 &
  echo $! >"$(pid_file policy0)"
fi

if ! is_service_running policy1; then
  cd "$ROOT"
  nohup env \
    SERVER_ID=1 \
    PORT="$P1_PORT" \
    DATA_DIR="$ROOT/policy_server/data" \
    FSS_DOMAIN_SIZE="$FSS_DOMAIN_SIZE" \
    POLICY_MAC_KEY="$POLICY1_MAC_KEY" \
    python -m policy_server.server >"$(log_file policy1)" 2>&1 &
  echo $! >"$(pid_file policy1)"
fi

if ! is_service_running executor; then
  cd "$ROOT"
  nohup env \
    EXECUTOR_PORT="$EXECUTOR_PORT" \
    POLICY0_MAC_KEY="$POLICY0_MAC_KEY" \
    POLICY1_MAC_KEY="$POLICY1_MAC_KEY" \
    EXECUTOR_REPLAY_DB_PATH="$EXECUTOR_REPLAY_DB_PATH" \
    python -m executor_server.server >"$(log_file executor)" 2>&1 &
  echo $! >"$(pid_file executor)"
fi

if ! is_service_running gateway; then
  cd "$ROOT"
  nohup env \
    POLICY0_URL="$POLICY0_URL" \
    POLICY1_URL="$POLICY1_URL" \
    EXECUTOR_URL="$EXECUTOR_URL" \
    FSS_DOMAIN_SIZE="$FSS_DOMAIN_SIZE" \
    MAX_TOKENS_PER_MESSAGE="$MAX_TOKENS_PER_MESSAGE" \
    MIRAGE_HTTP_PORT="$MIRAGE_HTTP_PORT" \
    MIRAGE_HTTP_BIND="$MIRAGE_HTTP_BIND" \
    MIRAGE_HTTP_TOKEN="$MIRAGE_HTTP_TOKEN" \
    HANDLE_DB_PATH="$HANDLE_DB_PATH" \
    LEAKAGE_BUDGET_DB_PATH="$LEAKAGE_BUDGET_DB_PATH" \
    AUDIT_LOG_PATH="$AUDIT_LOG_PATH" \
    python -m gateway.http_server >"$(log_file gateway)" 2>&1 &
  echo $! >"$(pid_file gateway)"
fi

wait_http_ok "${POLICY0_URL}/health" 80
wait_http_ok "${POLICY1_URL}/health" 80
wait_http_ok "${EXECUTOR_URL}/health" 80
wait_http_ok "http://${MIRAGE_HTTP_BIND}:${MIRAGE_HTTP_PORT}/health" 80

cat <<EOF
SecureClaw local stack is up.

policy0  : ${POLICY0_URL}
policy1  : ${POLICY1_URL}
executor : ${EXECUTOR_URL}
gateway  : http://${MIRAGE_HTTP_BIND}:${MIRAGE_HTTP_PORT}

Logs:
  $(log_file policy0)
  $(log_file policy1)
  $(log_file executor)
  $(log_file gateway)
EOF
