#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

wait_http_ok "${POLICY0_URL}/health" 4
wait_http_ok "${POLICY1_URL}/health" 4
wait_http_ok "${EXECUTOR_URL}/health" 4
wait_http_ok "http://${MIRAGE_HTTP_BIND}:${MIRAGE_HTTP_PORT}/health" 4

echo "OK  policy0  ${POLICY0_URL}"
echo "OK  policy1  ${POLICY1_URL}"
echo "OK  executor ${EXECUTOR_URL}"
echo "OK  gateway  http://${MIRAGE_HTTP_BIND}:${MIRAGE_HTTP_PORT}"

