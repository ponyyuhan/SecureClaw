#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

stop_service gateway
stop_service executor
stop_service policy1
stop_service policy0

echo "SecureClaw local stack stopped."

