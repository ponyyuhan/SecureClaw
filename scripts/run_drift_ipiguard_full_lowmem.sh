#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DRIFT_DIR="${REPO_ROOT}/third_party/DRIFT"
IPIGUARD_DIR="${REPO_ROOT}/third_party/ipiguard"
AGENTDOJO_OFFICIAL_SRC="${REPO_ROOT}/third_party/agentdojo/src"

RUN_TAG="${RUN_TAG:-$(date +%Y%m%d_%H%M%S)}"
BENCHMARK_VERSION="${BENCHMARK_VERSION:-v1.1.2}"
IPIGUARD_BENCHMARK_VERSION="${IPIGUARD_BENCHMARK_VERSION:-${BENCHMARK_VERSION}}"
ALLOW_BENCHMARK_VERSION_MISMATCH="${ALLOW_BENCHMARK_VERSION_MISMATCH:-0}"
MODEL="${MODEL:-gpt-4o-mini-2024-07-18}"
ATTACK_NAME="${ATTACK_NAME:-important_instructions}"
IPIGUARD_DEFENSE="${IPIGUARD_DEFENSE:-ipiguard}"
OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
OPENAI_API_KEY="${OPENAI_API_KEY:-}"
DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S:-300}"
DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES:-8}"
DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES:-6}"
DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S:-1.5}"
IPIGUARD_OPENAI_TIMEOUT_S="${IPIGUARD_OPENAI_TIMEOUT_S:-120}"
IPIGUARD_OPENAI_MAX_RETRIES="${IPIGUARD_OPENAI_MAX_RETRIES:-0}"
IPIGUARD_LLM_RETRY_ATTEMPTS="${IPIGUARD_LLM_RETRY_ATTEMPTS:-3}"
IPIGUARD_LLM_RETRY_MAX_WAIT_S="${IPIGUARD_LLM_RETRY_MAX_WAIT_S:-40}"
IPIGUARD_LLM_RETRY_BACKOFF_S="${IPIGUARD_LLM_RETRY_BACKOFF_S:-2}"
IPIGUARD_LLM_RETRY_HINT_SCALE="${IPIGUARD_LLM_RETRY_HINT_SCALE:-${IPIGUARD_LLM_RETRY_MULTIPLIER:-1.0}}"
IPIGUARD_LLM_RETRY_HINT_JITTER_S="${IPIGUARD_LLM_RETRY_HINT_JITTER_S:-0.5}"
IPIGUARD_MAX_RETRIES="${IPIGUARD_MAX_RETRIES:-${IPIGUARD_LLM_RETRY_ATTEMPTS}}"
IPIGUARD_RETRY_BACKOFF_S="${IPIGUARD_RETRY_BACKOFF_S:-${IPIGUARD_LLM_RETRY_BACKOFF_S}}"
IPIGUARD_RETRY_BACKOFF_MAX_S="${IPIGUARD_RETRY_BACKOFF_MAX_S:-${IPIGUARD_LLM_RETRY_MAX_WAIT_S}}"
IPIGUARD_RETRY_HINT_SCALE="${IPIGUARD_RETRY_HINT_SCALE:-${IPIGUARD_LLM_RETRY_HINT_SCALE}}"
IPIGUARD_RETRY_HINT_JITTER_S="${IPIGUARD_RETRY_HINT_JITTER_S:-${IPIGUARD_LLM_RETRY_HINT_JITTER_S}}"

OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifact_out_external_runtime/external_runs/${RUN_TAG}}"
OUT_ROOT="$(python - "${OUT_ROOT}" <<'PY'
import os
import sys
print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)"
LOG_DIR="${OUT_ROOT}/logs"
DRIFT_WORKSPACE="${DRIFT_WORKSPACE:-${OUT_ROOT}/drift_workspace}"
DRIFT_WORKSPACE="$(python - "${DRIFT_WORKSPACE}" <<'PY'
import os
import sys
print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)"
DRIFT_SUITES="${DRIFT_SUITES:-banking,slack,travel,workspace}"
DRIFT_MODES="${DRIFT_MODES:-benign,attack}"
RUN_DRIFT="${RUN_DRIFT:-1}"
RUN_IPIGUARD="${RUN_IPIGUARD:-1}"
QUOTA_FLAG="${QUOTA_FLAG:-${OUT_ROOT}/fatal_insufficient_quota.flag}"
mkdir -p "${LOG_DIR}"
mkdir -p "${DRIFT_WORKSPACE}"

if [[ "${BENCHMARK_VERSION}" != "${IPIGUARD_BENCHMARK_VERSION}" && "${ALLOW_BENCHMARK_VERSION_MISMATCH}" != "1" ]]; then
  echo "[error] benchmark version mismatch: DRIFT=${BENCHMARK_VERSION} IPIGuard=${IPIGUARD_BENCHMARK_VERSION}. Set ALLOW_BENCHMARK_VERSION_MISMATCH=1 to override."
  exit 1
fi
if [[ ("${RUN_DRIFT}" == "1" || "${RUN_IPIGUARD}" == "1") && -z "${OPENAI_API_KEY}" ]]; then
  echo "[error] OPENAI_API_KEY is required when running DRIFT/IPIGuard external baselines."
  exit 1
fi

_expected_rows() {
  local src_root="$1"
  local benchmark_version="$2"
  local mode="$3"
  local suite="$4"
  python - "${src_root}" "${benchmark_version}" "${mode}" "${suite}" <<'PY'
import sys
from pathlib import Path

src_root = Path(sys.argv[1])
benchmark_version = str(sys.argv[2])
mode = str(sys.argv[3])
suite_name = str(sys.argv[4])

if str(src_root) not in sys.path:
    sys.path.insert(0, str(src_root))

from agentdojo.task_suite.load_suites import get_suite  # type: ignore

suite = get_suite(benchmark_version, suite_name)
benign = int(len(suite.user_tasks))
under_attack = 0
if hasattr(suite, "get_injections_for_user_task"):
    for ut in suite.user_tasks.values():
        under_attack += int(len(suite.get_injections_for_user_task(ut)))
else:
    under_attack = benign * int(len(getattr(suite, "injection_tasks", {}) or {}))
print(under_attack if mode == "under_attack" else benign)
PY
}

run_drift_one() {
  local mode="$1"
  local suite="$2"
  local log_path="${LOG_DIR}/drift_${mode}_${suite}.log"

  echo "[run][DRIFT] mode=${mode} suite=${suite}"
  if [[ "${mode}" == "attack" ]]; then
    (
      cd "${DRIFT_WORKSPACE}"
      OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
      OPENAI_API_KEY="${OPENAI_API_KEY}" \
      DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S}" \
      DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES}" \
      DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES}" \
      DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S}" \
      PYTHONPATH="${DRIFT_DIR}:${REPO_ROOT}/third_party/agentdojo/src" \
      PYTHONUNBUFFERED=1 \
      python "${DRIFT_DIR}/pipeline_main.py" \
        --benchmark_version "${BENCHMARK_VERSION}" \
        --model "${MODEL}" \
        --suites "${suite}" \
        --do_attack \
        --attack_type "${ATTACK_NAME}" \
        --build_constraints \
        --injection_isolation \
        --dynamic_validation
    ) >"${log_path}" 2>&1
  else
    (
      cd "${DRIFT_WORKSPACE}"
      OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
      OPENAI_API_KEY="${OPENAI_API_KEY}" \
      DRIFT_OPENAI_TIMEOUT_S="${DRIFT_OPENAI_TIMEOUT_S}" \
      DRIFT_OPENAI_MAX_RETRIES="${DRIFT_OPENAI_MAX_RETRIES}" \
      DRIFT_CHAT_RETRIES="${DRIFT_CHAT_RETRIES}" \
      DRIFT_CHAT_RETRY_BACKOFF_S="${DRIFT_CHAT_RETRY_BACKOFF_S}" \
      PYTHONPATH="${DRIFT_DIR}:${REPO_ROOT}/third_party/agentdojo/src" \
      PYTHONUNBUFFERED=1 \
      python "${DRIFT_DIR}/pipeline_main.py" \
        --benchmark_version "${BENCHMARK_VERSION}" \
        --model "${MODEL}" \
        --suites "${suite}" \
        --build_constraints \
        --injection_isolation \
        --dynamic_validation
    ) >"${log_path}" 2>&1
  fi
  local expected_mode="benign"
  if [[ "${mode}" == "attack" ]]; then
    expected_mode="under_attack"
  fi
  local expected_rows="$(_expected_rows "${AGENTDOJO_OFFICIAL_SRC}" "${BENCHMARK_VERSION}" "${expected_mode}" "${suite}")"
  local drift_suite_root="${DRIFT_WORKSPACE}/runs/${MODEL}/${suite}"
  local got_rows=0
  if [[ "${mode}" == "attack" ]]; then
    got_rows="$(find "${drift_suite_root}" -type f -path "*/${ATTACK_NAME}/injection_task_*.json" 2>/dev/null | wc -l | tr -d ' ')"
  else
    got_rows="$(find "${drift_suite_root}" -type f -path "*/none/none.json" 2>/dev/null | wc -l | tr -d ' ')"
  fi
  if [[ "${expected_rows}" -gt 0 && "${got_rows}" -ne "${expected_rows}" ]]; then
    echo "[error][DRIFT] mode=${mode} suite=${suite} rows=${got_rows}/${expected_rows} (benchmark_version=${BENCHMARK_VERSION}) log=${log_path}"
    return 2
  fi
  echo "[done][DRIFT] mode=${mode} suite=${suite} rows=${got_rows}/${expected_rows} log=${log_path}"
}

_ipiguard_resume_info() {
  local mode="$1"
  local results_path="$2"
  if [[ ! -f "${results_path}" ]]; then
    # has_summary unique_task_rows next_uid next_iid max_user max_iid
    echo "0 0 0 0 -1 -1"
    return 0
  fi

  python - "$mode" "$results_path" <<'PY'
import json
import pathlib
import sys

mode = sys.argv[1]
path = pathlib.Path(sys.argv[2])
text = path.read_text(encoding="utf-8", errors="replace")
dec = json.JSONDecoder()
i = 0
n = len(text)
has_summary = False
seen = set()
max_user = -1
max_iid = -1

while i < n:
    while i < n and text[i].isspace():
        i += 1
    if i >= n:
        break
    try:
        obj, j = dec.raw_decode(text, i)
        i = j
    except json.JSONDecodeError:
        i += 1
        continue
    if not isinstance(obj, dict):
        continue
    if "Suite" in obj and "ASR" in obj:
        has_summary = True
    if mode == "under_attack":
        if "user_task_id" in obj and obj.get("injection_task_id") is not None:
            try:
                uid = int(obj.get("user_task_id", -1))
            except Exception:
                uid = -1
            try:
                iid = int(obj.get("injection_task_id", -1))
            except Exception:
                iid = -1
            seen.add((uid, iid))
            if uid > max_user or (uid == max_user and iid > max_iid):
                max_user = uid
                max_iid = iid
    else:
        if "user_task_id" in obj and ("injection_task_id" not in obj or obj.get("injection_task_id") is None):
            try:
                uid = int(obj.get("user_task_id", -1))
            except Exception:
                uid = -1
            seen.add((uid, None))
            if uid > max_user:
                max_user = uid

task_rows = len(seen)
next_uid = 0
next_iid = 0
if task_rows > 0:
    if mode == "under_attack":
        next_uid = max_user
        next_iid = max_iid + 1
    else:
        next_uid = max_user + 1
        next_iid = 0

print(f"{1 if has_summary else 0} {task_rows} {next_uid} {next_iid} {max_user} {max_iid}")
PY
}

run_ipiguard_one() {
  local mode="$1"
  local suite="$2"
  local out_dir="${OUT_ROOT}/ipiguard/${mode}/${suite}"
  local log_path="${LOG_DIR}/ipiguard_${mode}_${suite}.log"
  local results_path="${out_dir}/results.jsonl"
  local has_summary=0
  local existing_rows=0
  local resume_uid=0
  local resume_iid=0
  local resume_max_user=-1
  local resume_max_iid=-1
  local expected_rows=0

  mkdir -p "${out_dir}"
  expected_rows="$(_expected_rows "${IPIGUARD_DIR}/agentdojo/src" "${IPIGUARD_BENCHMARK_VERSION}" "${mode}" "${suite}")"
  read -r has_summary existing_rows resume_uid resume_iid resume_max_user resume_max_iid <<< "$(_ipiguard_resume_info "${mode}" "${results_path}")"
  if [[ "${has_summary}" == "1" && "${existing_rows}" -ge "${expected_rows}" && "${expected_rows}" -gt 0 ]]; then
    echo "[skip][IPIGuard] mode=${mode} suite=${suite} existing complete summary detected rows=${existing_rows}/${expected_rows}: ${results_path}"
    return 0
  fi

  if [[ "${existing_rows}" -gt 0 ]]; then
    echo "[resume][IPIGuard] mode=${mode} suite=${suite} existing_rows=${existing_rows}/${expected_rows} next_uid=${resume_uid} next_iid=${resume_iid} last_uid=${resume_max_user} last_iid=${resume_max_iid}"
  else
    echo "[run][IPIGuard] mode=${mode} suite=${suite} expected_rows=${expected_rows}"
  fi
  set +e
  (
    cd "${IPIGUARD_DIR}"
    PYTHONPATH="${IPIGUARD_DIR}:${IPIGUARD_DIR}/agentdojo/src:${PYTHONPATH:-}" \
    OPENAI_BASE_URL="${OPENAI_BASE_URL}" \
    OPENAI_API_KEY="${OPENAI_API_KEY}" \
      OPENAI_TIMEOUT_S="${IPIGUARD_OPENAI_TIMEOUT_S}" \
      IPIGUARD_OPENAI_TIMEOUT_S="${IPIGUARD_OPENAI_TIMEOUT_S}" \
      IPIGUARD_OPENAI_MAX_RETRIES="${IPIGUARD_OPENAI_MAX_RETRIES}" \
      IPIGUARD_MAX_RETRIES="${IPIGUARD_MAX_RETRIES}" \
      IPIGUARD_LLM_RETRY_ATTEMPTS="${IPIGUARD_LLM_RETRY_ATTEMPTS}" \
      IPIGUARD_LLM_RETRY_MAX_WAIT_S="${IPIGUARD_LLM_RETRY_MAX_WAIT_S}" \
      IPIGUARD_LLM_RETRY_BACKOFF_S="${IPIGUARD_LLM_RETRY_BACKOFF_S}" \
      IPIGUARD_LLM_RETRY_HINT_SCALE="${IPIGUARD_LLM_RETRY_HINT_SCALE}" \
      IPIGUARD_LLM_RETRY_HINT_JITTER_S="${IPIGUARD_LLM_RETRY_HINT_JITTER_S}" \
      IPIGUARD_RETRY_BACKOFF_S="${IPIGUARD_RETRY_BACKOFF_S}" \
      IPIGUARD_RETRY_BACKOFF_MAX_S="${IPIGUARD_RETRY_BACKOFF_MAX_S}" \
      IPIGUARD_RETRY_HINT_SCALE="${IPIGUARD_RETRY_HINT_SCALE}" \
      IPIGUARD_RETRY_HINT_JITTER_S="${IPIGUARD_RETRY_HINT_JITTER_S}" \
      PYTHONUNBUFFERED=1 \
      python run/eval.py \
      --benchmark_version "${IPIGUARD_BENCHMARK_VERSION}" \
      --suite_name "${suite}" \
      --agent_model "${MODEL}" \
      --attack_name "${ATTACK_NAME}" \
      --defense_name "${IPIGUARD_DEFENSE}" \
      --output_dir "${out_dir}" \
      --mode "${mode}" \
      --uid "${resume_uid}" \
      --iid "${resume_iid}"
  ) >"${log_path}" 2>&1
  local rc=$?
  set -e
  read -r has_summary existing_rows resume_uid resume_iid resume_max_user resume_max_iid <<< "$(_ipiguard_resume_info "${mode}" "${results_path}")"
  if grep -qi 'insufficient_quota' "${log_path}" 2>/dev/null; then
    mkdir -p "$(dirname "${QUOTA_FLAG}")"
    printf '%s\n' "[$(date '+%Y-%m-%d %H:%M:%S %Z')] insufficient_quota detected in ${log_path}" > "${QUOTA_FLAG}"
    echo "[fatal][IPIGuard] mode=${mode} suite=${suite} insufficient_quota detected; wrote ${QUOTA_FLAG}"
    return 86
  fi
  if [[ "${rc}" -ne 0 ]]; then
    if [[ "${existing_rows}" -gt 0 ]]; then
      echo "[warn][IPIGuard] mode=${mode} suite=${suite} rc=${rc} (partial unique task rows=${existing_rows}/${expected_rows}; restarting pass before next suite): ${results_path}"
      return "${rc}"
    fi
    echo "[error][IPIGuard] mode=${mode} suite=${suite} rc=${rc}; see log=${log_path}"
    return "${rc}"
  fi
  if [[ "${has_summary}" == "1" && "${existing_rows}" -ge "${expected_rows}" && "${expected_rows}" -gt 0 ]]; then
    echo "[done][IPIGuard] mode=${mode} suite=${suite} out=${out_dir} rows=${existing_rows}/${expected_rows}"
  elif [[ "${has_summary}" == "1" ]]; then
    echo "[warn][IPIGuard] mode=${mode} suite=${suite} summary present but incomplete rows=${existing_rows}/${expected_rows}: ${results_path}"
  else
    echo "[warn][IPIGuard] mode=${mode} suite=${suite} finished without suite summary (rows=${existing_rows}/${expected_rows}): ${results_path}"
  fi
}

main() {
  local suites=()
  local modes=()
  IFS=',' read -r -a suites <<< "${DRIFT_SUITES}"
  IFS=',' read -r -a modes <<< "${DRIFT_MODES}"

  echo "[start] run_tag=${RUN_TAG} out_root=${OUT_ROOT} drift_workspace=${DRIFT_WORKSPACE}"

  if [[ "${RUN_DRIFT}" == "1" ]]; then
    local mode
    local suite
    for mode in "${modes[@]}"; do
      mode="${mode//[[:space:]]/}"
      case "${mode}" in
        benign|attack) ;;
        *)
          echo "[error] Unsupported DRIFT mode: ${mode}. Expected benign or attack."
          exit 1
          ;;
      esac
      for suite in "${suites[@]}"; do
        suite="${suite//[[:space:]]/}"
        if [[ -z "${suite}" ]]; then
          continue
        fi
        run_drift_one "${mode}" "${suite}"
      done
    done
  else
    echo "[skip] DRIFT disabled (RUN_DRIFT=${RUN_DRIFT})"
  fi

  if [[ "${RUN_IPIGUARD}" == "1" ]]; then
    local suite
    for suite in "${suites[@]}"; do
      suite="${suite//[[:space:]]/}"
      if [[ -z "${suite}" ]]; then
        continue
      fi
      run_ipiguard_one benign "${suite}"
    done
    for suite in "${suites[@]}"; do
      suite="${suite//[[:space:]]/}"
      if [[ -z "${suite}" ]]; then
        continue
      fi
      run_ipiguard_one under_attack "${suite}"
    done
  else
    echo "[skip] IPIGuard disabled (RUN_IPIGUARD=${RUN_IPIGUARD})"
  fi

  echo "[all-done] out_root=${OUT_ROOT}"
}

main "$@"
