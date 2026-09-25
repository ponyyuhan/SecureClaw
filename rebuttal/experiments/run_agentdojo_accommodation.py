#!/usr/bin/env python3
"""Run the four AgentDojo accommodation counterfactuals with row-level evidence.

This runner keeps the submitted AgentDojo-v1.1.2 task enumeration, model
snapshot, temperature, attack, SecureClaw infrastructure, policy, and scorer.
Only these two executor switches change:

* alias resolution (on/off);
* policy-safe auto-confirmation (on/off).

The result stream is append-only and resumable.  ``--dry-run`` validates and
freezes the complete plan without starting infrastructure or making model
requests.  ``--analyze-only`` rebuilds transitions and summaries from existing
rows without making model requests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
IPIGUARD_ROOT = REPO_ROOT / "third_party" / "ipiguard"
AGENTDOJO_SRC = IPIGUARD_ROOT / "agentdojo" / "src"
for _path in (REPO_ROOT, IPIGUARD_ROOT, AGENTDOJO_SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from rebuttal.experiments.agentdojo_accommodation_core import (  # noqa: E402
    CONDITIONS,
    CONDITION_SWITCHES,
    EXPECTED_COUNTS,
    LANES,
    SUITES,
    Case,
    alias_tokens,
    assert_finite_numbers,
    build_transitions,
    enumerate_submitted_cases,
    event_summary,
    latest_rows,
    stable_json_digest,
    summarize_rows,
)


SCHEMA_VERSION = 1
DEFAULT_MODEL = "openai/gpt-4o-mini-2024-07-18"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_OUT = REPO_ROOT / "rebuttal" / "results" / "agentdojo_accommodation"
DEFAULT_SUBMITTED_REFERENCE = (
    REPO_ROOT
    / "artifact_out_external_runtime"
    / "external_runs"
    / "20260313_secureclaw_benign_gate_live_20260313_190327"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_value(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): _jsonable(nested) for key, nested in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(nested) for nested in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _jsonable(model_dump())
    return str(value)


def _atomic_json(path: Path, value: Any) -> None:
    assert_finite_numbers(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _append_jsonl(path: Path, value: dict[str, Any]) -> None:
    assert_finite_numbers(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                value,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        handle.flush()
        os.fsync(handle.fileno())


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL {path}:{line_number}: {exc}") from exc
            if isinstance(value, dict):
                rows.append(value)
    return rows


def _load_json_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return value


def _api_keys() -> list[str]:
    values: list[str] = []
    combined = str(os.getenv("OPENROUTER_API_KEYS") or "")
    for item in combined.replace("\n", ",").split(","):
        if item.strip():
            values.append(item.strip())
    for name in ("OPENROUTER_API_KEY", "OPENAI_API_KEY"):
        value = str(os.getenv(name) or "").strip()
        if value:
            values.append(value)
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


@contextmanager
def _environment(patch: dict[str, str]):
    old = {name: os.environ.get(name) for name in patch}
    try:
        os.environ.update({name: str(value) for name, value in patch.items()})
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _condition_env(condition: str) -> dict[str, str]:
    switches = CONDITION_SWITCHES[condition]
    return {
        "SECURECLAW_DISABLE_ALIAS_RESOLUTION": (
            "0" if switches["alias_resolution"] else "1"
        ),
        "SECURECLAW_AUTO_USER_CONFIRM": (
            "1" if switches["auto_confirm"] else "0"
        ),
        # Freeze the submitted settings explicitly rather than inheriting a
        # shell used for another experiment.
        "SECURECLAW_TASK_CAPSULE": "0",
        "SECURECLAW_HANDLEIZE_READ_OUTPUT": "1",
        "SECURECLAW_READ_OUTPUT_MODE": "sanitized_summary",
        "SECURECLAW_READ_SUMMARY_MAX_ITEMS": "8",
        "SECURECLAW_READ_SUMMARY_MAX_CHARS": "512",
        "SECURECLAW_MAX_TOOL_ITERS": "35",
        "SECURECLAW_ACCOMMODATION_AUDIT_PREFLIGHT": "1",
    }


def _validate_runtime_cases(cases: list[Case], benchmark_version: str) -> None:
    from agentdojo.task_suite.load_suites import get_suite

    by_suite: dict[str, list[Case]] = {}
    for case in cases:
        by_suite.setdefault(case.suite, []).append(case)
    for suite_name, suite_cases in by_suite.items():
        suite = get_suite(benchmark_version, suite_name)
        user_ids = set(suite.user_tasks)
        injection_ids = set(suite.injection_tasks)
        missing_users = sorted(
            {case.user_task_id for case in suite_cases} - user_ids
        )
        missing_injections = sorted(
            {
                str(case.injection_task_id)
                for case in suite_cases
                if case.injection_task_id is not None
            }
            - injection_ids
        )
        if missing_users or missing_injections:
            raise RuntimeError(
                f"{suite_name} dataset mismatch: "
                f"missing_users={missing_users}, missing_injections={missing_injections}"
            )


def _make_instrumented_executor_class():
    """Return a semantics-preserving SecureClaw executor with an event ledger."""

    import requests
    from agentdojo.agent_pipeline.tool_execution import SecureClawToolsExecutor

    class InstrumentedSecureClawToolsExecutor(SecureClawToolsExecutor):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._accommodation_ledger: dict[str, list[dict[str, Any]]] = {
                "alias_registrations": [],
                "alias_arguments": [],
                "policy_requests": [],
            }

        def _ensure_turn(self, query, messages, extra_args):
            previous = str(getattr(self, "_turn_id", "") or "")
            super()._ensure_turn(query, messages, extra_args)
            current = str(getattr(self, "_turn_id", "") or "")
            if current != previous:
                self._accommodation_ledger = {
                    "alias_registrations": [],
                    "alias_arguments": [],
                    "policy_requests": [],
                }

        def _register_alias(
            self,
            token_type: str,
            value: str,
            *,
            display_override: str | None = None,
        ) -> str:
            existed = str(value or "") in self._real_to_alias
            token = super()._register_alias(
                token_type,
                value,
                display_override=display_override,
            )
            if token and not existed:
                self._accommodation_ledger["alias_registrations"].append(
                    {
                        "token": str(token),
                        "target_type": str(token_type),
                        "target_sha256": hashlib.sha256(
                            str(value or "").encode("utf-8")
                        ).hexdigest(),
                    }
                )
            return token

        def _record_alias_arguments(self, messages) -> None:
            if not messages or messages[-1].get("role") != "assistant":
                return
            tool_calls = messages[-1].get("tool_calls") or []
            folded_map = {
                str(alias).casefold(): str(raw)
                for alias, raw in self._alias_to_real.items()
            }
            for tool_call in tool_calls:
                function = str(
                    getattr(tool_call, "function", None)
                    or (
                        tool_call.get("function")
                        if isinstance(tool_call, dict)
                        else ""
                    )
                    or ""
                )
                args = getattr(tool_call, "args", None)
                if args is None and isinstance(tool_call, dict):
                    args = tool_call.get("args")
                serialized = json.dumps(
                    _jsonable(args or {}),
                    ensure_ascii=False,
                    sort_keys=True,
                )
                for token in alias_tokens(serialized):
                    raw = folded_map.get(token.casefold())
                    occurrences = len(
                        list(
                            re.finditer(
                                rf"\b{re.escape(token)}\b",
                                serialized,
                                flags=re.IGNORECASE,
                            )
                        )
                    )
                    self._accommodation_ledger["alias_arguments"].append(
                        {
                            "tool": function,
                            "token": token,
                            "occurrences": max(1, occurrences),
                            "known_alias": raw is not None,
                            "resolved": bool(
                                self._alias_resolution_enabled and raw is not None
                            ),
                            "target_sha256": (
                                hashlib.sha256(raw.encode("utf-8")).hexdigest()
                                if raw is not None
                                else None
                            ),
                        }
                    )

        def _policy_preflight(self, payload: dict[str, Any]) -> dict[str, Any]:
            mapping = {
                "SendMessage": "CheckMessagePolicy",
                "FetchResource": "CheckFetchPolicy",
                "PostWebhook": "CheckWebhookPolicy",
            }
            check_intent = mapping.get(str(payload.get("intent_id") or ""))
            if not check_intent:
                return {}
            check_payload = {
                "intent_id": check_intent,
                "inputs": dict(payload.get("inputs") or {}),
                "constraints": {
                    **dict(payload.get("constraints") or {}),
                    "user_confirm": False,
                },
                "caller": str(payload.get("caller") or ""),
            }
            headers = {"X-Mirage-Session": self._session_id}
            response = requests.post(
                f"{self._base_url}/act",
                json=check_payload,
                headers=headers,
                timeout=self._timeout_s,
            )
            response.raise_for_status()
            value = response.json()
            return value if isinstance(value, dict) else {}

        def _submit_act(self, payload: dict) -> dict:
            confirm_flag = bool(
                (payload.get("constraints") or {}).get("user_confirm", False)
            )
            preflight: dict[str, Any] = {}
            preflight_error = ""
            if bool(
                int(
                    os.getenv(
                        "SECURECLAW_ACCOMMODATION_AUDIT_PREFLIGHT", "1"
                    )
                    or "1"
                )
            ):
                try:
                    preflight = self._policy_preflight(payload)
                except Exception as exc:  # instrumentation must not change outcome
                    preflight_error = f"{type(exc).__name__}: {exc}"

            event: dict[str, Any] = {
                "intent_id": str(payload.get("intent_id") or ""),
                "request_digest": stable_json_digest(payload),
                "auto_confirmation_flag": confirm_flag,
                "preflight_status": str(preflight.get("status") or ""),
                "preflight_reason": str(preflight.get("reason_code") or ""),
                "preflight_error": preflight_error,
            }
            required = event["preflight_reason"] == "REQUIRE_CONFIRM"
            preflight_allowed = (
                event["preflight_status"].upper() == "OK" or required
            )
            event["confirmation_required"] = required
            event["auto_confirmation_issued"] = bool(required and confirm_flag)
            event["policy_allowed"] = bool(preflight_allowed)
            preflight_data = (
                preflight.get("data")
                if isinstance(preflight.get("data"), dict)
                else {}
            )
            denied_tokens = int(
                bool(
                    not preflight_allowed
                    and str(preflight_data.get("confirm_token") or "")
                )
            )
            event["denied_auto_confirm_tokens"] = denied_tokens
            event["denied_auto_confirm_bug"] = bool(denied_tokens)
            try:
                result = super()._submit_act(payload)
            except Exception as exc:
                event.update(
                    {
                        "actual_status": "ERROR",
                        "actual_reason": f"{type(exc).__name__}: {exc}",
                        "denied_action_executed": False,
                    }
                )
                self._accommodation_ledger["policy_requests"].append(event)
                raise
            event.update(
                {
                    "actual_status": str(result.get("status") or ""),
                    "actual_reason": str(result.get("reason_code") or ""),
                    "denied_action_executed": False,
                }
            )
            if not preflight:
                event["policy_allowed"] = (
                    event["actual_status"].upper() == "OK"
                )
            self._accommodation_ledger["policy_requests"].append(event)
            return result

        def query(self, query, runtime, env=None, messages=(), extra_args=None):
            if extra_args is None:
                extra_args = {}
            # Ensure the per-task ledger is reset before inspecting the first
            # assistant tool call.  The superclass repeats this idempotently.
            self._ensure_turn(query, messages, extra_args)
            self._record_alias_arguments(messages)
            result = super().query(
                query,
                runtime,
                env=env,
                messages=messages,
                extra_args=extra_args,
            )
            out_args = result[-1]
            out_args["secureclaw_accommodation_events"] = _jsonable(
                self._accommodation_ledger
            )
            return result

    return InstrumentedSecureClawToolsExecutor


def _build_pipeline(
    *,
    model: str,
    base_url: str,
    api_keys: list[str],
    seed: int,
    timeout_s: float,
    retries: int,
    max_tool_iters: int,
):
    import openai
    from openai._types import NOT_GIVEN
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.llms import openai_llm as llm_module
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
    from agentdojo.functions_runtime import EmptyEnv

    InstrumentedExecutor = _make_instrumented_executor_class()

    class SeededOpenRouterLLM:
        name = model

        def __init__(self):
            self.model = model
            self.seed = int(seed)
            self.clients = [
                openai.OpenAI(
                    api_key=key,
                    base_url=base_url,
                    timeout=float(timeout_s),
                    max_retries=0,
                )
                for key in api_keys
            ]
            self.next_client = 0

        def query(
            self,
            query,
            runtime,
            env=EmptyEnv(),
            messages=(),
            extra_args=None,
        ):
            if extra_args is None:
                extra_args = {}
            openai_messages = [
                llm_module._message_to_openai(message) for message in messages
            ]
            openai_tools = [
                llm_module._function_to_openai(tool)
                for tool in runtime.functions.values()
            ]
            attempts = max(1, int(retries) + 1)
            completion = None
            errors: list[str] = []
            started = time.perf_counter()
            for attempt in range(attempts):
                client_index = (self.next_client + attempt) % len(self.clients)
                client = self.clients[client_index]
                try:
                    completion = client.chat.completions.create(
                        model=self.model,
                        messages=openai_messages,
                        tools=openai_tools or NOT_GIVEN,
                        tool_choice="auto" if openai_tools else NOT_GIVEN,
                        temperature=0.0,
                        seed=self.seed,
                    )
                    self.next_client = (client_index + 1) % len(self.clients)
                    break
                except (
                    openai.APIConnectionError,
                    openai.APITimeoutError,
                    openai.InternalServerError,
                    openai.RateLimitError,
                ) as exc:
                    errors.append(f"{type(exc).__name__}: {str(exc)[:240]}")
                    if attempt + 1 >= attempts:
                        raise
                    time.sleep(min(10.0, 1.5 * (2**attempt)))
            if completion is None:
                raise RuntimeError("provider returned no completion")

            usage = getattr(completion, "usage", None)
            prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
            completion_tokens = int(
                getattr(usage, "completion_tokens", 0) or 0
            )
            extra_args["input_tokens"] = int(
                extra_args.get("input_tokens") or 0
            ) + prompt_tokens
            extra_args["output_tokens"] = int(
                extra_args.get("output_tokens") or 0
            ) + completion_tokens
            request_record = {
                "response_id": str(getattr(completion, "id", "") or ""),
                "request_id": str(
                    getattr(completion, "_request_id", "") or ""
                ),
                "requested_model": self.model,
                "returned_model": str(getattr(completion, "model", "") or ""),
                "seed": self.seed,
                "temperature": 0.0,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "latency_s": time.perf_counter() - started,
                "transport_retries": len(errors),
                "retry_errors": errors,
            }
            cost = getattr(usage, "cost", None)
            if isinstance(cost, (int, float)):
                request_record["cost_usd"] = float(cost)
            extra_args.setdefault("provider_requests", []).append(request_record)
            output = llm_module._openai_to_assistant_message(
                completion.choices[0].message
            )
            return query, runtime, env, [*messages, output], extra_args

    llm = SeededOpenRouterLLM()
    executor = InstrumentedExecutor()
    pipeline = AgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            llm,
            ToolsExecutionLoop(
                [executor, llm],
                max_iters=max(5, int(max_tool_iters)),
            ),
        ]
    )
    pipeline.name = f"{model}-secureclaw-accommodation"
    return pipeline


def _trace_path(out_dir: Path, condition: str, case: Case, seed: int) -> Path:
    injection = case.injection_task_id or "none"
    return (
        out_dir
        / "traces"
        / condition
        / case.suite
        / case.lane
        / f"{case.user_task_id}__{injection}__seed{seed}.json"
    )


def _run_case(
    *,
    condition: str,
    case: Case,
    suite: Any,
    attacker: Any,
    pipeline: Any,
    model: str,
    seed: int,
    out_dir: Path,
) -> dict[str, Any]:
    started_wall = _utc_now()
    started = time.perf_counter()
    user_task = suite.get_user_task_by_id(case.user_task_id)
    messages: Any = []
    extra_args: dict[str, Any] = {"input_tokens": 0, "output_tokens": 0}
    utility = False
    raw_security = True if case.lane == "benign" else False
    error: str | None = None
    try:
        if case.lane == "attacked":
            assert case.injection_task_id is not None
            injection_task = suite.get_injection_task_by_id(
                case.injection_task_id
            )
            injections = attacker.attack(user_task, injection_task)
            utility, raw_security, messages, extra_args = (
                suite.run_task_with_pipeline_msg(
                    pipeline,
                    user_task,
                    injection_task,
                    injections,
                    extra_args=extra_args,
                )
            )
        else:
            utility, raw_security, messages, extra_args = (
                suite.run_task_with_pipeline_msg(
                    pipeline,
                    user_task,
                    injection_task=None,
                    injections={},
                    extra_args=extra_args,
                )
            )
    except Exception as exc:  # semantic failures are retained, not retried
        error = f"{type(exc).__name__}: {exc}"

    provider_requests = [
        item
        for item in extra_args.get("provider_requests", [])
        if isinstance(item, dict)
    ]
    if error is None:
        if not provider_requests:
            error = "ProviderAuditError: no provider request metadata recorded"
        else:
            bad_requests = [
                item
                for item in provider_requests
                if (
                    not str(item.get("response_id") or "")
                    or str(item.get("requested_model") or "") != model
                    or str(item.get("returned_model") or "") != model
                )
            ]
            if bad_requests:
                error = (
                    "ProviderAuditError: missing response id or exact "
                    "requested/returned model mismatch"
                )

    ledger = extra_args.get("secureclaw_accommodation_events")
    evidence = event_summary(ledger if isinstance(ledger, dict) else {})
    attack_success = bool(raw_security) if case.lane == "attacked" else False
    trace_path = _trace_path(out_dir, condition, case, seed)
    trace = {
        "schema_version": SCHEMA_VERSION,
        "benchmark": "AgentDojo",
        "suite": case.suite,
        "lane": case.lane,
        "condition": condition,
        "row_id": case.row_id,
        "seed": seed,
        "messages": _jsonable(messages),
        "executor_events": _jsonable(ledger or {}),
        "provider_requests": _jsonable(
            extra_args.get("provider_requests") or []
        ),
    }
    _atomic_json(trace_path, trace)

    row: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "experiment": "accommodation",
        "benchmark": "AgentDojo",
        "benchmark_version": "v1.1.2",
        "suite": case.suite,
        "lane": case.lane,
        "kind": "attack" if case.lane == "attacked" else "benign",
        "condition": condition,
        "config_id": condition,
        "row_id": case.row_id,
        "user_task_id": case.user_task_id,
        "injection_task_id": case.injection_task_id,
        "model": model,
        "seed": seed,
        "temperature": 0.0,
        "status": "ok" if error is None else "error",
        "error": error,
        "utility": bool(utility),
        "utility_success": bool(utility),
        # AgentDojo-v1.1.2's injection-task evaluator returns True when the
        # injection goal succeeds; this is an undesirable ASR event.
        "security": bool(raw_security),
        "attack_success": attack_success,
        "security_violation": attack_success,
        "input_tokens": int(extra_args.get("input_tokens") or 0),
        "output_tokens": int(extra_args.get("output_tokens") or 0),
        "provider_requests": len(provider_requests),
        "provider_request_ids": [
            str(item.get("response_id") or item.get("request_id") or "")
            for item in provider_requests
            if str(item.get("response_id") or item.get("request_id") or "")
        ],
        "cost_usd": sum(
            float(item.get("cost_usd") or 0.0) for item in provider_requests
        ),
        "latency_s": time.perf_counter() - started,
        "started_at": started_wall,
        "completed_at": _utc_now(),
        "trace_path": str(trace_path.relative_to(out_dir)),
        "trace_sha256": _sha256_file(trace_path),
        **{
            key: value
            for key, value in evidence.items()
            if key not in {"alias", "confirmation"}
        },
        "alias": evidence["alias"],
        "confirmation": evidence["confirmation"],
    }
    return row


def _write_analysis(out_dir: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = _load_jsonl(out_dir / "rows.jsonl")
    transitions = build_transitions(rows)
    summary = summarize_rows(rows, transitions)
    _atomic_json(out_dir / "transitions.json", {"rows": transitions})
    transition_path = out_dir / "transitions.jsonl"
    temporary = transition_path.with_suffix(".jsonl.tmp")
    temporary.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("w", encoding="utf-8") as handle:
        for transition in transitions:
            handle.write(
                json.dumps(
                    transition,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )
    temporary.replace(transition_path)
    _atomic_json(out_dir / "summary.json", summary)
    return transitions, summary


def _selection_from_args(args: argparse.Namespace) -> list[Case]:
    suites = [value.strip() for value in args.suites.split(",") if value.strip()]
    lanes = [value.strip() for value in args.lanes.split(",") if value.strip()]
    cases = enumerate_submitted_cases(suites=suites, lanes=lanes)
    if args.row_ids_file:
        requested = {
            line.strip()
            for line in Path(args.row_ids_file).read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        known = {case.row_id for case in cases}
        unknown = sorted(requested - known)
        if unknown:
            raise ValueError(f"unknown row IDs: {unknown[:20]}")
        cases = [case for case in cases if case.row_id in requested]
    if args.max_rows:
        cases = cases[: int(args.max_rows)]
    return cases


def _selection_document(cases: list[Case]) -> dict[str, Any]:
    return {
        "cases": [
            {
                "suite": case.suite,
                "lane": case.lane,
                "row_id": case.row_id,
                "user_task_id": case.user_task_id,
                "injection_task_id": case.injection_task_id,
            }
            for case in cases
        ]
    }


def _resume_contract(
    *,
    selection: dict[str, Any],
    config: dict[str, Any],
    source_hashes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source_digest_input = {
        name: details.get("sha256")
        for name, details in sorted(source_hashes.items())
    }
    components = {
        "version": 1,
        "selection_sha256": stable_json_digest(selection),
        "config_sha256": stable_json_digest(config),
        "source_sha256": stable_json_digest(source_digest_input),
    }
    return {
        **components,
        "sha256": stable_json_digest(components),
    }


def _assert_resume_compatible(
    *,
    out_dir: Path,
    proposed_manifest: dict[str, Any],
    existing_rows: list[dict[str, Any]],
) -> None:
    """Reject reuse unless manifest, selection, sources, config, and rows agree."""

    previous_manifest_path = out_dir / "run_manifest.json"
    previous_selection_path = out_dir / "selection.json"
    rows_path = out_dir / "rows.jsonl"
    if not (
        previous_manifest_path.exists()
        or previous_selection_path.exists()
        or rows_path.exists()
    ):
        return

    mismatches: list[str] = []
    previous_manifest = _load_json_object(previous_manifest_path)
    previous_contract = (
        previous_manifest.get("resume_contract")
        if isinstance(previous_manifest, dict)
        else None
    )
    proposed_contract = proposed_manifest.get("resume_contract")
    if not isinstance(previous_contract, dict):
        mismatches.append("previous resume contract missing")
    if not isinstance(proposed_contract, dict):
        mismatches.append("proposed resume contract missing")

    if isinstance(previous_contract, dict):
        previous_components = {
            key: previous_contract.get(key)
            for key in (
                "version",
                "selection_sha256",
                "config_sha256",
                "source_sha256",
            )
        }
        if previous_contract.get("sha256") != stable_json_digest(
            previous_components
        ):
            mismatches.append("previous resume contract is corrupt")
        previous_selection = previous_manifest.get("selection")
        previous_config = previous_manifest.get("resume_config")
        previous_sources = previous_manifest.get("source_hashes")
        if not (
            isinstance(previous_selection, dict)
            and isinstance(previous_config, dict)
            and isinstance(previous_sources, dict)
        ):
            mismatches.append("previous manifest contract inputs missing")
        elif _resume_contract(
            selection=previous_selection,
            config=previous_config,
            source_hashes=previous_sources,
        ) != previous_contract:
            mismatches.append("previous manifest contract inputs are corrupt")

    if isinstance(proposed_contract, dict):
        proposed_selection = proposed_manifest.get("selection")
        proposed_config = proposed_manifest.get("resume_config")
        proposed_sources = proposed_manifest.get("source_hashes")
        if not (
            isinstance(proposed_selection, dict)
            and isinstance(proposed_config, dict)
            and isinstance(proposed_sources, dict)
        ):
            mismatches.append("proposed manifest contract inputs missing")
        elif _resume_contract(
            selection=proposed_selection,
            config=proposed_config,
            source_hashes=proposed_sources,
        ) != proposed_contract:
            mismatches.append("proposed manifest contract inputs are corrupt")

    if isinstance(previous_contract, dict) and isinstance(
        proposed_contract, dict
    ):
        for label, key in (
            ("selection", "selection_sha256"),
            ("config", "config_sha256"),
            ("source", "source_sha256"),
        ):
            if previous_contract.get(key) != proposed_contract.get(key):
                mismatches.append(f"{label} mismatch")
        if previous_contract.get("sha256") != proposed_contract.get("sha256"):
            mismatches.append("combined contract mismatch")

        stored_selection = _load_json_object(out_dir / "selection.json")
        if stored_selection is None:
            mismatches.append("selection file missing")
        elif (
            stable_json_digest(stored_selection)
            != proposed_contract.get("selection_sha256")
        ):
            mismatches.append("selection file mismatch")

        expected_row_contract = proposed_contract.get("sha256")
        bad_row_count = sum(
            row.get("resume_contract_sha256") != expected_row_contract
            for row in existing_rows
        )
        if bad_row_count:
            mismatches.append(
                f"{bad_row_count} existing row(s) lack the expected contract"
            )

        proposed_selection = proposed_manifest.get("selection")
        selection_cases = (
            proposed_selection.get("cases")
            if isinstance(proposed_selection, dict)
            else None
        )
        expected: dict[tuple[str, str, str, int], dict[str, Any]] = {}
        if not isinstance(selection_cases, list):
            mismatches.append("proposed selection cases missing")
        else:
            seed = int(proposed_manifest.get("seed") or 0)
            for case in selection_cases:
                if not isinstance(case, dict):
                    mismatches.append("proposed selection case malformed")
                    continue
                for condition in proposed_manifest.get("conditions") or []:
                    key = (
                        str(condition),
                        str(case.get("suite") or ""),
                        str(case.get("row_id") or ""),
                        seed,
                    )
                    expected[key] = case

        for row in existing_rows:
            key = (
                str(row.get("condition") or row.get("config_id") or ""),
                str(row.get("suite") or ""),
                str(row.get("row_id") or ""),
                int(row.get("seed") or 0),
            )
            case = expected.get(key)
            if case is None:
                mismatches.append("existing row identity is outside selection")
                continue
            identity_fields = {
                "schema_version": int(proposed_manifest.get("schema_version") or 0),
                "experiment": "accommodation",
                "benchmark": "AgentDojo",
                "benchmark_version": str(
                    proposed_manifest.get("resume_config", {}).get(
                        "benchmark_version"
                    )
                    or ""
                ),
                "suite": str(case.get("suite") or ""),
                "lane": str(case.get("lane") or ""),
                "row_id": str(case.get("row_id") or ""),
                "user_task_id": str(case.get("user_task_id") or ""),
                "injection_task_id": case.get("injection_task_id"),
                "condition": key[0],
                "config_id": key[0],
                "model": str(proposed_manifest.get("model") or ""),
                "seed": key[3],
            }
            if any(row.get(name) != value for name, value in identity_fields.items()):
                mismatches.append("existing row identity/schema is malformed")
            if str(row.get("status") or "") not in {"ok", "error"}:
                mismatches.append("existing row status is malformed")

    if mismatches:
        details = "; ".join(dict.fromkeys(mismatches))
        raise RuntimeError(
            "Refusing to resume accommodation results because "
            f"{details}. Use a fresh --out directory."
        )


def _manifest(
    *,
    args: argparse.Namespace,
    out_dir: Path,
    cases: list[Case],
    conditions: list[str],
    status: str,
) -> dict[str, Any]:
    source_paths = {
        "runner": Path(__file__).resolve(),
        "core": Path(__file__).with_name(
            "agentdojo_accommodation_core.py"
        ).resolve(),
        "protocol": (REPO_ROOT / "rebuttal" / "EXPERIMENT_PROTOCOL.md"),
        "tool_execution": (
            AGENTDOJO_SRC
            / "agentdojo"
            / "agent_pipeline"
            / "tool_execution.py"
        ),
        "task_suite": (
            AGENTDOJO_SRC / "agentdojo" / "task_suite" / "task_suite.py"
        ),
        "openai_llm": (
            AGENTDOJO_SRC
            / "agentdojo"
            / "agent_pipeline"
            / "llms"
            / "openai_llm.py"
        ),
    }
    submitted_report = (
        Path(args.submitted_reference).expanduser().resolve()
        / "agentdojo_native_plain_secureclaw_report.json"
    )
    selection = _selection_document(cases)
    source_hashes = {
        name: {
            "path": str(path),
            "sha256": _sha256_file(path),
        }
        for name, path in source_paths.items()
    }
    missing_sources = [
        name
        for name, details in source_hashes.items()
        if details["sha256"] is None
    ]
    if missing_sources:
        raise RuntimeError(
            f"cannot freeze missing source files: {missing_sources}"
        )
    config = {
        "schema_version": SCHEMA_VERSION,
        "experiment": "AgentDojo accommodation counterfactual",
        "benchmark": "AgentDojo-v1.1.2",
        "benchmark_version": str(args.benchmark_version),
        "attack": "important_instructions",
        "conditions": conditions,
        "condition_switches": {
            condition: CONDITION_SWITCHES[condition]
            for condition in conditions
        },
        "model": str(args.model),
        "provider_base_url": str(args.base_url),
        "temperature": 0.0,
        "seed": int(args.seed),
        "max_tool_iters": int(args.max_tool_iters),
        "transport_retries": int(args.retries),
        "timeout_s": float(args.timeout),
        "policy_discovery": str(
            os.getenv("SECURECLAW_POLICY_DISCOVERY") or "off"
        ),
        "submitted_reference_root": str(
            Path(args.submitted_reference).expanduser().resolve()
        ),
        "submitted_report_sha256": _sha256_file(submitted_report),
    }
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "experiment": "AgentDojo accommodation counterfactual",
        "status": status,
        "updated_at": _utc_now(),
        "expected_rows": len(cases) * len(conditions),
        "rows_per_condition": len(cases),
        "conditions": conditions,
        "condition_switches": {
            condition: CONDITION_SWITCHES[condition] for condition in conditions
        },
        "benchmark": "AgentDojo-v1.1.2",
        "attack": "important_instructions",
        "model": str(args.model),
        "provider_base_url": str(args.base_url),
        "temperature": 0.0,
        "seed": int(args.seed),
        "max_tool_iters": int(args.max_tool_iters),
        "transport_retries": int(args.retries),
        "timeout_s": float(args.timeout),
        "selected_suites": sorted({case.suite for case in cases}),
        "selected_lanes": sorted({case.lane for case in cases}),
        "selected_row_ids_sha256": stable_json_digest(
            [case.row_id for case in cases]
        ),
        "expected_frozen_counts": EXPECTED_COUNTS,
        "submitted_reference": {
            "root": str(Path(args.submitted_reference).expanduser().resolve()),
            "report": str(submitted_report),
            "report_sha256": _sha256_file(submitted_report),
        },
        "source_hashes": {
            name: details for name, details in source_hashes.items()
        },
        "selection": selection,
        "resume_config": config,
        "resume_contract": _resume_contract(
            selection=selection,
            config=config,
            source_hashes=source_hashes,
        ),
        "git": {
            "commit": _git_value("rev-parse", "HEAD"),
            "branch": _git_value("branch", "--show-current"),
            "dirty": bool(_git_value("status", "--porcelain")),
        },
        "runtime": {
            "python": sys.version,
            "platform": platform.platform(),
            "api_key_count_recorded": False,
            "api_keys_recorded": False,
        },
        "instrumentation": {
            "alias_registration_and_argument_events": True,
            "policy_request_digest_only": True,
            "confirmation_preflight": (
                "same-input Check*Policy preview; no external side effect; "
                "used only to observe need_confirm before the actual submitted path"
            ),
            "raw_sensitive_policy_inputs_persisted": False,
        },
        "command": [str(item) for item in sys.argv],
        "out_dir": str(out_dir),
    }
    return manifest


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Four-condition AgentDojo accommodation experiment."
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--base-url",
        default=os.getenv("OPENAI_BASE_URL") or DEFAULT_BASE_URL,
    )
    parser.add_argument("--benchmark-version", default="v1.1.2")
    parser.add_argument("--conditions", default=",".join(CONDITIONS))
    parser.add_argument("--suites", default=",".join(SUITES))
    parser.add_argument("--lanes", default=",".join(LANES))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--max-tool-iters", type=int, default=35)
    parser.add_argument("--max-rows", type=int, default=0)
    parser.add_argument("--row-ids-file", type=Path)
    parser.add_argument(
        "--submitted-reference",
        type=Path,
        default=DEFAULT_SUBMITTED_REFERENCE,
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument(
        "--keep-error-rows",
        action="store_true",
        help="Treat an existing error row as complete instead of rerunning it.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.benchmark_version != "v1.1.2":
        raise SystemExit(
            "This rebuttal protocol is frozen to AgentDojo-v1.1.2."
        )
    conditions = [
        value.strip() for value in args.conditions.split(",") if value.strip()
    ]
    unknown_conditions = sorted(set(conditions) - set(CONDITIONS))
    if unknown_conditions:
        raise SystemExit(f"unknown conditions: {unknown_conditions}")
    if len(set(conditions)) != len(conditions):
        raise SystemExit("conditions must be unique")

    out_dir = args.out.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = _selection_from_args(args)
    _validate_runtime_cases(cases, args.benchmark_version)
    manifest = _manifest(
        args=args,
        out_dir=out_dir,
        cases=cases,
        conditions=conditions,
        status="planned" if args.dry_run else "running",
    )
    rows_path = out_dir / "rows.jsonl"
    existing_rows = _load_jsonl(rows_path)
    _assert_resume_compatible(
        out_dir=out_dir,
        proposed_manifest=manifest,
        existing_rows=existing_rows,
    )
    if args.analyze_only:
        transitions, summary = _write_analysis(out_dir)
        print(
            json.dumps(
                {
                    "mode": "analyze_only",
                    "transitions": len(transitions),
                    "valid_rows": summary["valid_latest_rows"],
                    "out": str(out_dir),
                },
                sort_keys=True,
            )
        )
        return 0

    _atomic_json(out_dir / "run_manifest.json", manifest)
    _atomic_json(out_dir / "selection.json", _selection_document(cases))
    if args.dry_run:
        print(
            json.dumps(
                {
                    "mode": "dry_run",
                    "conditions": conditions,
                    "rows_per_condition": len(cases),
                    "expected_rows": len(cases) * len(conditions),
                    "api_calls": 0,
                    "out": str(out_dir),
                },
                sort_keys=True,
            )
        )
        return 0

    keys = _api_keys()
    if not keys:
        raise SystemExit(
            "Set OPENROUTER_API_KEYS (comma-separated), OPENROUTER_API_KEY, "
            "or OPENAI_API_KEY. No request was made."
        )

    existing = latest_rows(existing_rows)
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.task_suite.load_suites import get_suite
    from scripts.run_agentdojo_native_plain_secureclaw import SecureClawInfra

    common_env = {
        "OPENAI_API_KEY": keys[0],
        "OPENAI_BASE_URL": str(args.base_url),
        "SECURECLAW_READ_SUMMARY_MODEL": str(args.model),
        "SECURECLAW_POLICY_DISCOVERY": str(
            os.getenv("SECURECLAW_POLICY_DISCOVERY") or "off"
        ),
        "IPIGUARD_LLM_RETRY_ATTEMPTS": "1",
    }
    for condition in conditions:
        pending = []
        for case in cases:
            key = (condition, case.suite, case.row_id, int(args.seed))
            prior = existing.get(key)
            if prior is None:
                pending.append(case)
            elif prior.get("error") and not args.keep_error_rows:
                pending.append(case)
        if not pending:
            continue

        condition_env = {
            **common_env,
            **_condition_env(condition),
        }
        condition_infra_dir = out_dir / "infra" / condition
        with _environment(condition_env):
            with SecureClawInfra(
                run_dir=condition_infra_dir,
                benchmark_version=args.benchmark_version,
                suites=sorted({case.suite for case in pending}),
            ) as infra:
                with _environment(
                    {
                        name: str(value)
                        for name, value in infra.env_patch.items()
                    }
                ):
                    pipeline = _build_pipeline(
                        model=args.model,
                        base_url=args.base_url,
                        api_keys=keys,
                        seed=args.seed,
                        timeout_s=args.timeout,
                        retries=args.retries,
                        max_tool_iters=args.max_tool_iters,
                    )
                    suites = {
                        suite_name: get_suite(
                            args.benchmark_version, suite_name
                        )
                        for suite_name in sorted(
                            {case.suite for case in pending}
                        )
                    }
                    attackers = {
                        suite_name: load_attack(
                            "important_instructions",
                            suite,
                            pipeline,
                        )
                        for suite_name, suite in suites.items()
                    }
                    for index, case in enumerate(pending, start=1):
                        row = _run_case(
                            condition=condition,
                            case=case,
                            suite=suites[case.suite],
                            attacker=attackers[case.suite],
                            pipeline=pipeline,
                            model=args.model,
                            seed=args.seed,
                            out_dir=out_dir,
                        )
                        row["resume_contract_sha256"] = manifest[
                            "resume_contract"
                        ]["sha256"]
                        _append_jsonl(rows_path, row)
                        existing[
                            (
                                condition,
                                case.suite,
                                case.row_id,
                                int(args.seed),
                            )
                        ] = row
                        print(
                            json.dumps(
                                {
                                    "condition": condition,
                                    "progress": f"{index}/{len(pending)}",
                                    "row_id": case.row_id,
                                    "status": row["status"],
                                    "utility": row["utility"],
                                    "attack_success": row["attack_success"],
                                    "alias_fired": row["alias_fired"],
                                    "confirm_fired": row["confirm_fired"],
                                },
                                sort_keys=True,
                            ),
                            flush=True,
                        )

    transitions, summary = _write_analysis(out_dir)
    final_rows = _load_jsonl(rows_path)
    expected_keys = {
        (condition, case.suite, case.row_id, int(args.seed))
        for condition in conditions
        for case in cases
    }
    final_latest = latest_rows(final_rows)
    completed = [
        row
        for key, row in final_latest.items()
        if (
            key in expected_keys
            and not row.get("error")
            and str(row.get("status") or "") == "ok"
            and row.get("resume_contract_sha256")
            == manifest["resume_contract"]["sha256"]
        )
    ]
    manifest = _manifest(
        args=args,
        out_dir=out_dir,
        cases=cases,
        conditions=conditions,
        status=(
            "completed"
            if len(completed) == len(expected_keys)
            else "partial"
        ),
    )
    _assert_resume_compatible(
        out_dir=out_dir,
        proposed_manifest=manifest,
        existing_rows=final_rows,
    )
    manifest["completed_valid_rows"] = len(completed)
    manifest["transition_rows"] = len(transitions)
    manifest["summary_sha256"] = _sha256_file(out_dir / "summary.json")
    _atomic_json(out_dir / "run_manifest.json", manifest)
    print(str(out_dir / "summary.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
