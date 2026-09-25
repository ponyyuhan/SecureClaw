#!/usr/bin/env python3
"""Auditable, resumable SecureClaw cross-model runner for official ASB DPI.

The legacy ``scripts/run_cross_model_replication.py`` executes at import-time
CLI defaults, appends duplicate CSV rows on resume, and cannot safely expose a
``--help`` path.  This rebuttal runner deliberately separates four commands:

``plan``
    Freeze deterministic row IDs and write the manifest.  No credentials,
    services, or model calls are touched.
``dry-run``
    Validate the frozen selection and current resume state.  No credentials,
    services, or model calls are touched.
``run``
    Run only unfinished rows.  Successful rows are skipped; explicit error
    rows are retained in the audit log and retried on the next invocation.
``summarize``
    Rebuild canonical JSONL, ASB-compatible CSVs, and summaries atomically
    from the per-row state.  No credentials, services, or model calls are
    touched.

One output directory is one model run.  Use the same ``--seed`` and
``--n-per-attack`` in separate output directories to obtain exactly matching
row IDs for GPT-4o-mini, Qwen, and a frontier model.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import types
from types import SimpleNamespace
from typing import Any, Iterator, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = "openai/gpt-4o-mini-2024-07-18"
DEFAULT_N_PER_ATTACK = 50
DEFAULT_SEED = 3179
SCHEMA_VERSION = 1
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,;]+"),
)


class RunnerError(RuntimeError):
    """User-facing validation error."""


@dataclass(frozen=True)
class RunConfig:
    command: str
    out: Path
    model: str
    n_per_attack: int
    seed: int


@dataclass(frozen=True)
class PreparedRun:
    config: RunConfig
    components: Any
    attack_families: tuple[str, ...]
    selected_plan: tuple[dict[str, Any], ...]
    scenarios_by_key: Mapping[str, Any]
    inventory_by_family: Mapping[str, int]
    selection_sha256: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _git_commit() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = result.stdout.strip()
    return value or None


def _redact_error(value: Any) -> str:
    text = str(value or "")
    for pattern in _SECRET_PATTERNS:
        if "api" in pattern.pattern.lower():
            text = pattern.sub(r"\1[REDACTED]", text)
        else:
            text = pattern.sub("[REDACTED]", text)
    return text[:4000]


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except (TypeError, ValueError):
        return str(value)


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temp.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _atomic_json(path: Path, value: Any) -> None:
    _atomic_text(path, json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def _atomic_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    text = "".join(
        json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n" for row in rows
    )
    _atomic_text(path, text)


def _append_attempt(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(row), ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Cannot read {path}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise RunnerError(f"Expected a JSON object in {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RunnerError(
                    f"Invalid JSONL in {path}:{line_number}: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise RunnerError(f"Expected an object in {path}:{line_number}")
            rows.append(value)
    return rows


def _load_asb_components() -> Any:
    """Lazy-load the official ASB/SecureClaw implementation.

    Keeping this import behind command parsing guarantees that ``--help`` does
    not import benchmark integrations, inspect credentials, start services, or
    make a model request.
    """

    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    _install_plotting_stub_for_numpy2_abi()
    module = importlib.import_module("scripts.asb_five_baseline_compare")
    return SimpleNamespace(
        DEFAULT_ATTACK_TYPES=tuple(module.DEFAULT_ATTACK_TYPES),
        SecureClawInfra=module.SecureClawInfra,
        load_scenarios=module.load_scenarios,
        run_secureclaw_case=module._run_secureclaw_case,
        append_csv_row=module._append_csv_row,
        ensure_csv=module._ensure_csv,
        summarize_csv=module._summarize_csv,
        attack_success=module._attack_success,
        utility_success=module._utility_success,
        refusal_result=module._refusal_result,
    )


def _install_plotting_stub_for_numpy2_abi() -> None:
    """Avoid importing an unused matplotlib binary extension during summarize."""

    if "matplotlib.pylab" in sys.modules:
        return
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            import matplotlib.pylab  # noqa: F401
        return
    except Exception:
        mpl = types.ModuleType("matplotlib")
        pylab = types.ModuleType("matplotlib.pylab")
        setattr(mpl, "pylab", pylab)
        sys.modules["matplotlib"] = mpl
        sys.modules["matplotlib.pylab"] = pylab


def _normal_tool_record(tool: Any) -> dict[str, Any]:
    return {
        "name": str(getattr(tool, "name", "")),
        "description": str(getattr(tool, "description", "")),
        "expected_achievement": str(getattr(tool, "expected_achievement", "")),
    }


def _attack_tool_record(tool: Any) -> dict[str, Any]:
    return {
        "tool_name": str(getattr(tool, "tool_name", "")),
        "instruction": str(getattr(tool, "instruction", "")),
        "description": str(getattr(tool, "description", "")),
        "attack_goal": str(getattr(tool, "attack_goal", "")),
        "aggressive": bool(getattr(tool, "aggressive", False)),
    }


def _scenario_identity(scenario: Any) -> dict[str, Any]:
    """Return all semantic fields used to derive the immutable row key."""

    return {
        "benchmark": "ASB",
        "attack_family": str(getattr(scenario, "attack_type", "")),
        "agent_name": str(getattr(scenario, "agent_name", "")),
        "agent_path": str(getattr(scenario, "agent_path", "")),
        "task": str(getattr(scenario, "task", "")),
        "system_prompt_sha256": hashlib.sha256(
            str(getattr(scenario, "system_prompt", "")).encode("utf-8")
        ).hexdigest(),
        "normal_tools": [
            _normal_tool_record(tool)
            for tool in tuple(getattr(scenario, "normal_tools", ()) or ())
        ],
        "attack_tool": _attack_tool_record(getattr(scenario, "attack_tool", None)),
    }


def scenario_row_key(scenario: Any) -> str:
    identity = _scenario_identity(scenario)
    family = re.sub(r"[^A-Za-z0-9_.-]+", "_", identity["attack_family"])
    digest = _sha256_json(identity)
    return f"asb_{family}_{digest}"


def _selection_seed(seed: int, family: str) -> int:
    digest = hashlib.sha256(f"{int(seed)}|{family}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def _sample_family(
    scenarios: Sequence[Any],
    *,
    family: str,
    n: int,
    seed: int,
) -> list[Any]:
    import random

    pool = sorted(scenarios, key=scenario_row_key)
    if len(pool) < n:
        raise RunnerError(
            f"ASB family {family!r} has {len(pool)} rows, fewer than requested {n}"
        )
    rng = random.Random(_selection_seed(seed, family))
    return sorted(rng.sample(pool, n), key=scenario_row_key)


def _build_selection(
    scenarios: Sequence[Any],
    *,
    attack_families: tuple[str, ...],
    n_per_attack: int,
    seed: int,
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any], dict[str, int],]:
    by_family: dict[str, list[Any]] = {family: [] for family in attack_families}
    all_by_key: dict[str, Any] = {}
    for scenario in scenarios:
        family = str(getattr(scenario, "attack_type", ""))
        if family not in by_family:
            continue
        key = scenario_row_key(scenario)
        if key in all_by_key:
            raise RunnerError(f"Duplicate ASB row identity: {key}")
        all_by_key[key] = scenario
        by_family[family].append(scenario)

    inventory = {family: len(by_family[family]) for family in attack_families}
    plan: list[dict[str, Any]] = []
    selected_lookup: dict[str, Any] = {}
    selection_index = 0
    for family in attack_families:
        selected = _sample_family(
            by_family[family],
            family=family,
            n=n_per_attack,
            seed=seed,
        )
        for family_index, scenario in enumerate(selected):
            key = scenario_row_key(scenario)
            identity = _scenario_identity(scenario)
            plan.append(
                {
                    "schema_version": SCHEMA_VERSION,
                    "selection_index": selection_index,
                    "family_index": family_index,
                    "row_key": key,
                    **identity,
                }
            )
            selected_lookup[key] = scenario
            selection_index += 1
    return tuple(plan), selected_lookup, inventory


def _resolve_config(args: argparse.Namespace) -> RunConfig:
    out = Path(args.out).expanduser().resolve()
    existing = _read_json(out / "run_manifest.json")

    existing_model = str((existing or {}).get("model") or "").strip()
    model = str(args.model or existing_model or DEFAULT_MODEL).strip()
    if not model:
        raise RunnerError("--model cannot be empty")

    existing_n = (existing or {}).get("n_per_attack")
    n_per_attack = (
        int(args.n_per_attack)
        if args.n_per_attack is not None
        else int(existing_n or DEFAULT_N_PER_ATTACK)
    )
    if n_per_attack <= 0:
        raise RunnerError("--n-per-attack must be positive")

    existing_seed = (existing or {}).get("selection_seed", (existing or {}).get("seed"))
    seed = (
        int(args.seed)
        if args.seed is not None
        else int(existing_seed if existing_seed is not None else DEFAULT_SEED)
    )

    if existing:
        immutable = {
            "model": (existing_model, model),
            "n_per_attack": (
                int(existing_n or DEFAULT_N_PER_ATTACK),
                n_per_attack,
            ),
            "selection_seed": (
                int(existing_seed if existing_seed is not None else DEFAULT_SEED),
                seed,
            ),
        }
        changed = [
            f"{name}: existing={old!r}, requested={new!r}"
            for name, (old, new) in immutable.items()
            if old != new
        ]
        if changed:
            raise RunnerError(
                "Output directory is already bound to a different run; use a "
                f"fresh --out directory ({'; '.join(changed)})"
            )

    return RunConfig(
        command=str(args.command),
        out=out,
        model=model,
        n_per_attack=n_per_attack,
        seed=seed,
    )


def _source_manifest() -> dict[str, Any]:
    asb_script = REPO_ROOT / "scripts" / "asb_five_baseline_compare.py"
    ipiguard_openai = (
        REPO_ROOT
        / "third_party"
        / "ipiguard"
        / "agentdojo"
        / "src"
        / "agentdojo"
        / "agent_pipeline"
        / "llms"
        / "openai_llm.py"
    )
    ipiguard_executor = (
        REPO_ROOT
        / "third_party"
        / "ipiguard"
        / "agentdojo"
        / "src"
        / "agentdojo"
        / "agent_pipeline"
        / "tool_execution.py"
    )
    return {
        "git_commit": _git_commit(),
        "python": platform.python_version(),
        "runner": {
            "path": str(Path(__file__).resolve()),
            "sha256": _sha256_file(Path(__file__).resolve()),
        },
        "asb_secureclaw_source": {
            "path": str(asb_script.resolve()),
            "sha256": _sha256_file(asb_script),
        },
        "ipiguard_openai_adapter": {
            "path": str(ipiguard_openai.resolve()),
            "sha256": _sha256_file(ipiguard_openai),
            "malformed_tool_arguments": "fail_row_without_execution",
        },
        "ipiguard_secureclaw_executor": {
            "path": str(ipiguard_executor.resolve()),
            "sha256": _sha256_file(ipiguard_executor),
        },
    }


def _safe_runtime_config() -> dict[str, str]:
    """Record non-secret SecureClaw/ASB knobs that can change outcomes."""

    defaults = {
        "USE_POLICY_BUNDLE": "1",
        "DLP_MODE": "dfa",
        "LEAKAGE_BUDGET_ENABLED": "0",
        "SECURECLAW_SESSION_SCOPE": "per_turn",
        "SECURECLAW_STRICT_SINK_BINDING": "1",
        "SECURECLAW_DENY_UNMAPPED_EFFECT": "1",
        "SECURECLAW_ALLOW_LOCAL_STATE_EFFECTS": "1",
        "SECURECLAW_INTENT_CONTRACT_MODE": "intent_v1",
        "SECURECLAW_MAX_TOOL_ITERS": "20",
        "SECURECLAW_ENFORCE_COMMIT_PATH": "1",
        "SECURECLAW_AUTO_USER_CONFIRM": "1",
        "SECURECLAW_HANDLEIZE_READ_OUTPUT": "1",
        "SECURECLAW_READ_HANDLE_SENSITIVITY": "HIGH",
        "SECURECLAW_READ_HANDLE_TTL_S": "900",
        "SECURECLAW_READ_OUTPUT_MODE": "sanitized_summary",
        "SECURECLAW_READ_SUMMARY_MAX_ITEMS": "8",
        "SECURECLAW_READ_SUMMARY_MAX_CHARS": "512",
        "ASB_COMPARE_OPENAI_TIMEOUT_S": "180",
        "ASB_COMPARE_OPENAI_MAX_RETRIES": "3",
    }
    return {
        name: str(os.getenv(name, default))
        for name, default in sorted(defaults.items())
    }


def _manifest_for_prepared(
    prepared: PreparedRun,
    *,
    existing: Mapping[str, Any] | None,
    last_command: str,
) -> dict[str, Any]:
    created_at = str((existing or {}).get("created_at") or _utc_now())
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "experiment": "asb_secureclaw_cross_model",
        "status": str((existing or {}).get("status") or "PLANNED"),
        "created_at": created_at,
        "updated_at": _utc_now(),
        "last_command": last_command,
        "model": prepared.config.model,
        "provider_protocol": "OpenAI-compatible",
        "provider_base_url": OPENROUTER_BASE_URL,
        "selection_seed": prepared.config.seed,
        "seed": prepared.config.seed,
        "decoding_seed": None,
        "decoding_seed_note": (
            "--seed freezes ASB row selection; upstream _run_secureclaw_case "
            "does not expose a decoding-seed argument"
        ),
        "task_num": 1,
        "runtime_config": _safe_runtime_config(),
        "n_per_attack": prepared.config.n_per_attack,
        "attack_types": list(prepared.attack_families),
        "expected_rows": len(prepared.selected_plan),
        "inventory_by_attack": dict(prepared.inventory_by_family),
        "selection_sha256": prepared.selection_sha256,
        "row_plan": "selected_rows.jsonl",
        "result_store": "task_rows/",
        "attempt_log": "attempts.jsonl",
        "canonical_rows": "canonical_rows.jsonl",
        "asb_csv_root": "secureclaw/",
        "resume_policy": (
            "skip status=ok; retry status=error; rebuild compatibility CSVs "
            "from deduplicated per-row state"
        ),
        "sources": dict((existing or {}).get("sources") or _source_manifest()),
    }
    for key in ("completed_rows", "error_rows", "pending_rows"):
        if key in (existing or {}):
            manifest[key] = int((existing or {})[key])
    return manifest


def _prepare(args: argparse.Namespace) -> PreparedRun:
    config = _resolve_config(args)
    components = _load_asb_components()
    attack_families = tuple(str(x) for x in components.DEFAULT_ATTACK_TYPES)
    if len(attack_families) != 5 or len(set(attack_families)) != 5:
        raise RunnerError(
            "Expected exactly the five official ASB attack families, got "
            f"{attack_families!r}"
        )

    scenarios = components.load_scenarios(
        attack_types=attack_families,
        task_num=1,
    )
    selected_plan, lookup, inventory = _build_selection(
        scenarios,
        attack_families=attack_families,
        n_per_attack=config.n_per_attack,
        seed=config.seed,
    )
    selection_sha256 = _sha256_json([row["row_key"] for row in selected_plan])
    prepared = PreparedRun(
        config=config,
        components=components,
        attack_families=attack_families,
        selected_plan=selected_plan,
        scenarios_by_key=lookup,
        inventory_by_family=inventory,
        selection_sha256=selection_sha256,
    )

    existing_plan = _read_jsonl(config.out / "selected_rows.jsonl")
    if existing_plan:
        existing_keys = [str(row.get("row_key") or "") for row in existing_plan]
        current_keys = [str(row["row_key"]) for row in selected_plan]
        if existing_keys != current_keys:
            raise RunnerError(
                "Frozen selected_rows.jsonl does not match the current official "
                "ASB inventory/selection. Use a fresh --out directory rather "
                "than silently changing comparison rows."
            )

    existing_manifest = _read_json(config.out / "run_manifest.json")
    if existing_manifest:
        old_digest = str(existing_manifest.get("selection_sha256") or "")
        if old_digest and old_digest != selection_sha256:
            raise RunnerError(
                "run_manifest.json selection_sha256 does not match the "
                "deterministic selection"
            )
        current_sources = _source_manifest()
        if existing_manifest.get("sources") != current_sources:
            raise RunnerError(
                "run_manifest.json source provenance does not match the "
                "currently loaded runner/harness. Use a fresh --out directory "
                "instead of resuming rows produced by different code."
            )
        current_runtime = _safe_runtime_config()
        if existing_manifest.get("runtime_config") != current_runtime:
            raise RunnerError(
                "run_manifest.json runtime_config does not match the current "
                "SecureClaw/ASB environment. Use a fresh --out directory."
            )

    config.out.mkdir(parents=True, exist_ok=True)
    if not existing_plan:
        _atomic_jsonl(config.out / "selected_rows.jsonl", selected_plan)
    manifest = _manifest_for_prepared(
        prepared,
        existing=existing_manifest,
        last_command=config.command,
    )
    _atomic_json(config.out / "run_manifest.json", manifest)
    _atomic_json(
        config.out / "plan.json",
        {
            "experiment": manifest["experiment"],
            "model": config.model,
            "selection_seed": config.seed,
            "n_per_attack": config.n_per_attack,
            "attack_types": list(attack_families),
            "inventory_by_attack": inventory,
            "selected_by_attack": {
                family: sum(
                    str(row["attack_family"]) == family for row in selected_plan
                )
                for family in attack_families
            },
            "expected_rows": len(selected_plan),
            "selection_sha256": selection_sha256,
            "api_requests_made": 0,
        },
    )
    return prepared


def _task_result_path(out: Path, row_key: str) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", row_key):
        raise RunnerError(f"Unsafe row key: {row_key!r}")
    return out / "task_rows" / f"{row_key}.json"


def _load_current_results(
    prepared: PreparedRun,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    expected = {str(row["row_key"]) for row in prepared.selected_plan}
    results: dict[str, dict[str, Any]] = {}
    audit_errors: list[dict[str, Any]] = []
    result_dir = prepared.config.out / "task_rows"
    if not result_dir.is_dir():
        return results, audit_errors

    for path in sorted(result_dir.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("root is not an object")
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            key = path.stem
            value = {
                "schema_version": SCHEMA_VERSION,
                "row_key": key,
                "status": "error",
                "model": prepared.config.model,
                "seed": prepared.config.seed,
                "error": {
                    "type": "CorruptResultFile",
                    "message": _redact_error(exc),
                },
                "_result_file": str(path),
            }
        key = str(value.get("row_key") or "")
        if key not in expected:
            audit_errors.append(
                {
                    "row_key": key or path.stem,
                    "status": "error",
                    "error": {
                        "type": "UnknownRowKey",
                        "message": f"Unexpected result file: {path}",
                    },
                }
            )
            continue
        if str(value.get("model") or "") != prepared.config.model:
            value = {
                "schema_version": SCHEMA_VERSION,
                "row_key": key,
                "status": "error",
                "model": prepared.config.model,
                "seed": prepared.config.seed,
                "attempt": int(value.get("attempt") or 0),
                "error": {
                    "type": "ModelMismatch",
                    "message": (
                        f"Result model {value.get('model')!r} does not "
                        f"match manifest model {prepared.config.model!r}"
                    ),
                },
            }
            results[key] = value
            continue
        results[key] = value
    return results, audit_errors


def _result_metrics(
    prepared: PreparedRun, scenario: Any, messages: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "attack_success": bool(
            prepared.components.attack_success(
                messages,
                str(getattr(scenario.attack_tool, "attack_goal", "")),
            )
        ),
        "utility_success": bool(
            prepared.components.utility_success(
                messages,
                tuple(getattr(scenario, "normal_tools", ()) or ()),
            )
        ),
        "refusal": bool(prepared.components.refusal_result(messages)),
    }


def _validate_provider_records(
    extra_args: Mapping[str, Any],
    *,
    requested_model: str,
) -> None:
    records = [
        item
        for item in extra_args.get("provider_requests", [])
        if isinstance(item, Mapping)
    ]
    if not records:
        raise RunnerError("No provider request metadata was recorded")
    missing = sum(
        (
            not str(item.get("response_id") or "")
            or not str(item.get("requested_model") or "")
            or not str(item.get("returned_model") or "")
        )
        for item in records
    )
    mismatched = sorted(
        {
            (
                str(item.get("requested_model") or ""),
                str(item.get("returned_model") or ""),
            )
            for item in records
            if (
                str(item.get("requested_model") or "") != requested_model
                or str(item.get("returned_model") or "") != requested_model
            )
        }
    )
    if missing or mismatched:
        raise RunnerError(
            "Provider model audit failed: "
            f"requested={requested_model!r}, missing={missing}, "
            f"mismatched={mismatched!r}"
        )


def _canonical_result(
    plan_row: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    model: str,
    seed: int,
) -> dict[str, Any]:
    metrics = result.get("metrics")
    metrics = metrics if isinstance(metrics, dict) else {}
    error = result.get("error")
    error_message = None
    if isinstance(error, dict):
        error_message = str(error.get("message") or error.get("type") or "")
    elif error:
        error_message = str(error)
    extra_args = result.get("extra_args")
    extra_args = extra_args if isinstance(extra_args, Mapping) else {}
    provider_requests = [
        dict(item)
        for item in extra_args.get("provider_requests", [])
        if isinstance(item, Mapping)
    ]
    provider_request_ids = [
        str(item.get("request_id") or item.get("response_id") or "")
        for item in provider_requests
        if str(item.get("request_id") or item.get("response_id") or "")
    ]
    returned_models = sorted(
        {
            str(item.get("returned_model") or "")
            for item in provider_requests
            if str(item.get("returned_model") or "")
        }
    )
    cost_values = [
        float(item["cost_usd"])
        for item in provider_requests
        if isinstance(item.get("cost_usd"), (int, float))
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment": "openweight_asb",
        "benchmark": "ASB",
        "kind": "attack",
        "lane": "attacked",
        "system": "SecureClaw",
        "model": model,
        "seed": seed,
        "row_id": str(plan_row["row_key"]),
        "row_key": str(plan_row["row_key"]),
        "scenario_id": str(plan_row["row_key"]),
        "attack_family": str(plan_row["attack_family"]),
        "agent_name": str(plan_row["agent_name"]),
        "attack_tool": str((plan_row.get("attack_tool") or {}).get("tool_name") or ""),
        "status": str(result.get("status") or "error"),
        "attempt": int(result.get("attempt") or 0),
        "attack_success": metrics.get("attack_success"),
        "utility_success": metrics.get("utility_success"),
        "refusal": metrics.get("refusal"),
        "error": error_message,
        "started_at": result.get("started_at"),
        "completed_at": result.get("completed_at"),
        "latency_s": result.get("latency_s"),
        "input_tokens": int(extra_args.get("input_tokens") or 0),
        "output_tokens": int(extra_args.get("output_tokens") or 0),
        "provider_requests": len(provider_requests),
        "provider_request_ids": provider_request_ids,
        "returned_models": returned_models,
        "cost_usd": sum(cost_values) if cost_values else None,
    }


def _materialize_csvs(
    prepared: PreparedRun,
    results: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    csv_root = prepared.config.out / "secureclaw"
    csv_root.mkdir(parents=True, exist_ok=True)
    summaries: dict[str, dict[str, Any]] = {}
    for family in prepared.attack_families:
        final_path = csv_root / f"{family}.csv"
        temp_path = csv_root / f".{family}.{os.getpid()}.tmp.csv"
        if temp_path.exists():
            temp_path.unlink()
        prepared.components.ensure_csv(temp_path)
        for plan_row in prepared.selected_plan:
            if str(plan_row["attack_family"]) != family:
                continue
            key = str(plan_row["row_key"])
            result = results.get(key)
            if not isinstance(result, Mapping) or result.get("status") != "ok":
                continue
            messages = result.get("messages")
            if not isinstance(messages, list):
                continue
            prepared.components.append_csv_row(
                temp_path,
                scenario=prepared.scenarios_by_key[key],
                messages=messages,
            )
        os.replace(temp_path, final_path)
        summaries[family] = dict(prepared.components.summarize_csv(final_path))
    return summaries


def _aggregate_completed(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    ok_rows = [row for row in rows if row.get("status") == "ok"]
    attack = sum(bool(row.get("attack_success")) for row in ok_rows)
    utility = sum(bool(row.get("utility_success")) for row in ok_rows)
    refusal = sum(bool(row.get("refusal")) for row in ok_rows)
    n = len(ok_rows)
    return {
        "completed_rows": n,
        "attack_success_count": attack,
        "attack_success_rate": attack / n if n else None,
        "utility_success_count": utility,
        "utility_success_rate": utility / n if n else None,
        "refuse_count": refusal,
        "refuse_rate": refusal / n if n else None,
    }


def _summary_markdown(summary: Mapping[str, Any]) -> str:
    overall = summary

    def pct(value: Any) -> str:
        if value is None:
            return "—"
        return f"{100 * float(value):.2f}%"

    lines = [
        "# ASB SecureClaw Cross-Model Summary",
        "",
        f"- status: `{summary.get('status')}`",
        f"- model: `{summary.get('model')}`",
        f"- selection_seed: `{summary.get('selection_seed')}`",
        f"- expected_rows: `{summary.get('expected_rows')}`",
        f"- completed_rows: `{summary.get('completed_rows')}`",
        f"- error_rows: `{summary.get('error_rows')}`",
        f"- pending_rows: `{summary.get('pending_rows')}`",
        f"- selection_sha256: `{summary.get('selection_sha256')}`",
        "",
        "| Scope | Expected | Completed | Errors | Pending | ASR | Utility | Refuse |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| Overall | {summary.get('expected_rows', 0)} | "
            f"{summary.get('completed_rows', 0)} | "
            f"{summary.get('error_rows', 0)} | "
            f"{summary.get('pending_rows', 0)} | "
            f"{pct(overall.get('attack_success_rate'))} | "
            f"{pct(overall.get('utility_success_rate'))} | "
            f"{pct(overall.get('refuse_rate'))} |"
        ),
    ]
    per_attack = summary.get("per_attack")
    per_attack = per_attack if isinstance(per_attack, Mapping) else {}
    for family, row in per_attack.items():
        values = row if isinstance(row, Mapping) else {}
        lines.append(
            f"| {family} | {values.get('expected_rows', 0)} | "
            f"{values.get('completed_rows', 0)} | "
            f"{values.get('error_rows', 0)} | "
            f"{values.get('pending_rows', 0)} | "
            f"{pct(values.get('attack_success_rate'))} | "
            f"{pct(values.get('utility_success_rate'))} | "
            f"{pct(values.get('refuse_rate'))} |"
        )
    lines.append("")
    if summary.get("errors"):
        lines.extend(["## Explicit errors", ""])
        for error in summary["errors"]:
            lines.append(
                f"- `{error.get('row_key')}`: "
                f"{error.get('error_type')}: {error.get('message')}"
            )
        lines.append("")
    return "\n".join(lines)


def materialize(prepared: PreparedRun, *, last_command: str) -> dict[str, Any]:
    results, audit_errors = _load_current_results(prepared)
    canonical: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    per_attack_rows: dict[str, list[dict[str, Any]]] = {
        family: [] for family in prepared.attack_families
    }

    for plan_row in prepared.selected_plan:
        key = str(plan_row["row_key"])
        result = results.get(key)
        if result is None:
            continue
        canonical_row = _canonical_result(
            plan_row,
            result,
            model=prepared.config.model,
            seed=prepared.config.seed,
        )
        canonical.append(canonical_row)
        per_attack_rows[str(plan_row["attack_family"])].append(canonical_row)
        if canonical_row["status"] != "ok":
            error = result.get("error")
            error = error if isinstance(error, Mapping) else {}
            errors.append(
                {
                    "row_key": key,
                    "attack_family": str(plan_row["attack_family"]),
                    "error_type": str(error.get("type") or "UnknownError"),
                    "message": _redact_error(error.get("message") or ""),
                    "attempt": int(result.get("attempt") or 0),
                }
            )

    for audit_error in audit_errors:
        error = audit_error.get("error")
        error = error if isinstance(error, Mapping) else {}
        errors.append(
            {
                "row_key": str(audit_error.get("row_key") or ""),
                "attack_family": "",
                "error_type": str(error.get("type") or "AuditError"),
                "message": _redact_error(error.get("message") or ""),
                "attempt": int(audit_error.get("attempt") or 0),
            }
        )

    _atomic_jsonl(prepared.config.out / "canonical_rows.jsonl", canonical)
    csv_summaries = _materialize_csvs(prepared, results)

    expected = len(prepared.selected_plan)
    completed = sum(row.get("status") == "ok" for row in canonical)
    error_count = sum(row.get("status") != "ok" for row in canonical) + len(
        audit_errors
    )
    pending = max(0, expected - len(canonical))
    if completed == expected and error_count == 0:
        status = "COMPLETE"
    elif not canonical and not audit_errors:
        status = "PLANNED"
    else:
        status = "PARTIAL"

    per_attack: dict[str, Any] = {}
    for family in prepared.attack_families:
        rows = per_attack_rows[family]
        aggregate = _aggregate_completed(rows)
        family_errors = sum(row.get("status") != "ok" for row in rows)
        family_expected = sum(
            str(row["attack_family"]) == family for row in prepared.selected_plan
        )
        per_attack[family] = {
            "expected_rows": family_expected,
            **aggregate,
            "error_rows": family_errors,
            "pending_rows": max(
                0, family_expected - aggregate["completed_rows"] - family_errors
            ),
            "csv": csv_summaries.get(family),
        }

    overall = _aggregate_completed(canonical)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "experiment": "asb_secureclaw_cross_model",
        "status": status,
        "model": prepared.config.model,
        "selection_seed": prepared.config.seed,
        "seed": prepared.config.seed,
        "n_per_attack": prepared.config.n_per_attack,
        "attack_types": list(prepared.attack_families),
        "selection_sha256": prepared.selection_sha256,
        "expected_rows": expected,
        **overall,
        "error_rows": error_count,
        "pending_rows": pending,
        "per_attack": per_attack,
        "errors": errors,
        "unknown_or_corrupt_result_rows": len(audit_errors),
        "updated_at": _utc_now(),
    }
    _atomic_json(prepared.config.out / "summary.json", summary)
    _atomic_text(
        prepared.config.out / "summary.md",
        _summary_markdown(summary),
    )

    report = {
        "status": "OK" if status == "COMPLETE" else status,
        "experiment": "asb_secureclaw_cross_model",
        "run_root": str(prepared.config.out),
        "model": prepared.config.model,
        "seed": prepared.config.seed,
        "run_seed": prepared.config.seed,
        "task_num": 1,
        "attack_types": list(prepared.attack_families),
        "expected_rows": expected,
        "completed_rows": completed,
        "error_rows": error_count,
        "pending_rows": pending,
        "selection_sha256": prepared.selection_sha256,
        "baselines": {
            "secureclaw": {
                "per_attack_type": {
                    family: csv_summaries.get(family, {})
                    for family in prepared.attack_families
                },
                "overall": {"rows": completed, **overall},
            }
        },
    }
    _atomic_json(prepared.config.out / "report.json", report)

    old_manifest = _read_json(prepared.config.out / "run_manifest.json") or {}
    manifest = _manifest_for_prepared(
        prepared,
        existing=old_manifest,
        last_command=last_command,
    )
    manifest.update(
        {
            "status": status,
            "completed_rows": completed,
            "error_rows": error_count,
            "pending_rows": pending,
            "updated_at": _utc_now(),
        }
    )
    _atomic_json(prepared.config.out / "run_manifest.json", manifest)
    return summary


@contextmanager
def _patched_provider_environment() -> Iterator[None]:
    """Expose OpenRouter through the OpenAI-compatible variables only for run."""

    openrouter_present = bool(str(os.getenv("OPENROUTER_API_KEY") or "").strip())
    if not openrouter_present:
        raise RunnerError("run requires OPENROUTER_API_KEY; no request was made")

    names = ("OPENAI_API_KEY", "OPENAI_BASE_URL")
    old = {name: os.environ.get(name) for name in names}
    os.environ["OPENAI_API_KEY"] = os.environ["OPENROUTER_API_KEY"]
    os.environ["OPENAI_BASE_URL"] = OPENROUTER_BASE_URL
    try:
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextmanager
def _patched_infra_environment(patch: Mapping[str, Any]) -> Iterator[None]:
    old = {name: os.environ.get(name) for name in patch}
    for name, value in patch.items():
        os.environ[str(name)] = str(value)
    try:
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def execute_run(prepared: PreparedRun) -> dict[str, Any]:
    results, _ = _load_current_results(prepared)
    pending_rows = [
        row
        for row in prepared.selected_plan
        if (results.get(str(row["row_key"])) or {}).get("status") != "ok"
    ]
    if not pending_rows:
        return materialize(prepared, last_command="run")

    with _patched_provider_environment():
        infra_dir = prepared.config.out / "_infra_secureclaw"
        try:
            with prepared.components.SecureClawInfra(infra_dir) as infra:
                with _patched_infra_environment(infra.env_patch):
                    for index, plan_row in enumerate(pending_rows, start=1):
                        key = str(plan_row["row_key"])
                        scenario = prepared.scenarios_by_key[key]
                        previous = results.get(key) or {}
                        attempt = int(previous.get("attempt") or 0) + 1
                        started_at = _utc_now()
                        started_clock = time.monotonic()
                        try:
                            (
                                messages,
                                extra_args,
                            ) = prepared.components.run_secureclaw_case(
                                scenario,
                                prepared.config.model,
                            )
                            _validate_provider_records(
                                extra_args,
                                requested_model=prepared.config.model,
                            )
                            if not isinstance(messages, list):
                                messages = list(messages)
                            row_result = {
                                "schema_version": SCHEMA_VERSION,
                                "experiment": "asb_secureclaw_cross_model",
                                "row_key": key,
                                "status": "ok",
                                "model": prepared.config.model,
                                "seed": prepared.config.seed,
                                "attempt": attempt,
                                "started_at": started_at,
                                "completed_at": _utc_now(),
                                "latency_s": time.monotonic() - started_clock,
                                "metrics": _result_metrics(
                                    prepared, scenario, messages
                                ),
                                "messages": _json_safe(messages),
                                "extra_args": _json_safe(extra_args),
                                "error": None,
                            }
                        except Exception as exc:  # noqa: BLE001
                            row_result = {
                                "schema_version": SCHEMA_VERSION,
                                "experiment": "asb_secureclaw_cross_model",
                                "row_key": key,
                                "status": "error",
                                "model": prepared.config.model,
                                "seed": prepared.config.seed,
                                "attempt": attempt,
                                "started_at": started_at,
                                "completed_at": _utc_now(),
                                "latency_s": time.monotonic() - started_clock,
                                "metrics": {
                                    "attack_success": None,
                                    "utility_success": None,
                                    "refusal": None,
                                },
                                "messages": [],
                                "extra_args": {},
                                "error": {
                                    "type": type(exc).__name__,
                                    "message": _redact_error(exc),
                                },
                            }
                        _atomic_json(
                            _task_result_path(prepared.config.out, key), row_result
                        )
                        _append_attempt(
                            prepared.config.out / "attempts.jsonl",
                            {
                                key_name: row_result.get(key_name)
                                for key_name in (
                                    "schema_version",
                                    "experiment",
                                    "row_key",
                                    "status",
                                    "model",
                                    "seed",
                                    "attempt",
                                    "started_at",
                                    "completed_at",
                                    "latency_s",
                                    "metrics",
                                    "error",
                                )
                            },
                        )
                        results[key] = row_result
                        summary = materialize(
                            prepared,
                            last_command="run",
                        )
                        print(
                            f"[{index}/{len(pending_rows)}] "
                            f"{plan_row['attack_family']} {key} "
                            f"status={row_result['status']} "
                            f"complete={summary['completed_rows']}/"
                            f"{summary['expected_rows']}",
                            flush=True,
                        )
        finally:
            # Materialize even if service startup, interruption, or an
            # unexpected infrastructure exception aborts the loop.
            materialize(prepared, last_command="run")
    return materialize(prepared, last_command="run")


def _print_plan(prepared: PreparedRun, *, label: str) -> None:
    results, audit_errors = _load_current_results(prepared)
    ok = sum(row.get("status") == "ok" for row in results.values())
    failed = sum(row.get("status") != "ok" for row in results.values())
    expected = len(prepared.selected_plan)
    payload = {
        "command": label,
        "model": prepared.config.model,
        "out": str(prepared.config.out),
        "selection_seed": prepared.config.seed,
        "n_per_attack": prepared.config.n_per_attack,
        "attack_types": list(prepared.attack_families),
        "expected_rows": expected,
        "completed_rows": ok,
        "retryable_error_rows": failed,
        "pending_rows": max(0, expected - len(results)),
        "audit_error_rows": len(audit_errors),
        "selection_sha256": prepared.selection_sha256,
        "api_requests_made": 0,
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a fixed-row, resumable SecureClaw ASB cross-model rebuttal "
            "experiment. Only the 'run' command can make model/API calls."
        )
    )
    parser.add_argument(
        "command",
        choices=("plan", "dry-run", "run", "summarize"),
    )
    parser.add_argument(
        "--model",
        default=None,
        help=(
            "OpenAI-compatible model ID. For a new output directory the "
            f"default is {DEFAULT_MODEL!r}; existing manifests retain their model."
        ),
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output directory for exactly one model run.",
    )
    parser.add_argument(
        "--n-per-attack",
        type=int,
        default=None,
        help=(
            "Rows selected from each official ASB attack family "
            f"(default for a new run: {DEFAULT_N_PER_ATTACK})."
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help=(
            "Deterministic row-selection seed "
            f"(default for a new run: {DEFAULT_SEED})."
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        prepared = _prepare(args)
        if args.command == "plan":
            _print_plan(prepared, label="plan")
            return 0
        if args.command == "dry-run":
            summary = materialize(prepared, last_command="dry-run")
            _print_plan(prepared, label="dry-run")
            return 0 if not summary.get("unknown_or_corrupt_result_rows") else 2
        if args.command == "summarize":
            summary = materialize(prepared, last_command="summarize")
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return 0 if summary["status"] == "COMPLETE" else 2
        summary = execute_run(prepared)
        return 0 if summary["status"] == "COMPLETE" else 2
    except RunnerError as exc:
        print(f"ERROR: {_redact_error(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("ERROR: interrupted; resumable state was retained", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(
            f"ERROR: {type(exc).__name__}: {_redact_error(exc)}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
