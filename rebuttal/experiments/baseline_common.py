"""Shared, dependency-light helpers for the CaMeL/Progent rebuttal runners.

This module deliberately does not import either upstream artifact.  Runners can
therefore build and inspect manifests without loading API clients or mutating
Progent's import-time global policy state.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SUITES = ("workspace", "banking", "travel", "slack")
BENCHMARK_VERSION = "v1.1.2"
ATTACK = "important_instructions"


class ManifestContractError(RuntimeError):
    """Raised when an existing baseline run cannot be resumed faithfully."""


@dataclass(frozen=True)
class SuiteInventory:
    suite: str
    user_tasks: tuple[str, ...]
    injection_tasks: tuple[str, ...]

    @property
    def benign_rows(self) -> int:
        return len(self.user_tasks)

    @property
    def attack_rows(self) -> int:
        return len(self.user_tasks) * len(self.injection_tasks)


@dataclass(frozen=True)
class RowSelection:
    benchmark_version: str
    selection: str
    seed: int
    attack_rows: tuple[tuple[str, str, str], ...]
    benign_rows: tuple[tuple[str, str], ...]

    def to_json_dict(self) -> dict:
        return {
            "benchmark_version": self.benchmark_version,
            "selection": self.selection,
            "seed": self.seed,
            "attack_rows": [
                {"suite": suite, "user_task_id": user, "injection_task_id": injection}
                for suite, user, injection in self.attack_rows
            ],
            "benign_rows": [
                {"suite": suite, "user_task_id": user}
                for suite, user in self.benign_rows
            ],
        }


def _stable_order(parts: Iterable[str], seed: int) -> str:
    value = "\0".join((str(seed), *parts)).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _largest_remainder(capacities: Mapping[str, int], total: int) -> dict[str, int]:
    capacity_sum = sum(capacities.values())
    if total < 0 or total > capacity_sum:
        raise ValueError(f"requested {total} rows, capacity is {capacity_sum}")
    if capacity_sum == 0:
        return {key: 0 for key in capacities}
    exact = {key: total * value / capacity_sum for key, value in capacities.items()}
    assigned = {key: min(capacities[key], int(exact[key])) for key in capacities}
    remaining = total - sum(assigned.values())
    order = sorted(
        capacities,
        key=lambda key: (-(exact[key] - int(exact[key])), SUITES.index(key)),
    )
    while remaining:
        progressed = False
        for key in order:
            if assigned[key] < capacities[key]:
                assigned[key] += 1
                remaining -= 1
                progressed = True
                if remaining == 0:
                    break
        if not progressed:
            raise AssertionError("allocation did not converge")
    return assigned


def select_rows(
    inventories: Sequence[SuiteInventory],
    selection: str,
    *,
    seed: int = 3179,
    pilot_attack_rows: int = 100,
    pilot_benign_rows: int = 20,
) -> RowSelection:
    """Create an exact, deterministic, suite-stratified row manifest."""

    by_suite = {item.suite: item for item in inventories}
    missing = set(SUITES) - set(by_suite)
    if missing:
        raise ValueError(f"missing suites: {sorted(missing)}")
    if selection not in {"pilot", "full"}:
        raise ValueError("selection must be 'pilot' or 'full'")

    attack_capacity = {suite: by_suite[suite].attack_rows for suite in SUITES}
    benign_capacity = {suite: by_suite[suite].benign_rows for suite in SUITES}
    if selection == "full":
        attack_quota = attack_capacity
        benign_quota = benign_capacity
    else:
        attack_quota = _largest_remainder(attack_capacity, pilot_attack_rows)
        benign_quota = _largest_remainder(benign_capacity, pilot_benign_rows)

    selected_attack: list[tuple[str, str, str]] = []
    selected_benign: list[tuple[str, str]] = []
    for suite in SUITES:
        inventory = by_suite[suite]
        candidates = [
            (suite, user, injection)
            for user in inventory.user_tasks
            for injection in inventory.injection_tasks
        ]
        candidates.sort(key=lambda row: _stable_order(row, seed))
        selected_attack.extend(candidates[: attack_quota[suite]])

        benign = [(suite, user) for user in inventory.user_tasks]
        benign.sort(key=lambda row: _stable_order(row, seed))
        selected_benign.extend(benign[: benign_quota[suite]])

    return RowSelection(
        benchmark_version=BENCHMARK_VERSION,
        selection=selection,
        seed=seed,
        attack_rows=tuple(selected_attack),
        benign_rows=tuple(selected_benign),
    )


def group_attack_rows(
    rows: Sequence[tuple[str, str, str]],
) -> dict[str, dict[str, tuple[str, ...]]]:
    """Group exact pairs by suite and user without introducing a Cartesian product."""

    grouped: dict[str, dict[str, list[str]]] = {}
    for suite, user, injection in rows:
        grouped.setdefault(suite, {}).setdefault(user, []).append(injection)
    return {
        suite: {user: tuple(injections) for user, injections in users.items()}
        for suite, users in grouped.items()
    }


def group_benign_rows(rows: Sequence[tuple[str, str]]) -> dict[str, tuple[str, ...]]:
    grouped: dict[str, list[str]] = {}
    for suite, user in rows:
        grouped.setdefault(suite, []).append(user)
    return {suite: tuple(users) for suite, users in grouped.items()}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_fingerprints(source_paths: Mapping[str, Path]) -> dict[str, dict[str, str]]:
    fingerprints: dict[str, dict[str, str]] = {}
    for name, raw_path in sorted(source_paths.items()):
        path = raw_path.expanduser().resolve()
        if not path.is_file():
            raise ManifestContractError(f"source file is missing: {name}={path}")
        fingerprints[str(name)] = {
            "path": str(path),
            "sha256": sha256_file(path),
        }
    return fingerprints


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(dict(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestContractError(
            f"manifest is missing: {path}; run plan in a fresh output directory"
        ) from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestContractError(f"manifest is unreadable: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ManifestContractError(f"manifest root is not an object: {path}")
    return payload


def load_manifest_contract(
    path: Path,
    *,
    runner: str,
    source_paths: Mapping[str, Path],
    configuration: Mapping[str, object],
    selection: str,
    seed: int,
) -> dict[str, Any]:
    """Load an existing manifest and fail closed on provenance/config drift."""

    payload = _read_manifest(path)
    mismatches: list[str] = []
    if payload.get("runner") != runner:
        mismatches.append(
            f"runner expected {runner!r}, found {payload.get('runner')!r}"
        )

    recorded_sources = payload.get("sources")
    current_sources = source_fingerprints(source_paths)
    if not isinstance(recorded_sources, dict):
        mismatches.append(
            "source fingerprints are absent (legacy manifests require an explicit "
            "migration or a fresh output directory)"
        )
    else:
        for name, current in current_sources.items():
            recorded = recorded_sources.get(name)
            if not isinstance(recorded, dict):
                mismatches.append(f"source {name!r} is absent")
                continue
            if str(recorded.get("path") or "") != current["path"]:
                mismatches.append(
                    f"source {name!r} path changed: "
                    f"{recorded.get('path')!r} != {current['path']!r}"
                )
            if str(recorded.get("sha256") or "") != current["sha256"]:
                mismatches.append(f"source {name!r} sha256 changed")

    recorded_configuration = payload.get("configuration")
    if not isinstance(recorded_configuration, dict):
        mismatches.append("configuration is absent")
    else:
        for key, expected in configuration.items():
            actual = recorded_configuration.get(key)
            if actual != expected:
                mismatches.append(
                    f"configuration.{key} expected {expected!r}, found {actual!r}"
                )

    rows = payload.get("rows")
    if not isinstance(rows, dict):
        mismatches.append("rows contract is absent")
    else:
        if rows.get("selection") != selection:
            mismatches.append(
                f"rows.selection expected {selection!r}, "
                f"found {rows.get('selection')!r}"
            )
        if rows.get("seed") != seed:
            mismatches.append(
                f"rows.seed expected {seed!r}, found {rows.get('seed')!r}"
            )
        attack_rows = rows.get("attack_rows")
        benign_rows = rows.get("benign_rows")
        if not isinstance(attack_rows, list) or not isinstance(benign_rows, list):
            mismatches.append("rows.attack_rows/benign_rows are not lists")
        else:
            attack_ids = [
                (
                    row.get("suite"),
                    row.get("user_task_id"),
                    row.get("injection_task_id"),
                )
                for row in attack_rows
                if isinstance(row, dict)
            ]
            benign_ids = [
                (row.get("suite"), row.get("user_task_id"))
                for row in benign_rows
                if isinstance(row, dict)
            ]
            if len(attack_ids) != len(attack_rows) or len(set(attack_ids)) != len(
                attack_ids
            ):
                mismatches.append(
                    "rows.attack_rows contains malformed or duplicate rows"
                )
            if len(benign_ids) != len(benign_rows) or len(set(benign_ids)) != len(
                benign_ids
            ):
                mismatches.append(
                    "rows.benign_rows contains malformed or duplicate rows"
                )

    if mismatches:
        details = "; ".join(mismatches)
        raise ManifestContractError(
            f"manifest contract mismatch for {path}: {details}. "
            "Do not resume this output directory."
        )
    return payload


def assert_manifest_rows(
    payload: Mapping[str, Any],
    expected: RowSelection,
) -> None:
    recorded = payload.get("rows")
    frozen = expected.to_json_dict()
    if recorded != frozen:
        raise ManifestContractError(
            "manifest row contract does not match the deterministic current "
            "inventory/selection; do not resume this output directory"
        )


def migrate_legacy_manifest_sources(
    path: Path,
    *,
    runner: str,
    source_paths: Mapping[str, Path],
    configuration: Mapping[str, object],
    selection: str,
    seed: int,
    note: str,
) -> dict[str, Any]:
    """Explicitly add provenance to a legacy manifest without touching raw logs."""

    note = str(note or "").strip()
    if not note:
        raise ManifestContractError(
            "legacy manifest migration requires a non-empty note"
        )
    payload = _read_manifest(path)
    if payload.get("sources") is not None:
        raise ManifestContractError(
            "manifest already has source fingerprints; migration is not allowed"
        )
    if payload.get("runner") != runner:
        raise ManifestContractError(
            f"legacy manifest runner mismatch: {payload.get('runner')!r}"
        )
    recorded_configuration = payload.get("configuration")
    if not isinstance(recorded_configuration, dict):
        raise ManifestContractError("legacy manifest configuration is absent")
    for key, expected in configuration.items():
        if recorded_configuration.get(key) != expected:
            raise ManifestContractError(f"legacy manifest configuration.{key} mismatch")
    rows = payload.get("rows")
    if (
        not isinstance(rows, dict)
        or rows.get("selection") != selection
        or rows.get("seed") != seed
    ):
        raise ManifestContractError("legacy manifest selection/seed mismatch")

    original_sha256 = sha256_file(path)
    payload["sources"] = source_fingerprints(source_paths)
    payload["source_migration"] = {
        "kind": "explicit_legacy_source_migration",
        "migrated_at": datetime.now(timezone.utc).isoformat(),
        "original_manifest_sha256": original_sha256,
        "note": note,
        "raw_logs_modified": False,
    }
    _atomic_json(path, payload)
    return load_manifest_contract(
        path,
        runner=runner,
        source_paths=source_paths,
        configuration=configuration,
        selection=selection,
        seed=seed,
    )


def write_manifest(
    path: Path,
    *,
    runner: str,
    upstream: Mapping[str, str],
    inventories: Sequence[SuiteInventory],
    rows: RowSelection,
    configuration: Mapping[str, object],
    source_paths: Mapping[str, Path],
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "runner": runner,
        "upstream": dict(upstream),
        "inventories": [asdict(item) for item in inventories],
        "rows": rows.to_json_dict(),
        "configuration": dict(configuration),
        "sources": source_fingerprints(source_paths),
    }
    if path.exists():
        existing = _read_manifest(path)
        if existing != payload:
            raise ManifestContractError(
                f"refusing to overwrite a non-identical manifest: {path}; "
                "use a fresh output directory"
            )
        return existing
    _atomic_json(path, payload)
    return payload


def read_task_result(path: Path) -> dict | None:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    required = {"suite_name", "user_task_id"}
    return value if isinstance(value, dict) and required.issubset(value) else None


def _result_contract_error(
    record: Mapping[str, object],
    *,
    attacked: bool,
    suite: str,
    user: str,
    injection: str | None,
) -> str | None:
    expected_identity = {
        "suite_name": suite,
        "user_task_id": user,
        "injection_task_id": injection,
    }
    for key, expected in expected_identity.items():
        if record.get(key) != expected:
            return (
                f"IncompleteResult: {key} expected {expected!r}, "
                f"found {record.get(key)!r}"
            )
    if "error" not in record:
        return "IncompleteResult: missing error field"
    if record.get("error") is not None:
        return str(record.get("error"))
    if not isinstance(record.get("utility"), bool):
        return "IncompleteResult: utility must be boolean"
    if attacked and not isinstance(record.get("security"), bool):
        return "IncompleteResult: security must be boolean for attack rows"
    return None


def summarize_result_tree(
    log_root: Path,
    pipeline_name: str,
    expected: RowSelection,
) -> dict:
    """Summarize exact expected rows from AgentDojo's native JSON artifacts."""

    attack_records = []
    benign_records = []
    missing_attack = []
    missing_benign = []
    invalid_attack = []
    invalid_benign = []
    valid_attack_records = []
    valid_benign_records = []

    for suite, user, injection in expected.attack_rows:
        path = log_root / pipeline_name / suite / user / ATTACK / f"{injection}.json"
        record = read_task_result(path)
        if record is None:
            missing_attack.append(str(path))
        else:
            contract_error = _result_contract_error(
                record,
                attacked=True,
                suite=suite,
                user=user,
                injection=injection,
            )
            if contract_error is not None:
                invalid_attack.append({"path": str(path), "reason": contract_error})
            else:
                valid_attack_records.append(record)
            attack_records.append(record)

    for suite, user in expected.benign_rows:
        path = log_root / pipeline_name / suite / user / "none" / "none.json"
        record = read_task_result(path)
        if record is None:
            missing_benign.append(str(path))
        else:
            contract_error = _result_contract_error(
                record,
                attacked=False,
                suite=suite,
                user=user,
                injection=None,
            )
            if contract_error is not None:
                invalid_benign.append({"path": str(path), "reason": contract_error})
            else:
                valid_benign_records.append(record)
            benign_records.append(record)

    def counts(
        records: Sequence[dict],
        valid_records: Sequence[dict],
        attacked: bool,
    ) -> dict:
        result: dict[str, dict[str, int]] = {}
        for suite in SUITES:
            suite_rows = [row for row in records if row.get("suite_name") == suite]
            valid_rows = [
                row for row in valid_records if row.get("suite_name") == suite
            ]
            task_errors = sum(row.get("error") is not None for row in suite_rows)
            entry = {
                "n": len(valid_rows),
                "observed_n": len(suite_rows),
                "utility_success": sum(bool(row.get("utility")) for row in valid_rows),
                "errors": len(suite_rows) - len(valid_rows),
                "task_errors": task_errors,
                "incomplete": len(suite_rows) - len(valid_rows) - task_errors,
            }
            if attacked:
                # AgentDojo's second scorer boolean says whether the injection
                # task itself succeeded (TaskSuite.run_task_with_pipeline_msg).
                # It is therefore attack success, not attack prevention.
                entry["attack_success"] = sum(
                    row.get("security") is True for row in valid_rows
                )
                entry["attack_blocked"] = sum(
                    row.get("security") is False for row in valid_rows
                )
            result[suite] = entry
        return result

    attack_by_suite = counts(attack_records, valid_attack_records, True)
    benign_by_suite = counts(benign_records, valid_benign_records, False)
    attack_n = len(valid_attack_records)
    benign_n = len(valid_benign_records)
    attack_success = sum(row.get("security") is True for row in valid_attack_records)
    return {
        "schema_version": 1,
        "pipeline_name": pipeline_name,
        "selection": expected.selection,
        "attack": {
            "n": attack_n,
            "observed_n": len(attack_records),
            "expected_n": len(expected.attack_rows),
            "errors": len(attack_records) - attack_n,
            "task_errors": sum(row.get("error") is not None for row in attack_records),
            "incomplete": len(invalid_attack)
            - sum(row.get("error") is not None for row in attack_records),
            "attack_success": attack_success,
            "asr": attack_success / attack_n if attack_n else None,
            "utility_success": sum(
                bool(row.get("utility")) for row in valid_attack_records
            ),
            "utility_rate": (
                sum(bool(row.get("utility")) for row in valid_attack_records) / attack_n
                if attack_n
                else None
            ),
            "by_suite": attack_by_suite,
            "missing": missing_attack,
            "invalid": invalid_attack,
        },
        "benign": {
            "n": benign_n,
            "observed_n": len(benign_records),
            "expected_n": len(expected.benign_rows),
            "errors": len(benign_records) - benign_n,
            "task_errors": sum(row.get("error") is not None for row in benign_records),
            "incomplete": len(invalid_benign)
            - sum(row.get("error") is not None for row in benign_records),
            "utility_success": sum(
                bool(row.get("utility")) for row in valid_benign_records
            ),
            "utility_rate": (
                sum(bool(row.get("utility")) for row in valid_benign_records) / benign_n
                if benign_n
                else None
            ),
            "by_suite": benign_by_suite,
            "missing": missing_benign,
            "invalid": invalid_benign,
        },
        "complete": (
            not missing_attack
            and not missing_benign
            and not invalid_attack
            and not invalid_benign
            and len(valid_attack_records) == len(attack_records)
            and len(valid_benign_records) == len(benign_records)
        ),
    }


def git_head(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def dump_summary(path: Path, summary: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def export_canonical_rows(
    path: Path,
    *,
    log_root: Path,
    pipeline_name: str,
    expected: RowSelection,
    system: str,
) -> None:
    """Export the common row schema consumed by rebuttal statistical tooling."""

    rows = []
    for suite, user, injection in expected.attack_rows:
        source = log_root / pipeline_name / suite / user / ATTACK / f"{injection}.json"
        record = read_task_result(source)
        if record is None:
            continue
        contract_error = _result_contract_error(
            record,
            attacked=True,
            suite=suite,
            user=user,
            injection=injection,
        )
        rows.append(
            {
                "system": system,
                "benchmark": f"AgentDojo-{BENCHMARK_VERSION}",
                "lane": "attack",
                "row_id": f"{suite}/{user}/{injection}",
                "suite": suite,
                "user_task_id": user,
                "injection_task_id": injection,
                "status": "error" if contract_error is not None else "ok",
                "error": contract_error,
                "utility_success": (
                    bool(record.get("utility")) if contract_error is None else None
                ),
                "attack_success": (
                    record.get("security") is True if contract_error is None else None
                ),
                "seed": expected.seed,
            }
        )
    for suite, user in expected.benign_rows:
        source = log_root / pipeline_name / suite / user / "none" / "none.json"
        record = read_task_result(source)
        if record is None:
            continue
        contract_error = _result_contract_error(
            record,
            attacked=False,
            suite=suite,
            user=user,
            injection=None,
        )
        rows.append(
            {
                "system": system,
                "benchmark": f"AgentDojo-{BENCHMARK_VERSION}",
                "lane": "benign",
                "row_id": f"{suite}/{user}/none",
                "suite": suite,
                "user_task_id": user,
                "injection_task_id": None,
                "status": "error" if contract_error is not None else "ok",
                "error": contract_error,
                "utility_success": (
                    bool(record.get("utility")) if contract_error is None else None
                ),
                "attack_success": None,
                "seed": expected.seed,
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
