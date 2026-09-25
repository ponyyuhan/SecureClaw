"""Pure helpers for the AgentDojo accommodation counterfactual experiment.

The paid runner lives in :mod:`run_agentdojo_accommodation`.  This module is
deliberately dependency-free so that row selection, event normalization, paired
transitions, and aggregation can be regression-tested without importing the
vendored AgentDojo runtime or making network calls.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any


CONDITIONS: tuple[str, ...] = ("full", "no_alias", "no_confirm", "neither")
LANES: tuple[str, ...] = ("attacked", "benign")
SUITES: tuple[str, ...] = ("banking", "slack", "travel", "workspace")

CONDITION_SWITCHES: dict[str, dict[str, bool]] = {
    "full": {"alias_resolution": True, "auto_confirm": True},
    "no_alias": {"alias_resolution": False, "auto_confirm": True},
    "no_confirm": {"alias_resolution": True, "auto_confirm": False},
    "neither": {"alias_resolution": False, "auto_confirm": False},
}

# This is the exact task enumeration used by the submitted AgentDojo-v1.1.2
# runner in third_party/ipiguard/run/data_module.py.  Slack intentionally starts
# at injection_task_1; injection_task_0 is not part of the submitted 105 rows.
SUBMITTED_DATASET_SPEC: dict[str, dict[str, Any]] = {
    "banking": {"user_tasks": 16, "injection_start": 0, "injection_tasks": 9},
    "slack": {"user_tasks": 21, "injection_start": 1, "injection_tasks": 5},
    "travel": {"user_tasks": 20, "injection_start": 0, "injection_tasks": 7},
    "workspace": {"user_tasks": 40, "injection_start": 0, "injection_tasks": 6},
}

EXPECTED_COUNTS: dict[str, dict[str, int]] = {
    suite: {
        "attacked": int(spec["user_tasks"]) * int(spec["injection_tasks"]),
        "benign": int(spec["user_tasks"]),
    }
    for suite, spec in SUBMITTED_DATASET_SPEC.items()
}

ALIAS_TOKEN_RE = re.compile(
    r"\b(?:IBAN|EMAIL|URL|DOMAIN|TARGET|PARTY)_REF_[A-Za-z0-9_]+\b",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class Case:
    suite: str
    lane: str
    user_task_id: str
    injection_task_id: str | None

    @property
    def row_id(self) -> str:
        injection = self.injection_task_id or "none"
        return f"{self.suite}:{self.user_task_id}:{injection}"


def enumerate_submitted_cases(
    *,
    suites: Sequence[str] = SUITES,
    lanes: Sequence[str] = LANES,
) -> list[Case]:
    """Enumerate the frozen 629 attacked and 97 benign rows."""

    unknown_suites = sorted(set(suites) - set(SUITES))
    unknown_lanes = sorted(set(lanes) - set(LANES))
    if unknown_suites:
        raise ValueError(f"unknown suites: {unknown_suites}")
    if unknown_lanes:
        raise ValueError(f"unknown lanes: {unknown_lanes}")

    cases: list[Case] = []
    for suite in suites:
        spec = SUBMITTED_DATASET_SPEC[suite]
        for lane in lanes:
            for user_index in range(int(spec["user_tasks"])):
                user_task_id = f"user_task_{user_index}"
                if lane == "benign":
                    cases.append(Case(suite, lane, user_task_id, None))
                    continue
                start = int(spec["injection_start"])
                stop = start + int(spec["injection_tasks"])
                for injection_index in range(start, stop):
                    cases.append(
                        Case(
                            suite,
                            lane,
                            user_task_id,
                            f"injection_task_{injection_index}",
                        )
                    )
    return cases


def stable_json_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def alias_tokens(value: Any) -> list[str]:
    """Return ordered, de-duplicated alias tokens found in a JSON-like value."""

    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    out: list[str] = []
    seen: set[str] = set()
    for match in ALIAS_TOKEN_RE.finditer(text):
        token = match.group(0)
        folded = token.casefold()
        if folded not in seen:
            seen.add(folded)
            out.append(token)
    return out


def event_summary(ledger: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize the executor ledger into reviewer-facing row counters."""

    ledger = ledger if isinstance(ledger, Mapping) else {}
    registrations = [
        dict(item)
        for item in ledger.get("alias_registrations", [])
        if isinstance(item, Mapping)
    ]
    arguments = [
        dict(item)
        for item in ledger.get("alias_arguments", [])
        if isinstance(item, Mapping)
    ]
    policy_requests = [
        dict(item)
        for item in ledger.get("policy_requests", [])
        if isinstance(item, Mapping)
    ]

    tokens = {
        str(event.get("token") or "").casefold()
        for event in registrations
        if str(event.get("token") or "").strip()
    }
    encountered = sum(int(event.get("occurrences") or 1) for event in arguments)
    succeeded = sum(
        int(event.get("occurrences") or 1)
        for event in arguments
        if bool(event.get("resolved"))
    )
    failed = encountered - succeeded
    required = sum(bool(event.get("confirmation_required")) for event in policy_requests)
    flag_set = sum(bool(event.get("auto_confirmation_flag")) for event in policy_requests)
    issued = sum(bool(event.get("auto_confirmation_issued")) for event in policy_requests)
    allowed = sum(bool(event.get("policy_allowed")) for event in policy_requests)
    denied = len(policy_requests) - allowed
    denied_executed = sum(
        bool(event.get("denied_action_executed")) for event in policy_requests
    )
    denied_bug = sum(
        bool(event.get("denied_auto_confirm_bug")) for event in policy_requests
    )
    denied_tokens = sum(
        int(event.get("denied_auto_confirm_tokens") or 0)
        for event in policy_requests
    )

    return {
        # Scalars duplicated at top-level by the runner for the generic analyzer.
        "alias_fired": bool(registrations or arguments),
        "alias_tokens_emitted": len(tokens),
        "alias_event_count": len(registrations),
        "alias_arguments_encountered": encountered,
        "alias_resolutions_succeeded": succeeded,
        "alias_resolutions_failed": failed,
        "confirm_fired": bool(issued),
        "confirmation_required": bool(required),
        "confirmation_requests": required,
        "auto_confirmation_flag_count": flag_set,
        "auto_confirmation_issued": bool(issued),
        "auto_confirm_count": issued,
        "policy_request_count": len(policy_requests),
        "policy_allowed_count": allowed,
        "policy_denied_count": denied,
        "denied_action_executed": bool(denied_executed),
        "denied_auto_confirm_bug": bool(denied_bug),
        "denied_auto_confirm_bug_count": denied_bug,
        "denied_auto_confirm_tokens": denied_tokens,
        "alias": {
            "fired": bool(registrations or arguments),
            "tokens_emitted": len(tokens),
            "registration_events": len(registrations),
            "arguments_encountered": encountered,
            "resolutions_succeeded": succeeded,
            "resolutions_failed": failed,
            "events": registrations,
            "argument_events": arguments,
        },
        "confirmation": {
            "fired": bool(issued),
            "policy_requests": len(policy_requests),
            "required": required,
            "auto_confirmation_flags": flag_set,
            "auto_confirmation_issued": issued,
            "policy_allowed": allowed,
            "policy_denied": denied,
            "denied_action_executed": denied_executed,
            "denied_auto_confirm_bug": denied_bug,
            "denied_auto_confirm_tokens": denied_tokens,
            "events": policy_requests,
        },
    }


def _row_key(row: Mapping[str, Any]) -> tuple[str, str, str, int]:
    return (
        str(row.get("condition") or row.get("config_id") or ""),
        str(row.get("suite") or ""),
        str(row.get("row_id") or ""),
        int(row.get("seed") or 0),
    )


def latest_rows(rows: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str, str, int], dict[str, Any]]:
    """Last-write-wins view of an append-only result stream."""

    out: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        key = _row_key(row)
        if not all(key[:3]):
            continue
        out[key] = dict(row)
    return out


def build_transitions(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Build paired four-condition outcomes without imputing missing rows."""

    latest = latest_rows(rows)
    grouped: dict[tuple[str, str, str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
    for (condition, suite, row_id, seed), row in latest.items():
        lane = str(row.get("lane") or "")
        grouped[(suite, lane, row_id, seed)][condition] = row

    transitions: list[dict[str, Any]] = []
    for (suite, lane, row_id, seed), condition_rows in sorted(grouped.items()):
        if "full" not in condition_rows:
            continue
        full = condition_rows["full"]
        outcomes: dict[str, Any] = {}
        for condition in CONDITIONS:
            row = condition_rows.get(condition)
            outcomes[condition] = (
                {
                    "utility": bool(row.get("utility")),
                    "attack_success": bool(row.get("attack_success")),
                    "status": str(row.get("status") or ""),
                }
                if row is not None and not row.get("error")
                else None
            )

        full_utility = bool(full.get("utility"))
        full_attack = bool(full.get("attack_success"))

        def lost_utility(condition: str) -> bool | None:
            outcome = outcomes.get(condition)
            if outcome is None:
                return None
            return bool(full_utility and not outcome["utility"])

        def security_flip(condition: str) -> bool | None:
            outcome = outcomes.get(condition)
            if outcome is None:
                return None
            return bool(full_attack != outcome["attack_success"])

        no_confirm = condition_rows.get("no_confirm")
        confirm_required_counterfactual = bool(
            no_confirm
            and (
                no_confirm.get("confirmation_required")
                or int(no_confirm.get("confirmation_requests") or 0) > 0
            )
        )
        # A hosted-model rerun can disagree even when the removed mechanism
        # never participated in the full trace. Such discordance is useful for
        # the nondeterminism audit but is not causal evidence that an
        # accommodation was essential.
        alias_applied = int(full.get("alias_resolutions_succeeded") or 0) > 0
        confirm_applied = bool(
            full.get("confirm_fired") or confirm_required_counterfactual
        )
        raw_alias_loss = lost_utility("no_alias")
        raw_confirm_loss = lost_utility("no_confirm")
        raw_neither_loss = lost_utility("neither")
        raw_security_no_alias = security_flip("no_alias")
        raw_security_no_confirm = security_flip("no_confirm")
        raw_security_neither = security_flip("neither")

        def attributable(
            raw_value: bool | None,
            mechanism_applied: bool,
        ) -> bool | None:
            if raw_value is None:
                return None
            return bool(mechanism_applied and raw_value)

        transition = {
            "benchmark": "AgentDojo",
            "suite": suite,
            "lane": lane,
            "row_id": row_id,
            "seed": seed,
            "complete": all(outcomes.get(condition) is not None for condition in CONDITIONS),
            "conditions": outcomes,
            "full_utility": full_utility,
            "full_attack_success": full_attack,
            "alias_fired": bool(full.get("alias_fired")),
            "alias_applied": alias_applied,
            "confirm_fired": confirm_applied,
            "raw_utility_loss_no_alias": raw_alias_loss,
            "raw_utility_loss_no_confirm": raw_confirm_loss,
            "raw_utility_loss_neither": raw_neither_loss,
            "alias_essential": attributable(raw_alias_loss, alias_applied),
            "confirm_essential": attributable(
                raw_confirm_loss, confirm_applied
            ),
            "neither_essential": attributable(
                raw_neither_loss, alias_applied or confirm_applied
            ),
            "raw_security_flip_no_alias": raw_security_no_alias,
            "raw_security_flip_no_confirm": raw_security_no_confirm,
            "raw_security_flip_neither": raw_security_neither,
            "security_flip_no_alias": attributable(
                raw_security_no_alias, alias_applied
            ),
            "security_flip_no_confirm": attributable(
                raw_security_no_confirm, confirm_applied
            ),
            "security_flip_neither": attributable(
                raw_security_neither, alias_applied or confirm_applied
            ),
        }
        transitions.append(transition)
    return transitions


def _rate(count: int, total: int) -> float | None:
    return count / total if total else None


def summarize_rows(
    rows: Iterable[Mapping[str, Any]],
    transitions: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate counts only; confidence intervals live in the shared analyzer."""

    valid = [
        row
        for row in latest_rows(rows).values()
        if not row.get("error") and str(row.get("status") or "ok").lower() in {"ok", "success"}
    ]
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in valid:
        grouped[
            (
                str(row.get("suite") or ""),
                str(row.get("lane") or ""),
                str(row.get("condition") or row.get("config_id") or ""),
            )
        ].append(row)

    tables: dict[str, Any] = {}
    for suite in SUITES:
        suite_table: dict[str, Any] = {}
        for lane in LANES:
            condition_table: dict[str, Any] = {}
            for condition in CONDITIONS:
                condition_rows = grouped.get((suite, lane, condition), [])
                n = len(condition_rows)
                util = sum(bool(row.get("utility")) for row in condition_rows)
                attacks = sum(
                    bool(row.get("attack_success")) for row in condition_rows
                )
                condition_table[condition] = {
                    "n": n,
                    "utility_success": util,
                    "utility_rate": _rate(util, n),
                    "attack_success": attacks,
                    "attack_success_rate": _rate(attacks, n),
                    "alias_fired": sum(
                        bool(row.get("alias_fired")) for row in condition_rows
                    ),
                    "confirm_fired": sum(
                        bool(row.get("confirm_fired")) for row in condition_rows
                    ),
                    "denied_auto_confirm_bug": sum(
                        bool(row.get("denied_auto_confirm_bug"))
                        for row in condition_rows
                    ),
                }
            suite_table[lane] = condition_table
        tables[suite] = suite_table

    paired = list(transitions if transitions is not None else build_transitions(valid))
    dependency: dict[str, Any] = {}
    for suite in SUITES:
        dependency[suite] = {}
        for lane in LANES:
            subset = [
                row
                for row in paired
                if row.get("suite") == suite and row.get("lane") == lane
            ]
            successes = [row for row in subset if bool(row.get("full_utility"))]
            dependency[suite][lane] = {
                "paired_rows": len(subset),
                "complete_paired_rows": sum(bool(row.get("complete")) for row in subset),
                "full_utility_successes": len(successes),
                "alias_essential": sum(
                    row.get("alias_essential") is True for row in successes
                ),
                "confirm_essential": sum(
                    row.get("confirm_essential") is True for row in successes
                ),
                "neither_essential": sum(
                    row.get("neither_essential") is True for row in successes
                ),
                "raw_utility_loss_no_alias": sum(
                    row.get("raw_utility_loss_no_alias") is True
                    for row in successes
                ),
                "raw_utility_loss_no_confirm": sum(
                    row.get("raw_utility_loss_no_confirm") is True
                    for row in successes
                ),
                "raw_utility_loss_neither": sum(
                    row.get("raw_utility_loss_neither") is True
                    for row in successes
                ),
                "security_flip_no_alias": sum(
                    row.get("security_flip_no_alias") is True for row in subset
                ),
                "security_flip_no_confirm": sum(
                    row.get("security_flip_no_confirm") is True for row in subset
                ),
                "security_flip_neither": sum(
                    row.get("security_flip_neither") is True for row in subset
                ),
            }

    return {
        "schema_version": 1,
        "valid_latest_rows": len(valid),
        "expected_rows_per_condition": sum(
            value[lane] for value in EXPECTED_COUNTS.values() for lane in LANES
        ),
        "by_suite_lane_condition": tables,
        "paired_dependency": dependency,
    }


def assert_finite_numbers(value: Any) -> None:
    """Raise on NaN/Inf before writing evidence JSON."""

    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"non-finite result: {value!r}")
    if isinstance(value, Mapping):
        for nested in value.values():
            assert_finite_numbers(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            assert_finite_numbers(nested)
