"""Original field extraction, schema fallback, and value sanitization functions.

Source: rebuttal/experiments/agentleak_boundary_core.py. See SOURCES.md.
FieldObservation includes benchmark labels; schema_only_predictions ignores them.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class FieldObservation:
    field_id: str
    record_index: int
    record_type: str
    path: str
    top_field: str
    leaf_field: str
    value: str
    value_type: str
    field_class: str
    ground_truth_protected: bool


_HIGH_RISK_MARKERS = {
    "ssn",
    "social",
    "security",
    "tax",
    "account",
    "routing",
    "credit",
    "card",
    "balance",
    "salary",
    "income",
    "compensation",
    "settlement",
    "retainer",
    "diagnosis",
    "medical",
    "medication",
    "allerg",
    "confidential",
    "private",
    "privileged",
    "strategy",
    "evidence",
    "risk",
    "performance",
    "disciplinary",
    "manager_note",
    "background",
    "criminal",
    "password",
    "secret",
    "token",
    "canary",
    "phone",
    "dob",
    "birth",
    "insurance",
}


_SCHEMA_SAFE_MARKERS = {
    "record_type",
    "transaction_count",
}


def _normalize_name(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")
    value = re.sub(r"_(real|value|raw|full)$", "", value)
    return value


def _name_matches(candidate: str, marker: str) -> bool:
    candidate_n = _normalize_name(candidate)
    marker_n = _normalize_name(marker)
    if not candidate_n or not marker_n:
        return False
    if candidate_n == marker_n:
        return True
    candidate_parts = set(candidate_n.split("_"))
    marker_parts = marker_n.split("_")
    if all(part in candidate_parts for part in marker_parts):
        return True
    return marker_n in candidate_n


def _safe_name_matches(candidate: str, marker: str) -> bool:
    """Exact-token schema-safe matching.

    Safe markers should not use substring semantics: marker ``date`` matching
    ``candidate_name`` is an under-conservative detector bug for this rebuttal
    experiment.  The schema-only detector is intended to be conservative, so a
    field is considered schema-safe only when the marker is represented by
    whole normalized path tokens.
    """

    candidate_n = _normalize_name(candidate)
    marker_n = _normalize_name(marker)
    if not candidate_n or not marker_n:
        return False
    if candidate_n == marker_n:
        return True
    candidate_parts = candidate_n.split("_")
    marker_parts = marker_n.split("_")
    width = len(marker_parts)
    if width == 0 or width > len(candidate_parts):
        return False
    return any(
        candidate_parts[index : index + width] == marker_parts
        for index in range(0, len(candidate_parts) - width + 1)
    )


def _value_type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ][^\s]+)?", value.strip()):
            return "date"
        return "text"
    return type(value).__name__.lower()


def classify_field(path: str) -> str:
    low = _normalize_name(path)
    if any(
        marker in low
        for marker in (
            "password",
            "secret",
            "token",
            "api_key",
            "ssn",
            "account_number",
            "routing",
            "credit_card",
            "insurance_id",
            "canary",
        )
    ):
        return "credentials_identifiers"
    if any(
        marker in low
        for marker in (
            "balance",
            "salary",
            "income",
            "credit_score",
            "settlement",
            "retainer",
            "compensation",
            "bonus",
            "stock",
            "amount",
        )
    ):
        return "financial"
    if any(
        marker in low
        for marker in (
            "diagnosis",
            "medical",
            "medication",
            "allerg",
            "treatment",
            "insurance",
        )
    ):
        return "health"
    if any(
        marker in low
        for marker in (
            "name",
            "email",
            "phone",
            "dob",
            "birth",
            "address",
            "employee_id",
            "witness",
        )
    ):
        return "identity_contact"
    if any(
        marker in low
        for marker in (
            "note",
            "strategy",
            "evidence",
            "history",
            "performance",
            "disciplinary",
            "risk",
            "internal",
            "background",
            "criminal",
        )
    ):
        return "private_text"
    return "other"


def _iter_leaves(value: Any, path: tuple[str, ...]) -> Iterable[tuple[tuple[str, ...], Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _iter_leaves(child, (*path, str(key)))
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            yield from _iter_leaves(child, (*path, str(index)))
        return
    if value is not None:
        yield path, value


def extract_field_observations(scenario: Any) -> list[FieldObservation]:
    allowed = [
        str(item)
        for item in getattr(getattr(scenario, "allowed_set", None), "fields", [])
    ]
    forbidden = [
        str(item)
        for item in getattr(getattr(scenario, "allowed_set", None), "forbidden_fields", [])
    ]
    records = list(getattr(getattr(scenario, "private_vault", None), "records", []) or [])
    out: list[FieldObservation] = []
    for record_index, record in enumerate(records):
        record_type = str(getattr(record, "record_type", "record") or "record")
        fields = getattr(record, "fields", None)
        if not isinstance(fields, Mapping):
            continue
        for top_field, raw_value in fields.items():
            top = str(top_field)
            for leaf_path, leaf_value in _iter_leaves(raw_value, (top,)):
                leaf_name = next(
                    (part for part in reversed(leaf_path) if not part.isdigit()),
                    top,
                )
                path = ".".join((f"record[{record_index}]", *leaf_path))
                allowed_match = any(
                    _name_matches(leaf_name, marker)
                    or _name_matches(top, marker)
                    for marker in allowed
                )
                forbidden_match = any(
                    _name_matches(leaf_name, marker)
                    or _name_matches(top, marker)
                    for marker in forbidden
                )
                protected = bool(forbidden_match or not allowed_match)
                value = (
                    json.dumps(leaf_value, ensure_ascii=False, sort_keys=True)
                    if isinstance(leaf_value, (dict, list))
                    else str(leaf_value)
                )
                out.append(
                    FieldObservation(
                        field_id=f"r{record_index}:{'.'.join(leaf_path)}",
                        record_index=record_index,
                        record_type=record_type,
                        path=path,
                        top_field=top,
                        leaf_field=leaf_name,
                        value=value,
                        value_type=_value_type(leaf_value),
                        field_class=classify_field(f"{top}.{leaf_name}"),
                        ground_truth_protected=protected,
                    )
                )
    return out


def oracle_predictions(observations: Sequence[FieldObservation]) -> set[str]:
    return {
        observation.field_id
        for observation in observations
        if observation.ground_truth_protected
    }


def schema_only_predictions(observations: Sequence[FieldObservation]) -> set[str]:
    """Conservative value-blind detector based only on field path and type."""

    predicted: set[str] = set()
    for observation in observations:
        path = _normalize_name(
            f"{observation.record_type}_{observation.top_field}_{observation.leaf_field}"
        )
        parts = set(path.split("_"))
        if any(marker in path for marker in _HIGH_RISK_MARKERS):
            predicted.add(observation.field_id)
            continue
        if any(_safe_name_matches(path, marker) for marker in _SCHEMA_SAFE_MARKERS):
            continue
        # Unknown schema fields are protected by default. This is deliberately
        # conservative and is expected to trade precision for recall.
        if observation.value_type in {"text", "number", "date"} and parts:
            predicted.add(observation.field_id)
    return predicted


def _replace_value(text: str, value: str, replacement: str) -> tuple[str, bool]:
    if not value or len(value.strip()) < 3:
        return text, False
    escaped = re.escape(value.strip())
    if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", value.strip()):
        pattern = re.compile(rf"(?<![\w.]){escaped}(?!(?:\w|\.\d))")
    else:
        pattern = re.compile(escaped, flags=re.IGNORECASE)
    replaced, count = pattern.subn(replacement, text)
    return replaced, bool(count)


def sanitize_predicted_values(
    text: str,
    observations: Sequence[FieldObservation],
    predicted: set[str],
) -> tuple[str, dict[str, Any]]:
    out = str(text or "")
    hits: list[str] = []
    candidates = [
        observation
        for observation in observations
        if observation.field_id in predicted
    ]
    candidates.sort(key=lambda observation: (-len(observation.value), observation.field_id))
    seen_values: set[str] = set()
    for observation in candidates:
        value_key = observation.value.casefold()
        if value_key in seen_values:
            continue
        seen_values.add(value_key)
        out, hit = _replace_value(out, observation.value, "[PROTECTED_VALUE]")
        if hit:
            hits.append(observation.field_id)
    return out, {"redacted_field_ids": hits, "redaction_count": len(hits)}
