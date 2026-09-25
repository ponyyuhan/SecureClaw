"""Original value-free schema interface and AgentLeak vault adaptation.

Source: rebuttal/experiments/agentleak_parity_core.py. See SOURCES.md.
ConservativeSchemaDetector is distinct from boundary_fields.schema_only_predictions.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol, Sequence


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def normalized_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


@dataclass(frozen=True)
class SchemaField:
    """Value-free input contract for a protected-field detector.

    Deliberately absent are the field value and AgentLeak's allowed/forbidden
    annotations.  A detector implementing :class:`SchemaDetector` therefore
    cannot inspect the value or benchmark ground truth through this interface.
    """

    field_id: str
    record_type: str
    path: str
    top_field: str
    leaf_field: str
    value_type: str


class SchemaDetector(Protocol):
    detector_id: str

    def predict(self, fields: Sequence[SchemaField]) -> set[str]:
        """Return protected field IDs using only value-free schema metadata."""


_HIGH_RISK_MARKERS: tuple[str, ...] = (
    "ssn",
    "social_security",
    "tax_id",
    "account_number",
    "routing_number",
    "credit_card",
    "card_number",
    "balance",
    "credit_score",
    "salary",
    "annual_income",
    "current_salary",
    "expected_salary",
    "retainer_amount",
    "settlement_amount",
    "diagnosis",
    "medical_history",
    "medication",
    "allergy",
    "confidential",
    "private",
    "privileged",
    "strategy",
    "internal_notes",
    "criminal_history",
    "background_check",
    "performance_notes",
    "disciplinary",
    "password",
    "pin",
    "secret",
    "api_key",
    "token",
    "canary",
    "phone",
    "date_of_birth",
    "dob",
    "insurance_id",
)


_PUBLIC_SCHEMA_MARKERS: tuple[str, ...] = (
    "record_type",
    "case_id",
    "case_number",
    "case_type",
    "dispute_id",
    "account_last4",
    "visit_date",
    "hire_date",
    "department",
    "transaction_count",
    "merchant",
    "status",
    "date",
)


def _marker_matches(name: str, marker: str) -> bool:
    name_norm = normalized_name(name)
    marker_norm = normalized_name(marker)
    if not name_norm or not marker_norm:
        return False
    if name_norm == marker_norm or marker_norm in name_norm:
        return True
    name_parts = set(name_norm.split("_"))
    return all(part in name_parts for part in marker_norm.split("_"))


@dataclass(frozen=True)
class ConservativeSchemaDetector:
    """Frozen, deterministic, value-blind schema classifier.

    Unknown scalar fields default to protected.  This intentionally favors
    recall over precision and is expected to expose the utility cost of false
    positives rather than using AgentLeak labels as an oracle.
    """

    detector_id: str = "schema_conservative_v1"

    def predict(self, fields: Sequence[SchemaField]) -> set[str]:
        predicted: set[str] = set()
        for field in fields:
            joined = normalized_name(
                f"{field.record_type}_{field.top_field}_{field.leaf_field}"
            )
            if any(_marker_matches(joined, marker) for marker in _HIGH_RISK_MARKERS):
                predicted.add(field.field_id)
                continue
            if any(_marker_matches(joined, marker) for marker in _PUBLIC_SCHEMA_MARKERS):
                continue
            if field.value_type in {"text", "number", "date"}:
                predicted.add(field.field_id)
        return predicted


def value_free_schema_fields(observations: Sequence[Any]) -> tuple[SchemaField, ...]:
    """Project observations onto the detector's non-oracle input contract."""

    return tuple(
        SchemaField(
            field_id=str(observation.field_id),
            record_type=str(observation.record_type),
            path=str(observation.path),
            top_field=str(observation.top_field),
            leaf_field=str(observation.leaf_field),
            value_type=str(observation.value_type),
        )
        for observation in observations
    )


def oracle_protected_field_ids(observations: Sequence[Any]) -> set[str]:
    """Explicit benchmark-oracle adapter, kept separate from detector plugins."""

    return {
        str(observation.field_id)
        for observation in observations
        if bool(observation.ground_truth_protected)
    }


def _mask_value(
    value: Any,
    *,
    record_index: int,
    path: tuple[str, ...],
    predicted_ids: set[str],
    observation_by_id: dict[str, Any],
) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _mask_value(
                child,
                record_index=record_index,
                path=(*path, str(key)),
                predicted_ids=predicted_ids,
                observation_by_id=observation_by_id,
            )
            for key, child in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [
            _mask_value(
                child,
                record_index=record_index,
                path=(*path, str(index)),
                predicted_ids=predicted_ids,
                observation_by_id=observation_by_id,
            )
            for index, child in enumerate(value)
        ]
    field_id = f"r{record_index}:{'.'.join(path)}"
    if field_id not in predicted_ids:
        return value
    observation = observation_by_id.get(field_id)
    field_class = str(getattr(observation, "field_class", "protected") or "protected")
    value_type = str(getattr(observation, "value_type", "value") or "value")
    return f"[PROTECTED:{field_class}:{value_type}]"


def masked_flat_vault(
    scenario: Any,
    observations: Sequence[Any],
    predicted_ids: set[str],
) -> dict[str, Any]:
    """Build the parity topology's flat vault after boundary classification.

    The original parity harness flattens top-level vault fields into one mapping
    (later records overwrite repeated names).  This function preserves that
    topology while retaining structured nested values for the trusted summary
    operator to bound and alias.
    """

    observation_by_id = {
        str(observation.field_id): observation for observation in observations
    }
    records = list(
        getattr(getattr(scenario, "private_vault", None), "records", []) or []
    )
    out: dict[str, Any] = {}
    for record_index, record in enumerate(records):
        fields = getattr(record, "fields", None)
        if not isinstance(fields, dict):
            continue
        for top_field, value in fields.items():
            top = str(top_field)
            out[top] = _mask_value(
                value,
                record_index=record_index,
                path=(top,),
                predicted_ids=predicted_ids,
                observation_by_id=observation_by_id,
            )
    return out


def sensitive_registration_items(
    observations: Sequence[Any],
    predicted_ids: set[str],
) -> list[dict[str, str]]:
    """Return concrete values registered through the real gateway sanitizer."""

    items: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for observation in observations:
        field_id = str(observation.field_id)
        if field_id not in predicted_ids:
            continue
        value = str(observation.value).strip()
        if len(value) < 4:
            continue
        key = (field_id, value)
        if key in seen:
            continue
        seen.add(key)
        items.append({"field": field_id, "value": value})
    return items
