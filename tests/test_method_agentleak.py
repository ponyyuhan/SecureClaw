from __future__ import annotations

import os
import unittest
from dataclasses import replace
from types import SimpleNamespace as NS
from unittest.mock import patch

from method_adapters.agentleak import boundary_fields as boundary
from method_adapters.agentleak import contextual_schema as contextual
from method_adapters.agentleak import parity_fields as parity
from method_adapters.agentleak.channels import (
    SecureClawChannelMediator,
    TopologyOutputs,
    _gateway_user_visible_text,
)


def scenario() -> NS:
    return NS(
        scenario_id="synthetic-test",
        vertical="synthetic",
        objective=NS(
            user_request="Return the transaction count.",
            privacy_instruction="Only the transaction count may be released.",
        ),
        private_vault=NS(records=[NS(record_type="customer", fields={
            "account_number": "SYNTHETIC-1234",
            "transaction_count": 3,
            "notes": {"private_note": "SYNTHETIC PRIVATE NOTE"},
        })]),
        allowed_set=NS(fields=["transaction_count"], forbidden_fields=["account_number"]),
    )


class _RecordingMcp:
    def __init__(self):
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        intent = arguments["intent_id"]
        if intent == "FinalizeOutput":
            return {
                "status": "DENY", "reason_code": "POLICY_DENY",
                "summary": "Output denied.",
                "data": {"internal_policy_evidence": "SYNTHETIC PRIVATE NOTE"},
            }
        if intent in {"ReceiveInterAgentMessages", "MemoryRead"}:
            return {"status": "OK", "data": {"safe_text": "Safe channel response."}}
        return {"status": "OK", "data": {}}


class MethodAgentLeakTests(unittest.TestCase):
    def test_schema_prediction_ignores_values_and_labels(self):
        observations = boundary.extract_field_observations(scenario())
        changed = [replace(item, value="CHANGED", ground_truth_protected=not item.ground_truth_protected)
                   for item in observations]
        self.assertEqual(boundary.schema_only_predictions(observations),
                         boundary.schema_only_predictions(changed))
        self.assertEqual(parity.value_free_schema_fields(observations),
                         parity.value_free_schema_fields(changed))
        projected = parity.value_free_schema_fields(observations)
        self.assertNotIn("value", projected[0].__dataclass_fields__)
        self.assertNotIn("ground_truth_protected", projected[0].__dataclass_fields__)
        self.assertEqual(parity.ConservativeSchemaDetector().predict(projected),
                         parity.ConservativeSchemaDetector().predict(parity.value_free_schema_fields(changed)))

    def test_oracle_is_separate_and_forbidden_takes_precedence(self):
        sample = scenario()
        sample.allowed_set.fields.append("account_number")
        observations = boundary.extract_field_observations(sample)
        oracle = boundary.oracle_predictions(observations)
        self.assertIn("r0:account_number", oracle)
        self.assertNotIn("r0:transaction_count", oracle)
        self.assertEqual(oracle, parity.oracle_protected_field_ids(observations))

    def test_nested_values_are_masked_and_registered(self):
        sample = scenario()
        observations = boundary.extract_field_observations(sample)
        predicted = boundary.schema_only_predictions(observations)
        masked = parity.masked_flat_vault(sample, observations, predicted)
        self.assertNotIn("SYNTHETIC-1234", str(masked))
        self.assertNotIn("SYNTHETIC PRIVATE NOTE", str(masked))
        self.assertEqual(masked["transaction_count"], 3)
        registered = parity.sensitive_registration_items(observations, predicted)
        self.assertEqual({item["value"] for item in registered},
                         {"SYNTHETIC-1234", "SYNTHETIC PRIVATE NOTE"})

    def test_sanitizer_numeric_boundaries_do_not_redact_larger_number(self):
        original = boundary.extract_field_observations(scenario())[0]
        number = replace(original, value="1234")
        output, metadata = boundary.sanitize_predicted_values(
            "1234 and 12345", [number], {number.field_id})
        self.assertEqual(output, "[PROTECTED_VALUE] and 12345")
        self.assertEqual(metadata["redaction_count"], 1)

    def test_contextual_profile_excludes_values_and_labels(self):
        first = scenario()
        second = scenario()
        second.private_vault.records[0].fields["account_number"] = "DIFFERENT-VALUE"
        second.allowed_set.fields = ["account_number", "notes"]
        second.allowed_set.forbidden_fields = ["transaction_count"]
        profile = contextual.build_value_blind_profile(first)
        self.assertEqual(profile, contextual.build_value_blind_profile(second))
        self.assertNotIn("SYNTHETIC-1234", str(contextual._request_payload(profile)))
        self.assertNotIn("SYNTHETIC PRIVATE NOTE", str(contextual._request_payload(profile)))

    def test_classifier_requires_complete_unique_boolean_decisions(self):
        profile = contextual.build_value_blind_profile(scenario())
        valid = [{"schema_id": item["schema_id"], "protected": True,
                  "reason_code": "conservative_unknown"} for item in profile["fields"]]
        self.assertEqual(len(contextual._validate_decisions({"decisions": valid}, profile)), len(valid))
        for invalid in (valid[:-1], valid + [valid[0]], [dict(valid[0], protected="true")] + valid[1:]):
            with self.assertRaises(ValueError):
                contextual._validate_decisions({"decisions": invalid}, profile)

    def test_channel_response_omits_internal_policy_metadata(self):
        response = {"status": "DENY", "reason_code": "POLICY_DENY",
                    "data": {"internal_policy_evidence": "SYNTHETIC SECRET"}}
        visible = _gateway_user_visible_text(response, fallback="Not released.")
        self.assertNotIn("SYNTHETIC SECRET", visible)
        self.assertIn("DENY", visible)

    def test_original_channel_sequence_keeps_denial_and_registration(self):
        mcp = _RecordingMcp()
        adapter = SecureClawChannelMediator(mcp)
        outputs = TopologyOutputs("coord", "worker", "memory", "final", [])
        with patch.dict(os.environ, {"AGENTLEAK_AUTO_CONFIRM_POLICY": "never"}):
            channels, metadata = adapter.mediate(scenario=scenario(), outputs=outputs)
        self.assertEqual(channels["C1"], ["Output denied."])
        self.assertEqual(len(channels["C2"]), 2)
        self.assertEqual(len(channels["C5"]), 1)
        self.assertNotIn("SYNTHETIC PRIVATE NOTE", str(channels))
        intents = [args["intent_id"] for _, args in mcp.calls]
        self.assertEqual(intents[:2], ["ClearSessionSensitive", "RegisterSessionSensitive"])
        self.assertIn("MemoryWrite", intents)
        final = next(args for _, args in mcp.calls
                     if args["intent_id"] == "FinalizeOutput" and args["inputs"]["text"] == "final")
        self.assertNotIn("user_confirm", final["constraints"])
        self.assertEqual(metadata["statuses"]["c1_finalize"], "DENY")


if __name__ == "__main__":
    unittest.main()
