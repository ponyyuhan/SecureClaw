from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace
import unittest


# The context helper has no model or gateway dependencies. Load its actual
# definition so these regression tests require no benchmark services or keys.
_SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "paper_parity_agentleak_eval.py"
_TREE = ast.parse(_SOURCE.read_text(encoding="utf-8"))
_FUNCTIONS = [
    node for node in _TREE.body
    if isinstance(node, ast.FunctionDef)
    and node.name in {"_flatten_vault", "_vault_field_value_pairs"}
]
_NAMESPACE = {"json": json, "Scenario": object}
exec(compile(ast.Module(body=_FUNCTIONS, type_ignores=[]), str(_SOURCE), "exec"), _NAMESPACE)
_flatten_vault = _NAMESPACE["_flatten_vault"]
_vault_field_value_pairs = _NAMESPACE["_vault_field_value_pairs"]


def _scenario(*records):
    return SimpleNamespace(
        private_vault=SimpleNamespace(
            records=[SimpleNamespace(fields=fields) for fields in records]
        )
    )


class AgentLeakVaultContextTests(unittest.TestCase):
    def test_masked_context_preserves_records_and_masks_each_secret(self):
        from method_adapters.agentleak.parity_fields import masked_flat_vault as adapter_masked
        from rebuttal.experiments.agentleak_parity_core import masked_flat_vault as runner_masked
        sample = _scenario(
            {"name": "Requested Patient", "secret": "FIRST PRIVATE", "additional_record_2": "existing"},
            {"name": "Other Patient", "secret": "SECOND PRIVATE"},
        )
        for masked in (adapter_masked, runner_masked):
            with self.subTest(implementation=masked.__module__):
                context = masked(sample, [], {"r0:secret", "r1:secret"})
                self.assertEqual(context["name"], "Requested Patient")
                self.assertEqual(context["additional_record_2_" ]["name"], "Other Patient")
                self.assertEqual(context["additional_record_2"], "existing")
                self.assertNotIn("FIRST PRIVATE", str(context))
                self.assertNotIn("SECOND PRIVATE", str(context))

    def test_requested_first_record_is_not_overwritten(self):
        scenario = _scenario(
            {"name": "Requested Patient", "case_id": "CASE-001"},
            {"name": "Second Patient", "case_id": "CASE-002"},
            {"name": "Third Patient", "case_id": "CASE-003"},
        )
        context = _flatten_vault(scenario)
        self.assertEqual(context["name"], "Requested Patient")
        self.assertEqual(context["case_id"], "CASE-001")
        self.assertEqual(json.loads(context["additional_record_2"]), scenario.private_vault.records[1].fields)
        self.assertEqual(json.loads(context["additional_record_3"]), scenario.private_vault.records[2].fields)

    def test_single_record_keeps_existing_representation(self):
        context = _flatten_vault(_scenario({
            "name": "Patient A", "amount": 1200, "active": False,
            "allergies": ["pollen", "latex"], "details": {"status": "scheduled"},
            "unavailable": None,
        }))
        self.assertEqual(context, {
            "name": "Patient A", "amount": "1200", "active": "False",
            "allergies": '["pollen", "latex"]', "details": '{"status": "scheduled"}',
        })

    def test_record_container_does_not_replace_a_real_field(self):
        context = _flatten_vault(_scenario(
            {"name": "Requested Patient", "additional_record_2": "existing field", "additional_record_2_": "also existing"},
            {"name": "Second Patient", "nested": {"witnesses": ["Alice", "Bob"]}},
        ))
        self.assertEqual(context["additional_record_2"], "existing field")
        self.assertEqual(context["additional_record_2_"], "also existing")
        self.assertEqual(json.loads(context["additional_record_2__"])["nested"]["witnesses"], ["Alice", "Bob"])

    def test_sensitive_registration_still_covers_all_records(self):
        scenario = _scenario(
            {"name": "Requested Patient", "canary": "CANARY_FIRST_123"},
            {"name": "Second Patient", "canary": "CANARY_SECOND_456"},
        )
        before = _vault_field_value_pairs(scenario)
        _flatten_vault(scenario)
        self.assertEqual(_vault_field_value_pairs(scenario), before)
        self.assertTrue({"CANARY_FIRST_123", "CANARY_SECOND_456"}.issubset({x["value"] for x in before}))


if __name__ == "__main__":
    unittest.main()
