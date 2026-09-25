from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
import unittest

from common.output_sanitizer import OutputSanitizer


# Exercise the actual two registration helpers without importing model clients,
# benchmark packages, or starting gateway services.
_ROOT = Path(__file__).resolve().parents[1]
_HELPERS = {}
for _relative in (
    "scripts/paper_parity_agentleak_eval.py",
    "method_adapters/agentleak/channels.py",
):
    _source = _ROOT / _relative
    _tree = ast.parse(_source.read_text(encoding="utf-8"))
    _function = next(
        node for node in _tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_vault_field_value_pairs"
    )
    _namespace = {"json": json, "Scenario": object, "Any": Any}
    exec(compile(ast.Module(body=[_function], type_ignores=[]), str(_source), "exec"), _namespace)
    _HELPERS[_relative] = _namespace["_vault_field_value_pairs"]


def _scenario(*records):
    return SimpleNamespace(private_vault=SimpleNamespace(
        records=[SimpleNamespace(fields=fields) for fields in records]
    ))


class AgentLeakSensitiveRegistrationTests(unittest.TestCase):
    def _sanitizer(self, helper, scenario, mode="all"):
        sanitizer = OutputSanitizer()
        sanitizer.register_session_values("registered", helper(scenario), mode)
        return sanitizer

    def test_list_items_remain_protected_when_rendered_as_bullets(self):
        scenario = _scenario({"witness_list": ["Alice Example", "Boris Sample", "Carol Fixture"]})
        text = "Witnesses:\n- CAROL FIXTURE\n- Alice Example\n- boris sample"
        for name, helper in _HELPERS.items():
            with self.subTest(helper=name):
                sanitized, _ = self._sanitizer(helper, scenario).sanitize("registered", text)
                self.assertEqual(sanitized.count("[REDACTED:VAULT]"), 3)
                for witness in scenario.private_vault.records[0].fields["witness_list"]:
                    self.assertNotIn(witness.lower(), sanitized.lower())

    def test_integer_and_decimal_amounts_keep_exact_and_comma_forms(self):
        scenario = _scenario({"settlement_amount": 1234567, "retainer_amount": 45678.125})
        text = "$1,234,567; 1234567; $45,678.125; 45678.125; unrelated $98,765.50"
        for name, helper in _HELPERS.items():
            with self.subTest(helper=name):
                sanitized, _ = self._sanitizer(helper, scenario).sanitize("registered", text)
                self.assertEqual(sanitized.count("[REDACTED:VAULT]"), 4)
                self.assertIn("unrelated $98,765.50", sanitized)

    def test_nested_leaves_keep_parent_sensitivity_and_whole_values(self):
        sensitive = {"witnesses": ["Alice Example", {"name": "Boris Sample"}], "amount": 34567}
        public = {"label": "Public Meeting", "amount": 87654}
        scenario = _scenario({"confidential_notes": sensitive, "event_details": public})
        for name, helper in _HELPERS.items():
            with self.subTest(helper=name):
                pairs = helper(scenario)
                self.assertIn({"field": "confidential_notes", "value": json.dumps(sensitive)}, pairs)
                self.assertIn({"field": "confidential_notes", "value": "Boris Sample"}, pairs)
                self.assertIn({"field": "confidential_notes", "value": "34,567"}, pairs)
                sanitizer = self._sanitizer(helper, scenario, "always_sensitive")
                sanitized, _ = sanitizer.sanitize(
                    "registered", "Alice Example; Boris Sample; 34,567; Public Meeting; 87,654"
                )
                self.assertEqual(sanitized.count("[REDACTED:VAULT]"), 3)
                self.assertIn("Public Meeting; 87,654", sanitized)
                original_json, _ = sanitizer.sanitize("registered", json.dumps(sensitive))
                self.assertEqual(original_json, "[REDACTED:VAULT]")

    def test_string_identifiers_bools_and_short_values_are_not_reinterpreted(self):
        scenario = _scenario({"case_id": "1234567", "active": False, "short": 123,
                              "nested": ["Ada", None, 42]})
        for name, helper in _HELPERS.items():
            with self.subTest(helper=name):
                values = {pair["value"] for pair in helper(scenario)}
                self.assertIn("1234567", values)
                self.assertNotIn("1,234,567", values)
                self.assertNotIn("0", values)
                self.assertNotIn("123", values)
                self.assertNotIn("Ada", values)
                self.assertNotIn("42", values)
                sanitizer = self._sanitizer(helper, scenario)
                sanitized, _ = sanitizer.sanitize("registered", "1,234,567; Ada; 123; 42")
                self.assertEqual(sanitized, "1,234,567; Ada; 123; 42")

    def test_all_records_are_registered_and_sessions_remain_isolated(self):
        scenario = _scenario({"witness_list": ["Alice Example"]},
                             {"witness_list": ["Boris Sample"]})
        text = "Alice Example; Boris Sample"
        for name, helper in _HELPERS.items():
            with self.subTest(helper=name):
                sanitizer = self._sanitizer(helper, scenario)
                sanitized, _ = sanitizer.sanitize("registered", text)
                self.assertEqual(sanitized.count("[REDACTED:VAULT]"), 2)
                self.assertEqual(sanitizer.sanitize("unregistered", text)[0], text)
                sanitizer.clear_session("registered")
                self.assertEqual(sanitizer.sanitize("registered", text)[0], text)


if __name__ == "__main__":
    unittest.main()
