"""Fresh-clone selection must not depend on excluded historical model outputs."""
from __future__ import annotations
import ast
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from typing import Any, Sequence
import unittest
from unittest.mock import Mock

_SOURCE = Path(__file__).resolve().parents[1] / 'rebuttal/experiments/run_agentleak_boundary.py'
_NAMES = {'_scenario_kind', '_vertical', '_attack_class', '_attack_family', '_stable_hash', '_round_robin_ids', '_generated_selection_rows', '_balanced_selection_ids', '_load_scenario_ids', 'select_experiment_ids'}
_TREE = ast.parse(_SOURCE.read_text())
_NODES = [n for n in _TREE.body if isinstance(n, ast.FunctionDef) and n.name in _NAMES]
_NS = {'Any': Any, 'Sequence': Sequence, 'Path': Path, 'defaultdict': defaultdict, 'hashlib': hashlib}
exec(compile(ast.Module(body=_NODES, type_ignores=[]), str(_SOURCE), 'exec'), _NS)


def samples():
    return [NS(scenario_id=f'{v}-{i}', vertical=v,
               attack=NS(enabled=i < 124, attack_class=f'class-{i % 6}', attack_family=''))
            for v in ['corporate', 'finance', 'healthcare', 'legal'] for i in range(249)]


class BoundarySelectionTests(unittest.TestCase):
    def setUp(self):
        self.scenarios = samples()
        self.load = Mock(side_effect=AssertionError('Historical outputs unavailable in a clean checkout'))
        _NS['_load_frozen_rows'] = self.load

    def select(self, **kwargs):
        return _NS['select_experiment_ids'](self.scenarios, 'misclassification', seed=42, three_seed_subset=False, **kwargs)

    def test_full_inventory_needs_no_historical_results(self):
        ids = self.select(full_selection=True)
        self.assertEqual(len(ids), 996)
        self.assertEqual(set(ids), {s.scenario_id for s in self.scenarios})
        self.load.assert_not_called()

    def test_bounded_full_prefix_covers_both_kinds_and_all_verticals(self):
        by_id = {s.scenario_id: s for s in self.scenarios}
        ids = self.select(full_selection=True)
        for n in [12, 24]:
            counts = Counter(('attack' if by_id[i].attack.enabled else 'benign', by_id[i].vertical) for i in ids[:n])
            self.assertEqual(len(counts), 8)
            self.assertLessEqual(max(counts.values()) - min(counts.values()), 1)

    def test_default_subset_is_deterministic_and_outcome_blind(self):
        ids = self.select()
        self.assertEqual(len(ids), 240)
        self.assertEqual(ids, self.select())
        by_id = {s.scenario_id: s for s in self.scenarios}
        self.assertEqual(sum(by_id[i].attack.enabled for i in ids), 120)
        self.load.assert_not_called()

    def test_historical_selection_must_be_explicit_and_available(self):
        _NS['_load_frozen_rows'] = Mock(return_value=[])
        with self.assertRaisesRegex(ValueError, 'no historical rows'):
            self.select(historical_selection=True)
        _NS['_load_frozen_rows'].assert_called_once()

    def test_explicit_id_file_keeps_requested_order_and_rejects_unknown_ids(self):
        with TemporaryDirectory() as temp:
            p = Path(temp) / 'ids.txt'
            p.write_text('finance-3\ncorporate-4\nfinance-3\n')
            available = {s.scenario_id for s in self.scenarios}
            self.assertEqual(_NS['_load_scenario_ids'](p, available), ['finance-3', 'corporate-4'])
            p.write_text('nonexistent\n')
            with self.assertRaises(ValueError):
                _NS['_load_scenario_ids'](p, available)


if __name__ == '__main__':
    unittest.main()
