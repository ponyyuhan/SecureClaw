from __future__ import annotations

import os
import tempfile
import unittest

from gateway.executors.cryptoexec import CryptoExec
from gateway.executors.interagentexec import InterAgentExec
from gateway.executors.memoryexec import MemoryExec
from gateway.executors.outputexec import OutputExec
from gateway.handles import HandleStore
from gateway.interagent_store import InterAgentStore
from gateway.leakage_budget import LeakageBudget
from gateway.memory_service import MemoryService
from gateway.turn_gate import TurnGate


class _PolicyAllowStub:
    def preview(self, *, intent_id, inputs, constraints, session, caller):  # noqa: ANN001
        _ = (intent_id, inputs, constraints, session, caller)
        return {
            "allow_pre": True,
            "need_confirm": False,
            "patch": {"patch_id": 0, "params": {}},
            "tx_id": "tx_stub",
            "evidence": {},
        }

    def commit_from_tx(self, *, tx_id, intent_id, constraints, session, caller):  # noqa: ANN001
        _ = (tx_id, intent_id, constraints, session, caller)
        return {"status": "OK", "reason_code": "ALLOW", "data": {}}


class ChannelMechanismTests(unittest.TestCase):
    def test_c2_is_handleized_and_requires_confirm_for_declassify(self) -> None:
        with tempfile.NamedTemporaryFile() as db_msg, tempfile.NamedTemporaryFile() as db_budget:
            handles = HandleStore()
            store = InterAgentStore(db_path=db_msg.name)
            bus = InterAgentExec(handles, store)
            budget = LeakageBudget(db_path=db_budget.name)
            crypto = CryptoExec(handles, budget=budget)

            send = bus.send({"to_agent": "agent-b", "text": "AKIA1234567890ABCDEF", "artifacts": []}, session="s", caller="c")
            self.assertEqual(send["status"], "OK")
            recv = bus.receive({"agent_id": "agent-b", "max_messages": 1}, session="s", caller="agent-b")
            self.assertEqual(recv["status"], "OK")
            dump = str(recv)
            self.assertNotIn("AKIA1234567890ABCDEF", dump)
            msgs = ((recv.get("data") or {}).get("messages") or [])
            self.assertTrue(msgs)
            hid = str((msgs[0] or {}).get("payload_handle") or "")
            self.assertTrue(hid)

            dec = crypto.declassify({"handle": hid, "purpose": "inspect"}, constraints={}, session="s", caller="agent-b")
            self.assertEqual(dec["status"], "DENY")
            self.assertEqual(dec["reason_code"], "REQUIRE_CONFIRM")

    def test_c5_memory_is_service_handle_only(self) -> None:
        with tempfile.NamedTemporaryFile() as db_mem, tempfile.NamedTemporaryFile() as db_budget:
            handles = HandleStore()
            mem = MemoryService(db_path=db_mem.name)
            mx = MemoryExec(handles, mem)
            budget = LeakageBudget(db_path=db_budget.name)
            crypto = CryptoExec(handles, budget=budget)

            w = mx.write({"namespace": "n", "key": "k", "content": "AKIA1234567890ABCDEF"}, session="s", caller="c")
            self.assertEqual(w["status"], "OK")
            r = mx.read({"namespace": "n", "key": "k"}, session="s", caller="c")
            self.assertEqual(r["status"], "OK")
            self.assertTrue(r.get("artifacts"))
            self.assertNotIn("content", (r.get("data") or {}))
            hid = str((r.get("artifacts") or [{}])[0].get("handle") or "")
            self.assertTrue(hid)

            dec = crypto.declassify({"handle": hid, "purpose": "memory"}, constraints={}, session="s", caller="c")
            self.assertEqual(dec["status"], "DENY")
            self.assertEqual(dec["reason_code"], "REQUIRE_CONFIRM")

    def test_c1_output_gate_budget(self) -> None:
        old_limit = os.environ.get("LEAKAGE_BUDGET_C1")
        try:
            os.environ["LEAKAGE_BUDGET_C1"] = "5"
            with tempfile.NamedTemporaryFile() as db_budget:
                budget = LeakageBudget(db_path=db_budget.name)
                ox = OutputExec(_PolicyAllowStub(), budget)
                out = ox.finalize_output(
                    {"text": "1234567890", "artifacts": []},
                    constraints={"user_confirm": True},
                    session="s",
                    caller="c",
                )
                self.assertEqual(out["status"], "DENY")
                self.assertEqual(out["reason_code"], "LEAKAGE_BUDGET_EXCEEDED")
        finally:
            if old_limit is None:
                os.environ.pop("LEAKAGE_BUDGET_C1", None)
            else:
                os.environ["LEAKAGE_BUDGET_C1"] = old_limit

    def test_c2_receive_agent_id_must_match_caller(self) -> None:
        with tempfile.NamedTemporaryFile() as db_msg:
            handles = HandleStore()
            store = InterAgentStore(db_path=db_msg.name)
            bus = InterAgentExec(handles, store)
            send = bus.send({"to_agent": "agent-b", "text": "hello"}, session="s", caller="agent-a")
            self.assertEqual(send["status"], "OK")
            recv = bus.receive({"agent_id": "agent-b", "max_messages": 1}, session="s", caller="agent-a")
            self.assertEqual(recv["status"], "DENY")
            self.assertEqual(recv["reason_code"], "AGENT_ID_MISMATCH")

    def test_turn_gate_requires_finalize_before_next_turn(self) -> None:
        old = os.environ.get("MIRAGE_ENFORCE_FINAL_OUTPUT_GATE")
        try:
            os.environ["MIRAGE_ENFORCE_FINAL_OUTPUT_GATE"] = "1"
            tg = TurnGate()
            ok1, code1, _ = tg.on_non_finalize(session="s", caller="c", turn_id="t1")
            self.assertTrue(ok1)
            self.assertEqual(code1, "ALLOW")

            ok2, code2, _ = tg.on_non_finalize(session="s", caller="c", turn_id="t2")
            self.assertFalse(ok2)
            self.assertEqual(code2, "OUTPUT_GATE_REQUIRED")

            okf, codef, _ = tg.on_finalize(session="s", caller="c", turn_id="t1")
            self.assertTrue(okf)
            self.assertEqual(codef, "ALLOW")

            ok3, code3, _ = tg.on_non_finalize(session="s", caller="c", turn_id="t2")
            self.assertTrue(ok3)
            self.assertEqual(code3, "ALLOW")
        finally:
            if old is None:
                os.environ.pop("MIRAGE_ENFORCE_FINAL_OUTPUT_GATE", None)
            else:
                os.environ["MIRAGE_ENFORCE_FINAL_OUTPUT_GATE"] = old


if __name__ == "__main__":
    unittest.main()
