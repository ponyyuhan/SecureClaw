from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class _TurnState:
    turn_id: str
    finalized: bool


class TurnGate:
    """
    Optional strict per-turn output gate.

    When enabled, each turn (identified by constraints.turn_id) must end with a
    successful FinalizeOutput before the next turn may start.
    """

    def __init__(self):
        self.enabled = bool(int(os.getenv("MIRAGE_ENFORCE_FINAL_OUTPUT_GATE", "0")))
        self._lock = threading.Lock()
        self._state: Dict[Tuple[str, str], _TurnState] = {}

    def on_non_finalize(self, *, session: str, caller: str, turn_id: str) -> tuple[bool, str, dict]:
        if not self.enabled:
            return True, "ALLOW", {}
        tid = str(turn_id or "").strip()
        if not tid:
            return False, "TURN_ID_REQUIRED", {"hint": "Provide constraints.turn_id when MIRAGE_ENFORCE_FINAL_OUTPUT_GATE=1."}
        key = (str(session), str(caller))
        with self._lock:
            st = self._state.get(key)
            if st is None:
                self._state[key] = _TurnState(turn_id=tid, finalized=False)
                return True, "ALLOW", {}
            if st.turn_id == tid:
                return True, "ALLOW", {}
            if not st.finalized:
                return False, "OUTPUT_GATE_REQUIRED", {"pending_turn_id": st.turn_id}
            self._state[key] = _TurnState(turn_id=tid, finalized=False)
            return True, "ALLOW", {}

    def on_finalize(self, *, session: str, caller: str, turn_id: str) -> tuple[bool, str, dict]:
        if not self.enabled:
            return True, "ALLOW", {}
        tid = str(turn_id or "").strip()
        if not tid:
            return False, "TURN_ID_REQUIRED", {"hint": "Provide constraints.turn_id for FinalizeOutput."}
        key = (str(session), str(caller))
        with self._lock:
            st = self._state.get(key)
            if st is None:
                self._state[key] = _TurnState(turn_id=tid, finalized=True)
                return True, "ALLOW", {}
            if st.turn_id != tid:
                if not st.finalized:
                    return False, "TURN_ID_MISMATCH", {"expected_turn_id": st.turn_id}
                # Allow a turn that consists only of FinalizeOutput (no tool calls beforehand).
                self._state[key] = _TurnState(turn_id=tid, finalized=True)
                return True, "ALLOW", {}
            st.finalized = True
            return True, "ALLOW", {}

    def status(self, *, session: str, caller: str) -> dict[str, str | bool]:
        key = (str(session), str(caller))
        with self._lock:
            st = self._state.get(key)
        if st is None:
            return {"has_turn": False, "turn_id": "", "finalized": True}
        return {"has_turn": True, "turn_id": st.turn_id, "finalized": bool(st.finalized)}
