from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import threading


@dataclass(frozen=True, slots=True)
class Gate:
    op: str  # "XOR" | "AND" | "NOT" | "CONST"
    out: int
    a: int | None = None
    b: int | None = None
    value: int | None = None  # for CONST


class MpcSession:
    def __init__(
        self,
        *,
        action_id: str,
        program_id: str,
        request_sha256: str,
        party: int,
        n_wires: int,
        gates: List[Gate],
        input_shares: Dict[int, int],
        outputs: Dict[str, int],
        ttl_seconds: int = 30,
    ):
        if party not in (0, 1):
            raise ValueError("party must be 0/1")
        if n_wires <= 0:
            raise ValueError("n_wires must be > 0")
        self.action_id = str(action_id)
        self.program_id = str(program_id)
        self.request_sha256 = str(request_sha256)
        self.party = int(party)
        self.gates = list(gates or [])
        self.outputs = dict(outputs or {})
        self.created_at = float(time.time())
        self.ttl_seconds = int(ttl_seconds)

        self.wires: List[Optional[int]] = [None for _ in range(int(n_wires))]
        for wi, v in (input_shares or {}).items():
            w = int(wi)
            if w < 0 or w >= n_wires:
                raise ValueError("input wire out of range")
            self.wires[w] = int(v) & 1

        # gate_index -> (a_share,b_share,c_share)
        self._pending_triples: Dict[int, Tuple[int, int, int]] = {}

    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds

    def _wire(self, idx: int) -> int:
        v = self.wires[int(idx)]
        if v is None:
            raise ValueError("wire not ready")
        return int(v) & 1

    def _set_wire(self, idx: int, v: int) -> None:
        self.wires[int(idx)] = int(v) & 1

    def _eval_gate(self, g: Gate) -> None:
        op = str(g.op).upper()
        if op == "XOR":
            if g.a is None or g.b is None:
                raise ValueError("bad XOR gate")
            self._set_wire(g.out, self._wire(g.a) ^ self._wire(g.b))
            return
        if op == "NOT":
            if g.a is None:
                raise ValueError("bad NOT gate")
            # For XOR-sharing, NOT(x) = x XOR 1, and we assign the constant-1 share to party 0.
            self._set_wire(g.out, self._wire(g.a) ^ (1 if self.party == 0 else 0))
            return
        if op == "CONST":
            if g.value is None:
                raise ValueError("bad CONST gate")
            v = int(g.value) & 1
            self._set_wire(g.out, v if self.party == 0 else 0)
            return
        if op == "AND":
            # AND gates are handled via and_mask/and_finish and must never be evaluated locally.
            raise ValueError("AND gate requires interaction")
        raise ValueError(f"unknown gate op: {g.op}")

    def eval_local(self) -> int:
        """
        Best-effort local evaluation of XOR/NOT/CONST gates.

        We intentionally keep AND gates interactive (Beaver triples), but we do *not* require
        sequential stepping by program counter. This enables round-based batching of AND gates.

        Returns: number of newly-evaluated gates.
        """
        progressed = 0
        for g in self.gates:
            op = str(g.op).upper()
            if op == "AND":
                continue
            if self.wires[int(g.out)] is not None:
                continue
            if op == "XOR":
                if g.a is None or g.b is None:
                    raise ValueError("bad XOR gate")
                if self.wires[int(g.a)] is None or self.wires[int(g.b)] is None:
                    continue
                self._set_wire(g.out, self._wire(g.a) ^ self._wire(g.b))
                progressed += 1
                continue
            if op == "NOT":
                if g.a is None:
                    raise ValueError("bad NOT gate")
                if self.wires[int(g.a)] is None:
                    continue
                self._set_wire(g.out, self._wire(g.a) ^ (1 if self.party == 0 else 0))
                progressed += 1
                continue
            if op == "CONST":
                if g.value is None:
                    raise ValueError("bad CONST gate")
                v = int(g.value) & 1
                self._set_wire(g.out, v if self.party == 0 else 0)
                progressed += 1
                continue
            raise ValueError(f"unknown gate op: {g.op}")
        return int(progressed)

    def and_mask(self, *, gate_index: int, a_share: int, b_share: int, c_share: int) -> Tuple[int, int]:
        gi = int(gate_index)
        if gi < 0 or gi >= len(self.gates):
            raise ValueError("gate_index out of range")
        self.eval_local()
        g = self.gates[gi]
        if str(g.op).upper() != "AND" or g.a is None or g.b is None:
            raise ValueError("not an AND gate")
        # Save triple shares for finish.
        self._pending_triples[gi] = (int(a_share) & 1, int(b_share) & 1, int(c_share) & 1)
        if self.wires[int(g.a)] is None or self.wires[int(g.b)] is None:
            raise ValueError("and_inputs_not_ready")
        d_share = self._wire(g.a) ^ (int(a_share) & 1)
        e_share = self._wire(g.b) ^ (int(b_share) & 1)
        return int(d_share) & 1, int(e_share) & 1

    def and_finish(self, *, gate_index: int, d: int, e: int) -> int:
        gi = int(gate_index)
        if gi < 0 or gi >= len(self.gates):
            raise ValueError("gate_index out of range")
        triple = self._pending_triples.get(gi)
        if not triple:
            raise ValueError("missing triple for gate")
        a_share, b_share, c_share = triple
        g = self.gates[gi]
        if str(g.op).upper() != "AND" or g.out is None:
            raise ValueError("not an AND gate")

        dd = int(d) & 1
        ee = int(e) & 1
        z = (c_share ^ (dd & b_share) ^ (ee & a_share)) & 1
        if self.party == 0:
            z ^= (dd & ee) & 1
        self._set_wire(g.out, z)
        self._pending_triples.pop(gi, None)
        self.eval_local()
        return int(z) & 1

    def and_mask_batch(self, items: list[tuple[int, int, int, int]]) -> tuple[list[int], list[int]]:
        """
        Batch variant of and_mask.

        items: list of (gate_index, a_share, b_share, c_share).
        Returns: (d_shares, e_shares) aligned with items order.
        """
        self.eval_local()
        d_shares: list[int] = []
        e_shares: list[int] = []
        for gi, a0, b0, c0 in items:
            d, e = self.and_mask(gate_index=int(gi), a_share=int(a0), b_share=int(b0), c_share=int(c0))
            d_shares.append(int(d) & 1)
            e_shares.append(int(e) & 1)
        return d_shares, e_shares

    def and_finish_batch(self, items: list[tuple[int, int, int]]) -> list[int]:
        """
        Batch variant of and_finish.

        items: list of (gate_index, d, e).
        Returns: z_shares aligned with items order.
        """
        z_shares: list[int] = []
        for gi, d, e in items:
            z = self.and_finish(gate_index=int(gi), d=int(d), e=int(e))
            z_shares.append(int(z) & 1)
        return z_shares

    def finalize(self) -> Dict[str, int]:
        # Evaluate all local gates that are now ready.
        self.eval_local()
        # Ensure all ANDs have been finished.
        if self._pending_triples:
            raise ValueError("unfinished AND gate at finalize")
        out: Dict[str, int] = {}
        for name, wi in (self.outputs or {}).items():
            out[str(name)] = int(self._wire(int(wi))) & 1
        return out


class MpcSessionStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, MpcSession] = {}

    def _cleanup(self) -> None:
        dead = [k for k, s in self._sessions.items() if s.expired()]
        for k in dead:
            self._sessions.pop(k, None)

    def init(self, action_id: str, session: MpcSession) -> None:
        with self._lock:
            self._cleanup()
            self._sessions[str(action_id)] = session

    def get(self, action_id: str) -> MpcSession:
        with self._lock:
            self._cleanup()
            s = self._sessions.get(str(action_id))
            if not s:
                raise KeyError("missing_session")
            return s

    def pop(self, action_id: str) -> Optional[MpcSession]:
        with self._lock:
            self._cleanup()
            return self._sessions.pop(str(action_id), None)
