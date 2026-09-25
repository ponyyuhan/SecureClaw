from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from unittest.mock import patch

from executor_server import server as ex
from common.canonical import request_sha256_v1


def _mac_b64(key_hex: str, payload: dict) -> str:
    msg = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    mac = hmac.new(bytes.fromhex(key_hex), msg, hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def _mk_commit_proof(*, server_id: int, key_hex: str, action_id: str, program_id: str, request_sha256: str, outputs: dict[str, int], ts: int | None = None) -> dict:
    payload = {
        "v": 1,
        "kind": "commit",
        "server_id": int(server_id),
        "kid": "0",
        "ts": int(ts if ts is not None else time.time()),
        "action_id": str(action_id),
        "program_id": str(program_id),
        "request_sha256": str(request_sha256),
        "outputs": {str(k): int(v) & 1 for k, v in outputs.items()},
        "commit_tag_share_b64": base64.b64encode(b"\x01" * 16).decode("ascii"),
    }
    payload["mac_b64"] = _mac_b64(key_hex, payload)
    return payload


class SecurityGameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.k0 = "11" * 32
        self.k1 = "22" * 32
        os.environ["POLICY0_MAC_KEY"] = self.k0
        os.environ["POLICY1_MAC_KEY"] = self.k1
        os.environ["POLICY_MAC_TTL_S"] = "60"
        ex.POLICY0_KEYS = None
        ex.POLICY1_KEYS = None
        ex.MAC_TTL_S = 60
        ex._REPLAY_GUARD = None

    def test_dual_valid_commit_proofs_accept(self) -> None:
        action_id = "a_test"
        program_id = "policy_unified_v1"
        req_sha = "ab" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
        )
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": p1}, action_id=action_id, program_id=program_id, request_sha256=req_sha)
        self.assertEqual(code, "OK")
        self.assertIsNotNone(outs)
        self.assertIsNotNone(tag)
        self.assertEqual(int((outs or {}).get("allow_pre", 0)), 1)

    def test_replay_denied(self) -> None:
        action_id = "a_replay"
        program_id = "policy_unified_v1"
        req_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller="c",
            session="s",
            inputs={"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        )
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )

        req = ex.ExecSendMessageReq(
            action_id=action_id,
            channel="email",
            recipient="alice@example.com",
            domain="",
            text="hello",
            artifacts=[],
            dlp_mode="fourgram",
            evidence={},
            commit={"policy0": p0, "policy1": p1},
            caller="c",
            session="s",
            user_confirm=False,
        )
        r1 = ex.exec_send_message(req)
        self.assertEqual(str(r1.get("status")), "OK")

        r2 = ex.exec_send_message(req)
        self.assertEqual(str(r2.get("status")), "DENY")
        self.assertEqual(str(r2.get("reason_code")), "REPLAY_DENY")

    def test_session_binding_denied(self) -> None:
        action_id = "a_sess_bind"
        program_id = "policy_unified_v1"
        req_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller="caller_a",
            session="session_a",
            inputs={"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        )
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        # Change the session in the request so executor recomputes a different request_sha256.
        req = ex.ExecSendMessageReq(
            action_id=action_id,
            channel="email",
            recipient="alice@example.com",
            domain="",
            text="hello",
            artifacts=[],
            dlp_mode="fourgram",
            evidence={},
            commit={"policy0": p0, "policy1": p1},
            caller="caller_a",
            session="session_b",
            user_confirm=False,
        )
        r = ex.exec_send_message(req)
        self.assertEqual(str(r.get("status")), "DENY")
        self.assertEqual(str(r.get("reason_code")), "BAD_COMMIT_PROOF")
        self.assertEqual(str(r.get("details")), "bad_request_sha256")

    def test_caller_binding_denied(self) -> None:
        action_id = "a_caller_bind"
        program_id = "policy_unified_v1"
        req_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller="caller_a",
            session="session_a",
            inputs={"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
        )
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        # Change the caller in the request so executor recomputes a different request_sha256.
        req = ex.ExecSendMessageReq(
            action_id=action_id,
            channel="email",
            recipient="alice@example.com",
            domain="",
            text="hello",
            artifacts=[],
            dlp_mode="fourgram",
            evidence={},
            commit={"policy0": p0, "policy1": p1},
            caller="caller_b",
            session="session_a",
            user_confirm=False,
        )
        r = ex.exec_send_message(req)
        self.assertEqual(str(r.get("status")), "DENY")
        self.assertEqual(str(r.get("reason_code")), "BAD_COMMIT_PROOF")
        self.assertEqual(str(r.get("details")), "bad_request_sha256")

    def test_missing_second_proof_rejected(self) -> None:
        action_id = "a_test_missing"
        program_id = "policy_unified_v1"
        req_sha = "cd" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1},
        )
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": None}, action_id=action_id, program_id=program_id, request_sha256=req_sha)
        self.assertIsNone(outs)
        self.assertIsNone(tag)
        self.assertNotEqual(code, "OK")

    def test_external_principal_binding_denied(self) -> None:
        action_id = "a_principal_bind"
        program_id = "policy_unified_v1"
        req_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller="caller_a",
            session="session_a",
            inputs={"channel": "email", "recipient": "alice@example.com", "domain": "", "text": "hello"},
            context={"external_principal": "ext:internal-blue", "delegation_jti": "dlg_1"},
        )
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
            ts=int(time.time()),
        )
        req = ex.ExecSendMessageReq(
            action_id=action_id,
            channel="email",
            recipient="alice@example.com",
            domain="",
            text="hello",
            artifacts=[],
            dlp_mode="fourgram",
            evidence={},
            commit={"policy0": p0, "policy1": p1},
            caller="caller_a",
            session="session_a",
            user_confirm=False,
            external_principal="ext:internal-red",
            delegation_jti="dlg_1",
        )
        r = ex.exec_send_message(req)
        self.assertEqual(str(r.get("status")), "DENY")
        self.assertEqual(str(r.get("reason_code")), "BAD_COMMIT_PROOF")
        self.assertEqual(str(r.get("details")), "bad_request_sha256")

    def test_duplicate_server_id_rejected(self) -> None:
        action_id = "a_dup_sid"
        program_id = "policy_unified_v1"
        req_sha = "aa" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1, "need_confirm": 0, "patch0": 0, "patch1": 0},
        )
        # Malformed: second share claims the same server_id and key.
        p1 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0, "need_confirm": 0, "patch0": 0, "patch1": 0},
        )
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": p1}, action_id=action_id, program_id=program_id, request_sha256=req_sha)
        self.assertIsNone(outs)
        self.assertIsNone(tag)
        self.assertEqual(str(code), "server_id_mismatch")

    def test_bad_mac_rejected(self) -> None:
        action_id = "a_test_mac"
        program_id = "policy_unified_v1"
        req_sha = "ef" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1},
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0},
        )
        p0["mac_b64"] = base64.b64encode(b"badbadbadbadbadb").decode("ascii")
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": p1}, action_id=action_id, program_id=program_id, request_sha256=req_sha)
        self.assertIsNone(outs)
        self.assertIsNone(tag)
        self.assertNotEqual(code, "OK")

    def test_request_hash_binding_rejected(self) -> None:
        action_id = "a_test_sha"
        program_id = "policy_unified_v1"
        req_sha = "12" * 32
        p0 = _mk_commit_proof(
            server_id=0,
            key_hex=self.k0,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 1},
        )
        p1 = _mk_commit_proof(
            server_id=1,
            key_hex=self.k1,
            action_id=action_id,
            program_id=program_id,
            request_sha256=req_sha,
            outputs={"allow_pre": 0},
        )
        outs, tag, code = ex._verify_commit_evidence({"policy0": p0, "policy1": p1}, action_id=action_id, program_id=program_id, request_sha256=("34" * 32))
        self.assertIsNone(outs)
        self.assertIsNone(tag)
        self.assertNotEqual(code, "OK")


class DFAEvidenceTests(unittest.TestCase):
    @staticmethod
    def _mk_block(*, next_state: int, matched: bool, block_size: int = 4) -> bytes:
        if block_size < 3:
            raise ValueError("block_size must be >=3")
        return int(next_state).to_bytes(2, "little", signed=False) + bytes([1 if matched else 0]) + (b"\x00" * (block_size - 3))

    def test_unpadded_early_match_is_valid(self) -> None:
        dfa_ev = {
            "db": "dfa_transitions",
            "alpha": 8,
            "block_size": 4,
            "char_to_sym": {"A": 1, "B": 2},
            "steps": [{"idx": 1}, {"idx": 2}],
        }

        def fake_verify(step: dict, *, action_id: str, db: str, block_size: int):
            idx = int(step.get("idx", -1))
            matched = idx == 2
            return self._mk_block(next_state=0, matched=matched, block_size=block_size), "OK"

        with patch.dict(os.environ, {"PAD_DFA_STEPS": "0", "MAX_DFA_SCAN_CHARS": "16"}, clear=False):
            with patch.object(ex, "_verify_block_step", side_effect=fake_verify):
                matched, code = ex._verify_dfa_evidence(dfa_ev, text="ABCD", action_id="a1")
        self.assertTrue(bool(matched))
        self.assertEqual(code, "OK")

    def test_unpadded_truncated_without_match_is_invalid(self) -> None:
        dfa_ev = {
            "db": "dfa_transitions",
            "alpha": 8,
            "block_size": 4,
            "char_to_sym": {"A": 1, "B": 2},
            "steps": [{"idx": 1}, {"idx": 2}],
        }

        def fake_verify(step: dict, *, action_id: str, db: str, block_size: int):
            return self._mk_block(next_state=0, matched=False, block_size=block_size), "OK"

        with patch.dict(os.environ, {"PAD_DFA_STEPS": "0", "MAX_DFA_SCAN_CHARS": "16"}, clear=False):
            with patch.object(ex, "_verify_block_step", side_effect=fake_verify):
                matched, code = ex._verify_dfa_evidence(dfa_ev, text="ABCD", action_id="a2")
        self.assertIsNone(matched)
        self.assertEqual(code, "dfa_unpadded_truncated_without_match")

    def test_padded_mode_requires_fixed_step_count_and_accepts_post_match_padding(self) -> None:
        dfa_ev = {
            "db": "dfa_transitions",
            "alpha": 8,
            "block_size": 4,
            "char_to_sym": {"A": 1, "B": 2, "~": 0},
            "steps": [{"idx": 1}, {"idx": 2}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}, {"idx": 0}],
        }

        def fake_verify(step: dict, *, action_id: str, db: str, block_size: int):
            idx = int(step.get("idx", -1))
            return self._mk_block(next_state=0, matched=(idx == 2), block_size=block_size), "OK"

        with patch.dict(os.environ, {"PAD_DFA_STEPS": "1", "MAX_DFA_SCAN_CHARS": "16"}, clear=False):
            with patch.object(ex, "_verify_block_step", side_effect=fake_verify):
                matched, code = ex._verify_dfa_evidence(dfa_ev, text="AB", action_id="a3")
        self.assertTrue(bool(matched))
        self.assertEqual(code, "OK")

    def test_padded_mode_step_count_mismatch_rejected(self) -> None:
        dfa_ev = {
            "db": "dfa_transitions",
            "alpha": 8,
            "block_size": 4,
            "char_to_sym": {"A": 1, "~": 0},
            "steps": [{"idx": 1}],
        }

        def fake_verify(step: dict, *, action_id: str, db: str, block_size: int):
            return self._mk_block(next_state=0, matched=False, block_size=block_size), "OK"

        with patch.dict(os.environ, {"PAD_DFA_STEPS": "1", "MAX_DFA_SCAN_CHARS": "16"}, clear=False):
            with patch.object(ex, "_verify_block_step", side_effect=fake_verify):
                matched, code = ex._verify_dfa_evidence(dfa_ev, text="A", action_id="a4")
        self.assertIsNone(matched)
        self.assertEqual(code, "dfa_step_count_mismatch_padded")


if __name__ == "__main__":
    unittest.main()
