import unittest
import os
import json
import tempfile

from fss.dpf import (
    eval_dpf_pir_block_share,
    eval_dpf_pir_parity_share,
    eval_dpf_pir_parity_share_sparse,
    eval_dpf_point,
    gen_dpf_keys,
)
from gateway.handles import HandleStore
from gateway.guardrails import ObliviousGuardrails
from gateway.executors.cryptoexec import CryptoExec


def _set_bit(buf: bytearray, idx: int) -> None:
    buf[idx // 8] |= (1 << (idx % 8))


class _StubPir:
    def __init__(self, *, allow_recipient: bool = True, banned_hit: bool = False, allow_domain: bool = True):
        self._allow_recipient = allow_recipient
        self._banned_hit = banned_hit
        self._allow_domain = allow_domain

    def query_bit(self, db_name: str, idx: int, timeout_s: int = 10) -> int:  # noqa: ARG002
        if db_name == "allow_recipients":
            return 1 if self._allow_recipient else 0
        if db_name == "allow_domains":
            return 1 if self._allow_domain else 0
        raise KeyError(db_name)

    def query_bits(self, db_name: str, idxs, timeout_s: int = 10):  # noqa: ANN001, ARG002
        if db_name != "banned_tokens":
            raise KeyError(db_name)
        # If banned_hit is set, claim every queried token hits.
        v = 1 if self._banned_hit else 0
        return [v for _ in list(idxs)]


class DpfTests(unittest.TestCase):
    def test_point_function_correctness(self) -> None:
        for nbits in [4, 8]:
            N = 1 << nbits
            for alpha in [0, 1, 3, N // 2, N - 1]:
                k0, k1 = gen_dpf_keys(alpha=alpha, beta=1, domain_bits=nbits)
                for x in range(N):
                    y = eval_dpf_point(key_bytes=k0, x=x, party=0) ^ eval_dpf_point(key_bytes=k1, x=x, party=1)
                    exp = 1 if x == alpha else 0
                    self.assertEqual(y, exp)

    def test_pir_parity_share_reconstructs_db_bit(self) -> None:
        nbits = 12
        N = 1 << nbits
        nbytes = (N + 7) // 8
        db = bytearray(b"\x00" * nbytes)
        idx1 = 7
        idx0 = 8
        _set_bit(db, idx1)

        for idx, expected in [(idx1, 1), (idx0, 0)]:
            k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
            a0 = eval_dpf_pir_parity_share(key_bytes=k0, db_bitset=bytes(db), party=0)
            a1 = eval_dpf_pir_parity_share(key_bytes=k1, db_bitset=bytes(db), party=1)
            self.assertEqual((a0 ^ a1) & 1, expected)

    def test_sparse_parity_share_matches_dense(self) -> None:
        nbits = 10
        N = 1 << nbits
        nbytes = (N + 7) // 8
        db = bytearray(b"\x00" * nbytes)
        # Build a moderately sparse DB.
        for idx in [1, 7, 13, 42, 99, 101, 777]:
            _set_bit(db, idx)
        ones = [i for i in range(N) if ((db[i // 8] >> (i % 8)) & 1)]

        for alpha in [0, 1, 2, 7, 13, 42, 100, 777, 1023]:
            k0, k1 = gen_dpf_keys(alpha=alpha, beta=1, domain_bits=nbits)
            d0 = eval_dpf_pir_parity_share(key_bytes=k0, db_bitset=bytes(db), party=0) & 1
            d1 = eval_dpf_pir_parity_share(key_bytes=k1, db_bitset=bytes(db), party=1) & 1
            s0 = eval_dpf_pir_parity_share_sparse(key_bytes=k0, ones=ones, party=0) & 1
            s1 = eval_dpf_pir_parity_share_sparse(key_bytes=k1, ones=ones, party=1) & 1
            self.assertEqual(d0, s0)
            self.assertEqual(d1, s1)

    def test_pir_block_share_reconstructs_db_block(self) -> None:
        nbits = 8
        N = 1 << nbits
        block_size = 4
        db = bytearray(b"\x00" * (N * block_size))
        idx = 42
        want = bytes([1, 2, 3, 4])
        db[idx * block_size : idx * block_size + block_size] = want

        k0, k1 = gen_dpf_keys(alpha=idx, beta=1, domain_bits=nbits)
        b0 = eval_dpf_pir_block_share(key_bytes=k0, db_blocks=bytes(db), block_size=block_size, party=0)
        b1 = eval_dpf_pir_block_share(key_bytes=k1, db_blocks=bytes(db), block_size=block_size, party=1)
        got = bytes([x ^ y for x, y in zip(b0, b1)])
        self.assertEqual(got, want)

    def test_key_size_is_sublinear(self) -> None:
        # Communication sanity check: key should be much smaller than O(N) bitset.
        nbits = 16
        N = 1 << nbits
        bitset_bytes = (N + 7) // 8
        k0, _k1 = gen_dpf_keys(alpha=12345, beta=1, domain_bits=nbits)
        self.assertLess(len(k0), bitset_bytes // 8)  # very conservative threshold


class GuardrailsTests(unittest.TestCase):
    def test_allows_safe_message(self) -> None:
        handles = HandleStore()
        g = ObliviousGuardrails(pir=_StubPir(allow_recipient=True, banned_hit=False), handles=handles, domain_size=4096, max_tokens=32)
        dec = g.check_egress_message(recipient="alice@example.com", text="hello world", artifacts=[], session="s", caller="c")
        self.assertTrue(dec.allow)
        self.assertEqual(dec.reason_code, "ALLOW")

    def test_blocks_non_allowlisted_recipient(self) -> None:
        handles = HandleStore()
        g = ObliviousGuardrails(pir=_StubPir(allow_recipient=False, banned_hit=False), handles=handles, domain_size=4096, max_tokens=32)
        dec = g.check_egress_message(recipient="evil@attacker.com", text="hello world", artifacts=[], session="s", caller="c")
        self.assertFalse(dec.allow)
        self.assertEqual(dec.reason_code, "RECIPIENT_NOT_ALLOWED")

    def test_blocks_dlp_hit(self) -> None:
        handles = HandleStore()
        g = ObliviousGuardrails(pir=_StubPir(allow_recipient=True, banned_hit=True), handles=handles, domain_size=4096, max_tokens=32)
        dec = g.check_egress_message(recipient="alice@example.com", text="abcd", artifacts=[], session="s", caller="c")
        self.assertFalse(dec.allow)
        self.assertEqual(dec.reason_code, "DLP_BLOCKED")

    def test_blocks_high_handle(self) -> None:
        handles = HandleStore()
        rec = handles.mint(
            label="CONFIDENTIAL_FILE",
            sensitivity="HIGH",
            value={"content": "secret"},
            allowed_sinks=["Declassify"],
            session="s",
            ttl_seconds=600,
        )
        g = ObliviousGuardrails(pir=_StubPir(allow_recipient=True, banned_hit=False), handles=handles, domain_size=4096, max_tokens=32)
        dec = g.check_egress_message(recipient="alice@example.com", text="hello world", artifacts=[{"handle": rec.handle}], session="s", caller="unknown")
        self.assertFalse(dec.allow)
        self.assertEqual(dec.reason_code, "HIGH_HANDLE_BLOCKED")

    def test_blocks_handle_sink_not_allowed(self) -> None:
        handles = HandleStore()
        rec = handles.mint(
            label="SOME_HANDLE",
            sensitivity="LOW",
            value={"content": "not secret"},
            allowed_sinks=["Declassify"],  # explicitly NOT SendMessage
            session="s",
            ttl_seconds=600,
        )
        g = ObliviousGuardrails(pir=_StubPir(allow_recipient=True, banned_hit=False), handles=handles, domain_size=4096, max_tokens=32)
        dec = g.check_egress_message(recipient="alice@example.com", text="hello", artifacts=[{"handle": rec.handle}], session="s", caller="unknown")
        self.assertFalse(dec.allow)
        self.assertEqual(dec.reason_code, "HANDLE_SINK_BLOCKED")


class DeclassifyTests(unittest.TestCase):
    def test_declassify_requires_confirm_for_high(self) -> None:
        handles = HandleStore()
        crypto = CryptoExec(handles)

        token = "AKIA1234567890ABCDEF"
        rec = handles.mint(
            label="CONFIDENTIAL_FILE",
            sensitivity="HIGH",
            value={"content": f"here is a token: {token}"},
            allowed_sinks=["Declassify"],
            session="s",
            ttl_seconds=600,
        )

        obs_no = crypto.declassify({"handle": rec.handle, "purpose": "peek"}, constraints={}, session="s")
        self.assertEqual(obs_no["status"], "DENY")
        self.assertEqual(obs_no["reason_code"], "REQUIRE_CONFIRM")

        obs_yes = crypto.declassify({"handle": rec.handle, "purpose": "peek"}, constraints={"user_confirm": True}, session="s")
        self.assertEqual(obs_yes["status"], "OK")
        preview = obs_yes["data"]["text_preview"]
        self.assertIn("[REDACTED]", preview)
        self.assertNotIn(token, preview)

    def test_declassify_blocked_by_allowed_sinks(self) -> None:
        handles = HandleStore()
        crypto = CryptoExec(handles)
        rec = handles.mint(
            label="CAPABILITY",
            sensitivity="HIGH",
            value={"note": "secretless"},
            allowed_sinks=["UseCredential"],
            session="s",
            ttl_seconds=600,
        )
        obs = crypto.declassify({"handle": rec.handle, "purpose": "peek"}, constraints={"user_confirm": True}, session="s")
        self.assertEqual(obs["status"], "DENY")
        self.assertEqual(obs["reason_code"], "DECLASSIFY_BLOCKED")

    def test_use_credential_uses_secret_store_without_disclosing(self) -> None:
        old = os.environ.get("SECRETS_PATH")
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            json.dump({"demo": "s3cr3t"}, f)
            f.flush()
            os.environ["SECRETS_PATH"] = f.name

        handles = HandleStore()
        crypto = CryptoExec(handles)
        rec = handles.mint(
            label="CAPABILITY",
            sensitivity="HIGH",
            value={"secret_name": "demo"},
            allowed_sinks=["UseCredential"],
            session="s",
            ttl_seconds=600,
            caller="c",
            issuer_intent="ReadSecret",
        )
        obs = crypto.use_credential({"handle": rec.handle, "op": "SIGN", "target": "hello"}, session="s", caller="c")
        self.assertEqual(obs["status"], "OK")
        self.assertIn("hmac_sha256", obs["data"]["result"])
        if old is None:
            os.environ.pop("SECRETS_PATH", None)
        else:
            os.environ["SECRETS_PATH"] = old


if __name__ == "__main__":
    unittest.main()
