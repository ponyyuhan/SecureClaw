from __future__ import annotations

import hashlib
import hmac
import os
import unittest
from unittest.mock import patch

from common.canonical import canonical_json_bytes, request_sha256_v1


class RequestBindingTests(unittest.TestCase):
    def _payload(self) -> dict[str, object]:
        return {
            "v": 1,
            "intent_id": "SendMessage",
            "caller": "alice",
            "session": "s1",
            "inputs": {"channel": "email", "recipient": "bob@example.com", "domain": "", "text": "hello"},
            "context": {"external_principal": "ext:a", "delegation_jti": "dlg_1"},
        }

    def test_legacy_mode_uses_sha256(self) -> None:
        payload = self._payload()
        msg = canonical_json_bytes(payload)
        want = hashlib.sha256(msg).hexdigest()
        with patch.dict(
            os.environ,
            {"SECURECLAW_REQUEST_BINDING_KEY_HEX": "", "REQUEST_BINDING_KEY_HEX": ""},
            clear=False,
        ):
            got = request_sha256_v1(
                intent_id=str(payload["intent_id"]),
                caller=str(payload["caller"]),
                session=str(payload["session"]),
                inputs=dict(payload["inputs"]),
                context=dict(payload["context"]),
            )
        self.assertEqual(got, want)

    def test_keyed_mode_uses_hmac_sha256(self) -> None:
        payload = self._payload()
        msg = canonical_json_bytes(payload)
        key_hex = "ab" * 32
        want = hmac.new(bytes.fromhex(key_hex), msg, hashlib.sha256).hexdigest()
        legacy = hashlib.sha256(msg).hexdigest()
        with patch.dict(os.environ, {"SECURECLAW_REQUEST_BINDING_KEY_HEX": key_hex}, clear=False):
            got = request_sha256_v1(
                intent_id=str(payload["intent_id"]),
                caller=str(payload["caller"]),
                session=str(payload["session"]),
                inputs=dict(payload["inputs"]),
                context=dict(payload["context"]),
            )
        self.assertEqual(got, want)
        self.assertNotEqual(got, legacy)

    def test_short_binding_key_rejected(self) -> None:
        with patch.dict(os.environ, {"SECURECLAW_REQUEST_BINDING_KEY_HEX": "aa" * 8}, clear=False):
            with self.assertRaises(RuntimeError):
                _ = request_sha256_v1(
                    intent_id="SendMessage",
                    caller="alice",
                    session="s1",
                    inputs={"channel": "email", "recipient": "bob@example.com", "domain": "", "text": "hello"},
                    context={"external_principal": "ext:a"},
                )


if __name__ == "__main__":
    unittest.main()
