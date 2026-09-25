from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Optional


def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_dec(s: str) -> bytes:
    t = (s or "").strip()
    if not t:
        return b""
    pad = "=" * ((4 - (len(t) % 4)) % 4)
    return base64.urlsafe_b64decode(t + pad)


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@dataclass(frozen=True, slots=True)
class FederatedProofToken:
    v: int
    principal: str
    session: str
    exp_ms: int
    jti: str
    nonce: str
    evidence: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "v": int(self.v),
            "principal": str(self.principal),
            "session": str(self.session),
            "exp_ms": int(self.exp_ms),
            "jti": str(self.jti),
            "nonce": str(self.nonce),
            "evidence": str(self.evidence),
        }


@dataclass(frozen=True, slots=True)
class FederatedProofCheck:
    ok: bool
    code: str
    token: Optional[FederatedProofToken] = None



def mint_federated_proof_token(
    *,
    key_hex: str,
    principal: str,
    session: str,
    ttl_s: int = 120,
    evidence: str = "remote-attested",
    now_ms: int | None = None,
) -> str:
    key = bytes.fromhex((key_hex or "").strip())
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    ttl = int(ttl_s)
    if ttl < 10:
        ttl = 10
    if ttl > 3600:
        ttl = 3600
    tok = FederatedProofToken(
        v=1,
        principal=str(principal),
        session=str(session),
        exp_ms=int(now_ms) + (ttl * 1000),
        jti=f"pf_{secrets.token_urlsafe(10)}",
        nonce=secrets.token_urlsafe(8),
        evidence=str(evidence),
    )
    msg = _canonical_json_bytes(tok.to_payload())
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return f"{_b64u_enc(msg)}.{_b64u_enc(mac)}"


def verify_federated_proof_token(
    *,
    key_hex: str,
    token: str,
    expected_principal: str,
    expected_session: str,
    now_ms: int | None = None,
) -> FederatedProofCheck:
    kh = (key_hex or "").strip()
    if not kh:
        return FederatedProofCheck(False, "PROOF_KEY_MISSING")
    t = (token or "").strip()
    if "." not in t:
        return FederatedProofCheck(False, "PROOF_TOKEN_MALFORMED")
    a, b = t.split(".", 1)
    try:
        msg = _b64u_dec(a)
        mac = _b64u_dec(b)
    except Exception:
        return FederatedProofCheck(False, "PROOF_TOKEN_DECODE_FAILED")
    if not msg or not mac:
        return FederatedProofCheck(False, "PROOF_TOKEN_MALFORMED")
    key = bytes.fromhex(kh)
    want = hmac.new(key, msg, hashlib.sha256).digest()
    if not hmac.compare_digest(want, mac):
        return FederatedProofCheck(False, "PROOF_TOKEN_BAD_MAC")
    try:
        payload = json.loads(msg.decode("utf-8"))
    except Exception:
        return FederatedProofCheck(False, "PROOF_TOKEN_BAD_JSON")
    if not isinstance(payload, dict):
        return FederatedProofCheck(False, "PROOF_TOKEN_BAD_JSON")
    try:
        v = int(payload.get("v") or 0)
        exp_ms = int(payload.get("exp_ms") or 0)
    except Exception:
        return FederatedProofCheck(False, "PROOF_TOKEN_BAD_FIELDS")
    if v != 1 or exp_ms <= 0:
        return FederatedProofCheck(False, "PROOF_TOKEN_BAD_FIELDS")
    principal = str(payload.get("principal") or "")
    session = str(payload.get("session") or "")
    jti = str(payload.get("jti") or "")
    nonce = str(payload.get("nonce") or "")
    evidence = str(payload.get("evidence") or "")
    if not principal or not session or not jti:
        return FederatedProofCheck(False, "PROOF_TOKEN_BAD_FIELDS")
    if principal != str(expected_principal or ""):
        return FederatedProofCheck(False, "PROOF_PRINCIPAL_MISMATCH")
    if session != str(expected_session or ""):
        return FederatedProofCheck(False, "PROOF_SESSION_MISMATCH")
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if int(now_ms) > exp_ms:
        return FederatedProofCheck(False, "PROOF_TOKEN_EXPIRED")
    tok = FederatedProofToken(v=1, principal=principal, session=session, exp_ms=exp_ms, jti=jti, nonce=nonce, evidence=evidence)
    return FederatedProofCheck(True, "ALLOW", token=tok)
