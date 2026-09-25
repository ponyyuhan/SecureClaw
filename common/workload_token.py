from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


class WorkloadTokenError(RuntimeError):
    pass


def _b64u_enc(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_dec(s: str) -> bytes:
    t = (s or "").strip()
    if not t:
        return b""
    pad = "=" * ((4 - (len(t) % 4)) % 4)
    return base64.urlsafe_b64decode(t + pad)


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


@dataclass(frozen=True, slots=True)
class WorkloadToken:
    v: int
    skill_digest: str
    session: str
    exp_ms: int
    nonce: str

    def to_payload(self) -> Dict[str, Any]:
        return {
            "v": int(self.v),
            "skill_digest": str(self.skill_digest),
            "session": str(self.session),
            "exp_ms": int(self.exp_ms),
            "nonce": str(self.nonce),
        }


def mint_workload_token(
    *,
    key_hex: str,
    skill_digest: str,
    session: str,
    ttl_s: int = 3600,
    now_ms: int | None = None,
) -> str:
    key_hex = (key_hex or "").strip()
    if not key_hex:
        raise WorkloadTokenError("missing key")
    key = bytes.fromhex(key_hex)
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    exp_ms = int(now_ms) + (int(ttl_s) * 1000)
    tok = WorkloadToken(
        v=1,
        skill_digest=str(skill_digest),
        session=str(session),
        exp_ms=int(exp_ms),
        nonce=secrets.token_urlsafe(8),
    )
    payload = tok.to_payload()
    msg = _canonical_json_bytes(payload)
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return f"{_b64u_enc(msg)}.{_b64u_enc(mac)}"


def verify_workload_token(
    *,
    key_hex: str,
    token: str,
    session: str,
    now_ms: int | None = None,
) -> Optional[WorkloadToken]:
    key_hex = (key_hex or "").strip()
    if not key_hex:
        return None
    t = (token or "").strip()
    if "." not in t:
        return None
    a, b = t.split(".", 1)
    try:
        msg = _b64u_dec(a)
        mac = _b64u_dec(b)
    except Exception:
        return None
    if not msg or not mac:
        return None
    key = bytes.fromhex(key_hex)
    want = hmac.new(key, msg, hashlib.sha256).digest()
    if not hmac.compare_digest(want, mac):
        return None
    try:
        payload = json.loads(msg.decode("utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if int(payload.get("v") or 0) != 1:
        return None
    skill_digest = str(payload.get("skill_digest") or "")
    sess = str(payload.get("session") or "")
    try:
        exp_ms = int(payload.get("exp_ms") or 0)
    except Exception:
        return None
    nonce = str(payload.get("nonce") or "")
    if not skill_digest or not sess or exp_ms <= 0:
        return None
    if str(session) != sess:
        return None
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if int(now_ms) > exp_ms:
        return None
    return WorkloadToken(v=1, skill_digest=skill_digest, session=sess, exp_ms=exp_ms, nonce=nonce)

