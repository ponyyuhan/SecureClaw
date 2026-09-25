from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, Iterable, Optional


class DelegationTokenError(RuntimeError):
    pass


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


def _normalize_scope(scope: Iterable[str]) -> list[str]:
    out: list[str] = []
    for x in scope:
        s = str(x or "").strip()
        if not s:
            continue
        if s not in out:
            out.append(s)
    return out


def _principal_match(pattern: str, value: str) -> bool:
    p = str(pattern or "").strip()
    v = str(value or "").strip()
    if not p or not v:
        return False
    if p == "*":
        return True
    return fnmatchcase(v, p)


def scope_allows_intent(scope: Iterable[str], intent_id: str) -> bool:
    wanted = str(intent_id or "").strip()
    if not wanted:
        return False
    for raw in scope:
        s = str(raw or "").strip()
        if not s:
            continue
        if s == "*" or s == "intent:*":
            return True
        if s == wanted or s == f"intent:{wanted}":
            return True
        if s.startswith("intent:") and s.endswith("*"):
            pat = s[len("intent:") :]
            if fnmatchcase(wanted, pat):
                return True
    return False


@dataclass(frozen=True, slots=True)
class DelegationToken:
    v: int
    iss: str
    sub: str
    session: str
    scope: tuple[str, ...]
    exp_ms: int
    jti: str
    nonce: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "v": int(self.v),
            "iss": str(self.iss),
            "sub": str(self.sub),
            "session": str(self.session),
            "scope": list(self.scope),
            "exp_ms": int(self.exp_ms),
            "jti": str(self.jti),
            "nonce": str(self.nonce),
        }


@dataclass(frozen=True, slots=True)
class DelegationCheck:
    ok: bool
    code: str
    token: Optional[DelegationToken] = None



def mint_delegation_token(
    *,
    key_hex: str,
    issuer: str,
    subject: str,
    session: str,
    scope: Iterable[str],
    ttl_s: int = 600,
    now_ms: int | None = None,
    jti: str | None = None,
) -> str:
    key_hex = (key_hex or "").strip()
    if not key_hex:
        raise DelegationTokenError("missing key")
    key = bytes.fromhex(key_hex)
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    ttl = int(ttl_s)
    if ttl < 30:
        ttl = 30
    if ttl > 7 * 24 * 3600:
        ttl = 7 * 24 * 3600
    tok = DelegationToken(
        v=1,
        iss=str(issuer),
        sub=str(subject),
        session=str(session),
        scope=tuple(_normalize_scope(scope)),
        exp_ms=int(now_ms) + (ttl * 1000),
        jti=str(jti or f"dlg_{secrets.token_urlsafe(10)}"),
        nonce=secrets.token_urlsafe(8),
    )
    if not tok.iss or not tok.sub or not tok.session or not tok.scope:
        raise DelegationTokenError("invalid delegation fields")
    msg = _canonical_json_bytes(tok.to_payload())
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    return f"{_b64u_enc(msg)}.{_b64u_enc(mac)}"


def parse_and_verify_delegation_token(
    *,
    key_hex: str,
    token: str,
    expected_session: str,
    expected_subject: str,
    expected_intent: str,
    now_ms: int | None = None,
) -> DelegationCheck:
    key_hex = (key_hex or "").strip()
    if not key_hex:
        return DelegationCheck(False, "DELEGATION_KEY_MISSING")
    t = (token or "").strip()
    if "." not in t:
        return DelegationCheck(False, "DELEGATION_TOKEN_MALFORMED")
    a, b = t.split(".", 1)
    try:
        msg = _b64u_dec(a)
        mac = _b64u_dec(b)
    except Exception:
        return DelegationCheck(False, "DELEGATION_TOKEN_DECODE_FAILED")
    if not msg or not mac:
        return DelegationCheck(False, "DELEGATION_TOKEN_MALFORMED")

    key = bytes.fromhex(key_hex)
    want = hmac.new(key, msg, hashlib.sha256).digest()
    if not hmac.compare_digest(want, mac):
        return DelegationCheck(False, "DELEGATION_TOKEN_BAD_MAC")

    try:
        payload = json.loads(msg.decode("utf-8"))
    except Exception:
        return DelegationCheck(False, "DELEGATION_TOKEN_BAD_JSON")
    if not isinstance(payload, dict):
        return DelegationCheck(False, "DELEGATION_TOKEN_BAD_JSON")

    try:
        v = int(payload.get("v") or 0)
        exp_ms = int(payload.get("exp_ms") or 0)
    except Exception:
        return DelegationCheck(False, "DELEGATION_TOKEN_BAD_FIELDS")
    if v != 1:
        return DelegationCheck(False, "DELEGATION_TOKEN_BAD_VERSION")

    iss = str(payload.get("iss") or "")
    sub = str(payload.get("sub") or "")
    sess = str(payload.get("session") or "")
    jti = str(payload.get("jti") or "")
    nonce = str(payload.get("nonce") or "")
    scope_raw = payload.get("scope")
    scope = tuple(_normalize_scope(scope_raw if isinstance(scope_raw, list) else []))

    if not iss or not sub or not sess or not jti or exp_ms <= 0 or not scope:
        return DelegationCheck(False, "DELEGATION_TOKEN_BAD_FIELDS")
    if str(expected_session) != sess:
        return DelegationCheck(False, "DELEGATION_SESSION_MISMATCH")
    if not _principal_match(sub, str(expected_subject or "")):
        return DelegationCheck(False, "DELEGATION_SUBJECT_MISMATCH")
    if not scope_allows_intent(scope, str(expected_intent or "")):
        return DelegationCheck(False, "DELEGATION_SCOPE_DENY")

    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if int(now_ms) > exp_ms:
        return DelegationCheck(False, "DELEGATION_TOKEN_EXPIRED")

    tok = DelegationToken(v=1, iss=iss, sub=sub, session=sess, scope=scope, exp_ms=exp_ms, jti=jti, nonce=nonce)
    return DelegationCheck(True, "ALLOW", token=tok)
