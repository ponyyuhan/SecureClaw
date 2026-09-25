from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from common.federated_proof_token import verify_federated_proof_token


def _default_ingress_replay_db_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "artifact_out" / "ingress_replay.sqlite")


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _b64u_dec(s: str) -> bytes:
    t = (s or "").strip()
    if not t:
        return b""
    pad = "=" * ((4 - (len(t) % 4)) % 4)
    return base64.urlsafe_b64decode(t + pad)


class _IngressReplayStore:
    def __init__(self, db_path: str | None = None):
        self._db_path = (db_path or os.getenv("INGRESS_REPLAY_DB_PATH", "").strip()) or _default_ingress_replay_db_path()
        self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._lock = threading.Lock()
        self._ttl_s = int(os.getenv("INGRESS_REPLAY_TTL_S", "600") or "600")
        if self._ttl_s < 30:
            self._ttl_s = 30
        if self._ttl_s > 7 * 24 * 3600:
            self._ttl_s = 7 * 24 * 3600
        with self._lock:
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS ingress_replay (
                  replay_key TEXT PRIMARY KEY,
                  seen_at REAL NOT NULL
                )
                """
            )
            self._db.commit()

    def _prune_locked(self, now: float) -> None:
        self._db.execute("DELETE FROM ingress_replay WHERE seen_at < ?", (float(now - self._ttl_s),))
        self._db.commit()

    def check_and_mark(self, replay_key: str) -> bool:
        k = str(replay_key or "").strip()
        if not k:
            return False
        now = float(time.time())
        with self._lock:
            self._prune_locked(now)
            row = self._db.execute("SELECT replay_key FROM ingress_replay WHERE replay_key=?", (k,)).fetchone()
            if row:
                return False
            self._db.execute("INSERT INTO ingress_replay(replay_key, seen_at) VALUES(?,?)", (k, now))
            self._db.commit()
        return True


_REPLAY: _IngressReplayStore | None = None


def _replay() -> _IngressReplayStore:
    global _REPLAY
    if _REPLAY is None:
        _REPLAY = _IngressReplayStore()
    return _REPLAY


@dataclass(frozen=True, slots=True)
class FederatedAuthDecision:
    ok: bool
    code: str
    external_principal: str
    mtls_cert_sha256: str
    signature_kid: str
    proof_jti: str
    auth_context: dict[str, Any]



def _parse_sig_keys(env_val: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for part in str(env_val or "").split(","):
        p = part.strip()
        if not p:
            continue
        if ":" in p:
            kid, key_hex = p.split(":", 1)
        else:
            kid, key_hex = "0", p
        kid = kid.strip() or "0"
        key_hex = key_hex.strip()
        if not key_hex:
            continue
        try:
            out[kid] = bytes.fromhex(key_hex)
        except Exception:
            continue
    return out


def _sig_message(
    *,
    method: str,
    path: str,
    session: str,
    principal: str,
    ts_ms: int,
    nonce: str,
    payload_sha256: str,
) -> bytes:
    s = "\n".join(
        [
            "secureclaw-federated-sig-v1",
            str(method).upper(),
            str(path),
            str(session),
            str(principal),
            str(int(ts_ms)),
            str(nonce),
            str(payload_sha256),
        ]
    )
    return s.encode("utf-8")


def _verify_hmac_signature(*, key: bytes, msg: bytes, sig_raw: str) -> bool:
    sig = (sig_raw or "").strip()
    if not sig:
        return False
    want = hmac.new(key, msg, hashlib.sha256).digest()

    # Accept hex, base64, and base64url.
    cands: list[bytes] = []
    try:
        cands.append(bytes.fromhex(sig))
    except Exception:
        pass
    try:
        cands.append(base64.b64decode(sig))
    except Exception:
        pass
    try:
        cands.append(_b64u_dec(sig))
    except Exception:
        pass

    for got in cands:
        if got and hmac.compare_digest(want, got):
            return True
    return False


def verify_federated_ingress(
    *,
    method: str,
    path: str,
    payload: dict[str, Any],
    session: str,
    external_principal: str,
    mtls_client_cert_sha256: str,
    sig_kid: str,
    sig_value: str,
    sig_ts_ms: str,
    sig_nonce: str,
    proof_token: str,
) -> FederatedAuthDecision:
    principal = str(external_principal or "").strip()
    payload_sha = _sha256_hex(_canonical_json_bytes(payload or {}))

    mtls_required = bool(int(os.getenv("MIRAGE_MTLS_REQUIRED", "0") or "0"))
    sig_required = bool(int(os.getenv("MIRAGE_FEDERATED_SIG_REQUIRED", "0") or "0"))
    proof_required = bool(int(os.getenv("MIRAGE_FEDERATED_PROOF_REQUIRED", "0") or "0"))

    mtls_hash = str(mtls_client_cert_sha256 or "").strip().lower()
    if mtls_required and not mtls_hash:
        return FederatedAuthDecision(False, "MTLS_REQUIRED", "", "", "", "", {})
    allow_certs = [x.strip().lower() for x in str(os.getenv("MIRAGE_MTLS_CERT_SHA256_ALLOWLIST", "") or "").split(",") if x.strip()]
    if mtls_hash and allow_certs and mtls_hash not in set(allow_certs):
        return FederatedAuthDecision(False, "MTLS_CERT_NOT_ALLOWED", "", "", "", "", {})

    # Signature verification
    use_sig = bool(sig_value.strip())
    sig_k = str(sig_kid or "").strip() or "0"
    if sig_required and not use_sig:
        return FederatedAuthDecision(False, "FEDERATED_SIGNATURE_REQUIRED", "", mtls_hash, "", "", {})

    if use_sig:
        if not principal:
            return FederatedAuthDecision(False, "FEDERATED_PRINCIPAL_REQUIRED", "", mtls_hash, "", "", {})
        keys = _parse_sig_keys(os.getenv("MIRAGE_FEDERATED_SIG_KEYS", ""))
        key = keys.get(sig_k)
        if not key:
            return FederatedAuthDecision(False, "FEDERATED_SIG_UNKNOWN_KID", "", mtls_hash, "", "", {})
        try:
            ts = int(str(sig_ts_ms or "0"))
        except Exception:
            return FederatedAuthDecision(False, "FEDERATED_SIG_BAD_TS", "", mtls_hash, "", "", {})
        nonce = str(sig_nonce or "").strip()
        if not nonce:
            return FederatedAuthDecision(False, "FEDERATED_SIG_BAD_NONCE", "", mtls_hash, "", "", {})
        max_skew = int(os.getenv("MIRAGE_FEDERATED_SIG_MAX_SKEW_MS", "60000") or "60000")
        if max_skew < 1000:
            max_skew = 1000
        now_ms = int(time.time() * 1000)
        if abs(now_ms - ts) > max_skew:
            return FederatedAuthDecision(False, "FEDERATED_SIG_EXPIRED", "", mtls_hash, "", "", {})

        msg = _sig_message(
            method=method,
            path=path,
            session=session,
            principal=principal,
            ts_ms=ts,
            nonce=nonce,
            payload_sha256=payload_sha,
        )
        if not _verify_hmac_signature(key=key, msg=msg, sig_raw=sig_value):
            return FederatedAuthDecision(False, "FEDERATED_SIG_BAD_MAC", "", mtls_hash, "", "", {})

        # Replay protection for signature nonce.
        replay_key = f"sig:{principal}:{nonce}"
        if not _replay().check_and_mark(replay_key):
            return FederatedAuthDecision(False, "FEDERATED_SIG_REPLAY", "", mtls_hash, "", "", {})

    # Proof token verification
    proof_jti = ""
    use_proof = bool((proof_token or "").strip())
    if proof_required and not use_proof:
        return FederatedAuthDecision(False, "FEDERATED_PROOF_REQUIRED", "", mtls_hash, sig_k if use_sig else "", "", {})

    if use_proof:
        if not principal:
            return FederatedAuthDecision(False, "FEDERATED_PRINCIPAL_REQUIRED", "", mtls_hash, sig_k if use_sig else "", "", {})
        proof_key = (os.getenv("MIRAGE_FEDERATED_PROOF_KEY", "") or "").strip()
        chk = verify_federated_proof_token(
            key_hex=proof_key,
            token=proof_token,
            expected_principal=principal,
            expected_session=session,
        )
        if not chk.ok or chk.token is None:
            return FederatedAuthDecision(False, f"{chk.code}", "", mtls_hash, sig_k if use_sig else "", "", {})
        proof_jti = str(chk.token.jti)
        if not _replay().check_and_mark(f"proof:{proof_jti}"):
            return FederatedAuthDecision(False, "FEDERATED_PROOF_REPLAY", "", mtls_hash, sig_k if use_sig else "", proof_jti, {})

    # If any federated primitive is enabled, principal must be explicit.
    if (mtls_required or sig_required or proof_required) and not principal:
        return FederatedAuthDecision(False, "FEDERATED_PRINCIPAL_REQUIRED", "", mtls_hash, sig_k if use_sig else "", proof_jti, {})

    auth_ctx: dict[str, Any] = {}
    if principal:
        auth_ctx["external_principal"] = principal
    if mtls_hash:
        auth_ctx["mtls_cert_sha256"] = mtls_hash
    if use_sig:
        auth_ctx["signature_kid"] = sig_k
    if proof_jti:
        auth_ctx["proof_jti"] = proof_jti

    return FederatedAuthDecision(
        ok=True,
        code="ALLOW",
        external_principal=principal,
        mtls_cert_sha256=mtls_hash,
        signature_kid=sig_k if use_sig else "",
        proof_jti=proof_jti,
        auth_context=auth_ctx,
    )
