from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, Field

from common.canonical import request_sha256_v1
from common.sanitize import SanitizePatch, apply_patch_to_domain, apply_patch_to_message

EXECUTOR_INSECURE_ALLOW = bool(int(os.getenv("EXECUTOR_INSECURE_ALLOW", "0")))


_confirm_key_warned = False


def _confirm_token_key() -> bytes | None:
    """Optional key for binding user confirmation to (action_id, request_sha)."""
    raw = (os.getenv("SECURECLAW_CONFIRM_TOKEN_KEY_HEX", "").strip()
           or os.getenv("CONFIRM_TOKEN_KEY_HEX", "").strip())
    if not raw:
        global _confirm_key_warned
        if not _confirm_key_warned:
            _logger.warning(
                "confirm_token: no SECURECLAW_CONFIRM_TOKEN_KEY_HEX set — "
                "confirmation binding degrades to bare boolean (trust-the-gateway).  "
                "Set the key for production."
            )
            _confirm_key_warned = True
        return None
    return bytes.fromhex(raw)


def _verify_confirm_token(action_id: str, request_sha: str, token: str) -> bool:
    """Verify that a confirm token binds to (action_id, request_sha).

    If no confirm token key is configured, falls back to accepting bare boolean
    (legacy mode) with a warning.
    """
    key = _confirm_token_key()
    if not key:
        # Legacy: no key configured, bare boolean accepted.
        return True
    expected = hmac.new(key, f"{action_id}|{request_sha}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, token)

POLICY_PROGRAM_ID = (os.getenv("MIRAGE_POLICY_PROGRAM_ID", "policy_unified_v1") or "policy_unified_v1").strip()

class _ReplayGuard:
    """
    Best-effort anti-replay guard for commit proofs.

    Without this, an attacker who captures a valid (dual) commit proof can attempt to
    replay it within the MAC TTL window. We treat each `action_id` as a one-time token
    and reject duplicates.

    Storage:
    - In-memory map by default.
    - Optional persistent sqlite via EXECUTOR_REPLAY_DB_PATH.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}
        self._ttl_s = int(os.getenv("EXECUTOR_REPLAY_TTL_S", "3600"))
        if self._ttl_s < 30:
            self._ttl_s = 30
        if self._ttl_s > 7 * 24 * 3600:
            self._ttl_s = 7 * 24 * 3600

        self._db_path = (os.getenv("EXECUTOR_REPLAY_DB_PATH", "") or "").strip() or None
        self._db: sqlite3.Connection | None = None
        if self._db_path:
            self._db = sqlite3.connect(self._db_path, check_same_thread=False)
            self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS replay (
                  action_id TEXT PRIMARY KEY,
                  seen_at REAL NOT NULL
                )
                """
            )
            self._db.commit()
        elif not os.getenv("SECURECLAW_ALLOW_VOLATILE_REPLAY"):
            _logger.warning(
                "replay_guard: no EXECUTOR_REPLAY_DB_PATH set — using volatile "
                "in-memory store.  Replay protection is lost on restart.  Set "
                "EXECUTOR_REPLAY_DB_PATH for production or export "
                "SECURECLAW_ALLOW_VOLATILE_REPLAY=1 to silence this warning."
            )

    def _prune_locked(self, now: float) -> None:
        # In-memory prune
        dead = [k for k, t in self._seen.items() if (now - float(t)) > float(self._ttl_s)]
        for k in dead:
            self._seen.pop(k, None)
        # Persistent prune (best-effort)
        if self._db is not None:
            try:
                self._db.execute("DELETE FROM replay WHERE seen_at < ?", (float(now - float(self._ttl_s)),))
                self._db.commit()
            except Exception:
                pass

    def check_and_mark(self, *, action_id: str) -> bool:
        """
        Returns True if this action_id is fresh and is now marked as used.
        Returns False if this action_id was already used (replay).
        """
        if not action_id:
            return False
        now = float(time.time())
        with self._lock:
            self._prune_locked(now)
            if action_id in self._seen:
                return False
            if self._db is not None:
                try:
                    row = self._db.execute("SELECT action_id FROM replay WHERE action_id=?", (str(action_id),)).fetchone()
                    if row:
                        return False
                    self._db.execute("INSERT OR REPLACE INTO replay(action_id, seen_at) VALUES (?,?)", (str(action_id), float(now)))
                    self._db.commit()
                except Exception:
                    # If persistent store fails, fall back to in-memory protection.
                    pass
            self._seen[str(action_id)] = now
            return True


_REPLAY_GUARD: _ReplayGuard | None = None


def _replay_guard() -> _ReplayGuard:
    global _REPLAY_GUARD
    if _REPLAY_GUARD is None:
        _REPLAY_GUARD = _ReplayGuard()
    return _REPLAY_GUARD

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(payload: dict) -> bytes:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _verify_mac(proof: dict, mac_key: bytes) -> bool:
    mac_b64 = proof.get("mac_b64")
    if not isinstance(mac_b64, str) or not mac_b64:
        return False
    payload = dict(proof)
    payload.pop("mac_b64", None)
    msg = _canonical_json_bytes(payload)
    want = hmac.new(mac_key, msg, hashlib.sha256).digest()
    try:
        got = base64.b64decode(mac_b64)
    except Exception:
        return False
    return hmac.compare_digest(want, got)


def _require_key(env_name: str) -> bytes:
    v = os.getenv(env_name, "").strip()
    if not v:
        raise RuntimeError(f"missing env {env_name}")
    return bytes.fromhex(v)


POLICY0_KEYS: dict[str, bytes] | None = None
POLICY1_KEYS: dict[str, bytes] | None = None
MAC_TTL_S = int(os.getenv("POLICY_MAC_TTL_S", "30"))
if MAC_TTL_S <= 0:
    MAC_TTL_S = 30


def _parse_mac_keys(s: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for part in (s or "").split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            kid, hexkey = part.split(":", 1)
        else:
            kid, hexkey = "0", part
        kid = kid.strip() or "0"
        hexkey = hexkey.strip()
        if not hexkey:
            continue
        out[kid] = bytes.fromhex(hexkey)
    return out


def _load_keys_for_server(server_id: int) -> dict[str, bytes]:
    global POLICY0_KEYS, POLICY1_KEYS
    if server_id == 0:
        if POLICY0_KEYS is None:
            multi = os.getenv("POLICY0_MAC_KEYS", "").strip()
            if multi:
                POLICY0_KEYS = _parse_mac_keys(multi)
            else:
                POLICY0_KEYS = {"0": _require_key("POLICY0_MAC_KEY")}
        return POLICY0_KEYS
    if server_id == 1:
        if POLICY1_KEYS is None:
            multi = os.getenv("POLICY1_MAC_KEYS", "").strip()
            if multi:
                POLICY1_KEYS = _parse_mac_keys(multi)
            else:
                POLICY1_KEYS = {"0": _require_key("POLICY1_MAC_KEY")}
        return POLICY1_KEYS
    raise ValueError("unexpected server_id")


def _mac_key_for_server(server_id: int, *, kid: str) -> bytes:
    keys = _load_keys_for_server(server_id)
    k = keys.get(kid)
    if not k:
        raise ValueError("unknown_kid")
    return k


def _validate_proof_common(proof: dict, *, kind: str, action_id: str, db: str) -> tuple[bool, str]:
    if not isinstance(proof, dict):
        return False, "bad_proof"
    if proof.get("v") != 1:
        return False, "bad_proof_version"
    if proof.get("kind") != kind:
        return False, "bad_proof_kind"
    if proof.get("action_id") != action_id:
        return False, "bad_action_id"
    if proof.get("db") != db:
        return False, "bad_db"
    try:
        ts = int(proof.get("ts"))
    except Exception:
        return False, "bad_ts"
    now = int(time.time())
    if abs(now - ts) > MAC_TTL_S:
        return False, "expired_proof"
    try:
        server_id = int(proof.get("server_id"))
    except Exception:
        return False, "bad_server_id"
    kid = str(proof.get("kid") or "0")
    try:
        key = _mac_key_for_server(server_id, kid=kid)
    except Exception:
        return False, "unknown_kid"
    if not _verify_mac(proof, key):
        return False, "bad_mac"
    return True, "OK"


def _validate_commit_proof_common(proof: dict, *, action_id: str, program_id: str, request_sha256: str) -> tuple[bool, str]:
    if not isinstance(proof, dict):
        return False, "bad_proof"
    if proof.get("v") != 1:
        return False, "bad_proof_version"
    if proof.get("kind") != "commit":
        return False, "bad_proof_kind"
    if proof.get("action_id") != action_id:
        return False, "bad_action_id"
    if proof.get("program_id") != program_id:
        return False, "bad_program_id"
    if proof.get("request_sha256") != request_sha256:
        return False, "bad_request_sha256"
    try:
        ts = int(proof.get("ts"))
    except Exception:
        return False, "bad_ts"
    now = int(time.time())
    if abs(now - ts) > MAC_TTL_S:
        return False, "expired_proof"
    try:
        server_id = int(proof.get("server_id"))
    except Exception:
        return False, "bad_server_id"
    kid = str(proof.get("kid") or "0")
    try:
        key = _mac_key_for_server(server_id, kid=kid)
    except Exception:
        return False, "unknown_kid"
    if not _verify_mac(proof, key):
        return False, "bad_mac"
    return True, "OK"


def _verify_commit_evidence(commit: dict, *, action_id: str, program_id: str, request_sha256: str) -> tuple[Optional[dict[str, int]], Optional[bytes], str]:
    if not isinstance(commit, dict):
        return None, None, "missing_commit"
    p0 = commit.get("policy0")
    p1 = commit.get("policy1")
    ok0, code0 = _validate_commit_proof_common(p0, action_id=action_id, program_id=program_id, request_sha256=request_sha256)
    if not ok0:
        return None, None, code0
    ok1, code1 = _validate_commit_proof_common(p1, action_id=action_id, program_id=program_id, request_sha256=request_sha256)
    if not ok1:
        return None, None, code1

    # Interface-level binding: commit evidence must contain one share per server.
    # We require `policy0.server_id=0` and `policy1.server_id=1` to match the wire format,
    # and to prevent any ambiguity in audit logs and replay tracking.
    try:
        sid0 = int((p0 or {}).get("server_id"))
        sid1 = int((p1 or {}).get("server_id"))
    except Exception:
        return None, None, "bad_server_id"
    if sid0 != 0 or sid1 != 1 or sid0 == sid1:
        return None, None, "server_id_mismatch"

    outs0 = p0.get("outputs") if isinstance(p0, dict) else None
    outs1 = p1.get("outputs") if isinstance(p1, dict) else None
    if not isinstance(outs0, dict) or not isinstance(outs1, dict):
        return None, None, "bad_outputs"

    # Reconstruct outputs by XOR-ing shares.
    outs: dict[str, int] = {}
    keys = set(str(k) for k in outs0.keys()) | set(str(k) for k in outs1.keys())
    for k in keys:
        a = int(outs0.get(k, 0)) & 1
        b = int(outs1.get(k, 0)) & 1
        outs[str(k)] = (a ^ b) & 1

    tag0_b64 = str((p0 or {}).get("commit_tag_share_b64") or "")
    tag1_b64 = str((p1 or {}).get("commit_tag_share_b64") or "")
    try:
        t0 = base64.b64decode(tag0_b64) if tag0_b64 else b""
        t1 = base64.b64decode(tag1_b64) if tag1_b64 else b""
    except Exception:
        return None, None, "bad_commit_tag_b64"
    # Semantic constraint: commit tag shares are fixed-width so audit records are uniform and
    # the executor acceptance predicate is machine-checkable.
    want_tag_len = int(os.getenv("COMMIT_TAG_LEN_BYTES", "16") or "16")
    if want_tag_len < 8:
        want_tag_len = 8
    if want_tag_len > 64:
        want_tag_len = 64
    if len(t0) != len(t1) or len(t0) != want_tag_len:
        return None, None, "bad_commit_tag_len"
    tag = bytes([x ^ y for x, y in zip(t0, t1)])

    # Semantic constraint: require a stable output interface.
    for need in ("allow_pre", "need_confirm", "patch0", "patch1"):
        if need not in outs:
            return None, None, "missing_output_key"
    return outs, tag, "OK"


def _verify_bit_batch_evidence(ev: dict, *, action_id: str, logical_db: str, allowed_dbs: list[str]) -> tuple[Optional[List[int]], str]:
    if not isinstance(ev, dict):
        return None, "missing_evidence"
    actual_db = str(ev.get("db") or "")
    if actual_db not in set(str(x) for x in (allowed_dbs or [])):
        return None, "unexpected_db"
    if ev.get("action_id") != action_id:
        return None, "evidence_mismatch"
    a0 = ev.get("a0")
    a1 = ev.get("a1")
    if not isinstance(a0, list) or not isinstance(a1, list) or len(a0) != len(a1):
        return None, "bad_share_lists"
    p0 = ev.get("policy0")
    p1 = ev.get("policy1")
    ok0, code0 = _validate_proof_common(p0, kind="bit", action_id=action_id, db=actual_db)
    if not ok0:
        return None, code0
    ok1, code1 = _validate_proof_common(p1, kind="bit", action_id=action_id, db=actual_db)
    if not ok1:
        return None, code1

    # Bind resp_sha256 to the actual shares.
    if _sha256_hex(bytes([int(x) & 1 for x in a0])) != p0.get("resp_sha256"):
        return None, "resp_hash_mismatch_p0"
    if _sha256_hex(bytes([int(x) & 1 for x in a1])) != p1.get("resp_sha256"):
        return None, "resp_hash_mismatch_p1"

    recon = [(int(x) & 1) ^ (int(y) & 1) for x, y in zip(a0, a1)]
    return recon, "OK"


def _verify_block_step(step: dict, *, action_id: str, db: str, block_size: int) -> tuple[Optional[bytes], str]:
    if not isinstance(step, dict):
        return None, "bad_step"
    pr = step.get("proof")
    if not isinstance(pr, dict):
        return None, "bad_step_proof"
    if pr.get("db") != db or pr.get("action_id") != action_id:
        return None, "step_mismatch"
    if int(pr.get("block_size", 0)) != int(block_size):
        return None, "block_size_mismatch"

    p0 = pr.get("policy0")
    p1 = pr.get("policy1")
    ok0, code0 = _validate_proof_common(p0, kind="block", action_id=action_id, db=db)
    if not ok0:
        return None, code0
    ok1, code1 = _validate_proof_common(p1, kind="block", action_id=action_id, db=db)
    if not ok1:
        return None, code1

    s0_b64 = pr.get("s0_b64") or []
    s1_b64 = pr.get("s1_b64") or []
    if not isinstance(s0_b64, list) or not isinstance(s1_b64, list) or len(s0_b64) != len(s1_b64):
        return None, "bad_block_share_lists"
    if len(s0_b64) != 1:
        return None, "expected_single_block"
    try:
        b0 = base64.b64decode(s0_b64[0])
        b1 = base64.b64decode(s1_b64[0])
    except Exception:
        return None, "bad_block_b64"
    if len(b0) != block_size or len(b1) != block_size:
        return None, "bad_block_size"

    if _sha256_hex(b0) != p0.get("resp_sha256"):
        return None, "resp_hash_mismatch_block_p0"
    if _sha256_hex(b1) != p1.get("resp_sha256"):
        return None, "resp_hash_mismatch_block_p1"

    blk = bytes([x ^ y for x, y in zip(b0, b1)])
    return blk, "OK"


def _verify_dfa_evidence(dfa_ev: dict, *, text: str, action_id: str) -> tuple[Optional[bool], str]:
    if not isinstance(dfa_ev, dict):
        return None, "missing_dfa"
    db = str(dfa_ev.get("db") or "dfa_transitions")
    alpha = int(dfa_ev.get("alpha", 0))
    block_size = int(dfa_ev.get("block_size", 0))
    char_to_sym = dfa_ev.get("char_to_sym") or {}
    steps = dfa_ev.get("steps") or []
    if alpha <= 0 or block_size <= 0:
        return None, "bad_dfa_config"
    if not isinstance(char_to_sym, dict) or not isinstance(steps, list):
        return None, "bad_dfa_evidence"

    # Normalize text exactly like gateway.
    s = (text or "").upper().replace("\n", " ")
    max_chars = int(os.getenv("MAX_DFA_SCAN_CHARS", "256"))
    if max_chars < 16:
        max_chars = 16
    if max_chars > 4096:
        max_chars = 4096
    if len(s) > max_chars:
        s = s[:max_chars]
    pad_steps = bool(int(os.getenv("PAD_DFA_STEPS", "0")))
    if pad_steps and len(s) < max_chars:
        s = s + ("~" * (max_chars - len(s)))

    n_chars = len(s)
    n_steps = len(steps)
    if pad_steps:
        # Padded mode emits exactly MAX_DFA_SCAN_CHARS steps.
        if n_steps != n_chars:
            return None, "dfa_step_count_mismatch_padded"
    else:
        # Unpadded mode may early-stop exactly at first matched step.
        if n_steps > n_chars:
            return None, "dfa_step_count_oversized"

    state = 0
    matched_any = False
    for i in range(n_steps):
        ch = s[i]
        sym = int(char_to_sym.get(ch, 0))
        expected_idx = (state * alpha) + sym
        step = steps[i]
        if int(step.get("idx", -1)) != expected_idx:
            return None, "dfa_idx_mismatch"
        blk, code = _verify_block_step(step, action_id=action_id, db=db, block_size=block_size)
        if blk is None:
            return None, code
        # next_state u16 + match flag byte
        state = int.from_bytes(blk[0:2], "little", signed=False)
        if (blk[2] & 1) == 1:
            matched_any = True
            if not pad_steps:
                # Gateway returns immediately at first match when unpadded.
                if i + 1 != n_steps:
                    return None, "dfa_unpadded_trailing_steps_after_match"
                return True, "OK"

    if not pad_steps and n_steps < n_chars:
        # In unpadded mode, truncation is only valid if a match occurred.
        return None, "dfa_unpadded_truncated_without_match"
    return matched_any, "OK"


class ExecSendMessageReq(BaseModel):
    action_id: str
    channel: str = "email"
    recipient: str
    domain: str = ""
    text: str
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    dlp_mode: str = "fourgram"
    evidence: dict[str, Any] = Field(default_factory=dict)
    commit: dict[str, Any] = Field(default_factory=dict)
    caller: str = ""
    session: str = ""
    user_confirm: bool = False
    confirm_token: str = ""
    external_principal: str = ""
    delegation_jti: str = ""
    contextual_targets_sha256: str = ""
    capsule_hash: str = ""


class ExecFetchReq(BaseModel):
    action_id: str
    resource_id: str = "example"
    domain: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    commit: dict[str, Any] = Field(default_factory=dict)
    caller: str = ""
    session: str = ""
    user_confirm: bool = False
    confirm_token: str = ""
    recipient: str = ""
    text: str = ""
    external_principal: str = ""
    delegation_jti: str = ""
    contextual_targets_sha256: str = ""
    capsule_hash: str = ""


class ExecWebhookReq(BaseModel):
    action_id: str
    domain: str
    path: str = "/"
    body: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    commit: dict[str, Any] = Field(default_factory=dict)
    caller: str = ""
    session: str = ""
    user_confirm: bool = False
    confirm_token: str = ""
    recipient: str = ""
    text: str = ""
    external_principal: str = ""
    delegation_jti: str = ""
    contextual_targets_sha256: str = ""
    capsule_hash: str = ""

class ExecSkillInstallReq(BaseModel):
    action_id: str
    skill_id: str
    skill_digest: str
    commit: dict[str, Any] = Field(default_factory=dict)
    caller: str = ""
    session: str = ""
    user_confirm: bool = False
    confirm_token: str = ""
    external_principal: str = ""
    delegation_jti: str = ""


app = FastAPI(title="MIRAGE-OG++ Executor", version="0.1")


def _req_hash_context(*, external_principal: str, delegation_jti: str, contextual_targets_sha256: str = "", capsule_hash: str = "") -> dict[str, Any]:
    ctx: dict[str, Any] = {}
    ep = str(external_principal or "").strip()
    dj = str(delegation_jti or "").strip()
    ct = str(contextual_targets_sha256 or "").strip()
    ch = str(capsule_hash or "").strip()
    if ep:
        ctx["external_principal"] = ep
    if dj:
        ctx["delegation_jti"] = dj
    if ct:
        ctx["contextual_targets_sha256"] = ct
    if ch:
        ctx["capsule_hash"] = ch
    return ctx


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/exec/send_message")
def exec_send_message(req: ExecSendMessageReq):
    action_id = req.action_id
    ev = req.evidence or {}

    if EXECUTOR_INSECURE_ALLOW:
        # Baseline / ablation: executor that does not enforce dual authorization.
        return {"status": "OK", "reason_code": "ALLOW_INSECURE", "data": {"recipient": req.recipient, "sent_chars": len(req.text)}}

    # Hard-stop: never allow exporting handles as artifacts in this demo executor.
    if req.artifacts:
        return {"status": "DENY", "reason_code": "ARTIFACTS_NOT_ALLOWED"}

    # New path: PREVIEW->COMMIT commit tokens from both policy servers.
    if isinstance(req.commit, dict) and req.commit.get("policy0") and req.commit.get("policy1"):
        hctx = _req_hash_context(
            external_principal=req.external_principal,
            delegation_jti=req.delegation_jti,
            contextual_targets_sha256=req.contextual_targets_sha256,
            capsule_hash=req.capsule_hash,
        )
        request_sha = request_sha256_v1(
            intent_id="SendMessage",
            caller=str(req.caller or ""),
            session=str(req.session or ""),
            inputs={"channel": str(req.channel), "recipient": str(req.recipient), "domain": str(req.domain), "text": str(req.text)},
            context=hctx,
        )
        outs, tag, code = _verify_commit_evidence(req.commit, action_id=action_id, program_id=POLICY_PROGRAM_ID, request_sha256=request_sha)
        if outs is None:
            return {"status": "DENY", "reason_code": "BAD_COMMIT_PROOF", "details": code}
        allow_pre = int(outs.get("allow_pre", 0)) & 1
        need_confirm = int(outs.get("need_confirm", 0)) & 1
        patch0 = int(outs.get("patch0", 0)) & 1
        patch1 = int(outs.get("patch1", 0)) & 1
        patch_id = (patch0 | (patch1 << 1)) & 3
        if allow_pre != 1:
            return {"status": "DENY", "reason_code": "POLICY_DENY"}
        if need_confirm == 1:
            if not bool(req.user_confirm):
                patch = SanitizePatch(patch_id, {})
                preview = apply_patch_to_message(text=req.text, patch=patch)
                return {"status": "DENY", "reason_code": "REQUIRE_CONFIRM", "data": {"text_preview": preview[:200]}}
            # Verify confirmation binds to this specific (action_id, request_sha).
            if not _verify_confirm_token(action_id, request_sha, req.confirm_token):
                return {"status": "DENY", "reason_code": "BAD_CONFIRM_TOKEN"}

        # Anti-replay: each (action_id, commit proof pair) should be usable at most once.
        if not _replay_guard().check_and_mark(action_id=str(action_id)):
            return {"status": "DENY", "reason_code": "REPLAY_DENY"}
        patch = SanitizePatch(patch_id, {})
        out_text = apply_patch_to_message(text=req.text, patch=patch)
        return {
            "status": "OK",
            "reason_code": "ALLOW",
            "data": {"recipient": req.recipient, "sent_chars": len(out_text), "commit_tag_b64": base64.b64encode(tag or b"").decode("ascii")},
        }

    # Recipient allowlist must be proven by both servers.
    recon, code = _verify_bit_batch_evidence(
        ev.get("allow_recipients") or {},
        action_id=action_id,
        logical_db="allow_recipients",
        allowed_dbs=["allow_recipients", os.getenv("POLICY_BUNDLE_DB", "policy_bundle")],
    )
    if recon is None or not recon or recon[0] != 1:
        return {"status": "DENY", "reason_code": "RECIPIENT_NOT_ALLOWED", "details": code}

    # DLP checks
    dlp_mode = (req.dlp_mode or "fourgram").strip().lower()
    hits, code2 = _verify_bit_batch_evidence(
        ev.get("banned_tokens") or {},
        action_id=action_id,
        logical_db="banned_tokens",
        allowed_dbs=["banned_tokens", os.getenv("POLICY_BUNDLE_DB", "policy_bundle")],
    )
    if hits is None:
        return {"status": "DENY", "reason_code": "MISSING_DLP_PROOF", "details": code2}

    has_hit = any(int(h) == 1 for h in hits)
    if not has_hit:
        return {"status": "OK", "reason_code": "ALLOW"}

    if dlp_mode != "dfa":
        return {"status": "DENY", "reason_code": "DLP_BLOCKED"}

    matched, code3 = _verify_dfa_evidence(ev.get("dfa") or {}, text=req.text, action_id=action_id)
    if matched is None:
        return {"status": "DENY", "reason_code": "BAD_DFA_PROOF", "details": code3}
    if matched:
        return {"status": "DENY", "reason_code": "DLP_BLOCKED"}
    return {"status": "OK", "reason_code": "ALLOW"}


@app.post("/exec/fetch")
def exec_fetch(req: ExecFetchReq):
    action_id = req.action_id
    ev = req.evidence or {}

    if EXECUTOR_INSECURE_ALLOW:
        return {"status": "OK", "reason_code": "ALLOW_INSECURE", "data": {"resource_id": req.resource_id, "domain": req.domain, "content_preview": "<html>...</html>"}}

    if isinstance(req.commit, dict) and req.commit.get("policy0") and req.commit.get("policy1"):
        hctx = _req_hash_context(
            external_principal=req.external_principal,
            delegation_jti=req.delegation_jti,
            contextual_targets_sha256=req.contextual_targets_sha256,
            capsule_hash=req.capsule_hash,
        )
        request_sha = request_sha256_v1(
            intent_id="FetchResource",
            caller=str(req.caller or ""),
            session=str(req.session or ""),
            inputs={"resource_id": str(req.resource_id), "recipient": str(req.recipient), "domain": str(req.domain), "text": str(req.text)},
            context=hctx,
        )
        outs, tag, code = _verify_commit_evidence(req.commit, action_id=action_id, program_id=POLICY_PROGRAM_ID, request_sha256=request_sha)
        if outs is None:
            return {"status": "DENY", "reason_code": "BAD_COMMIT_PROOF", "details": code}
        allow_pre = int(outs.get("allow_pre", 0)) & 1
        need_confirm = int(outs.get("need_confirm", 0)) & 1
        if allow_pre != 1:
            return {"status": "DENY", "reason_code": "POLICY_DENY"}
        if need_confirm == 1:
            if not bool(req.user_confirm):
                return {"status": "DENY", "reason_code": "REQUIRE_CONFIRM"}
            if not _verify_confirm_token(action_id, request_sha, req.confirm_token):
                return {"status": "DENY", "reason_code": "BAD_CONFIRM_TOKEN"}
        if not _replay_guard().check_and_mark(action_id=str(action_id)):
            return {"status": "DENY", "reason_code": "REPLAY_DENY"}
        return {
            "status": "OK",
            "reason_code": "ALLOW",
            "data": {"resource_id": req.resource_id, "domain": req.domain, "content_preview": "<html>...</html>", "commit_tag_b64": base64.b64encode(tag or b"").decode("ascii")},
        }

    recon, code = _verify_bit_batch_evidence(
        ev.get("allow_domains") or {},
        action_id=action_id,
        logical_db="allow_domains",
        allowed_dbs=["allow_domains", os.getenv("POLICY_BUNDLE_DB", "policy_bundle")],
    )
    if recon is None or not recon or recon[0] != 1:
        return {"status": "DENY", "reason_code": "DOMAIN_NOT_ALLOWED", "details": code}

    # Offline demo: return a canned response.
    return {
        "status": "OK",
        "reason_code": "ALLOW",
        "data": {"resource_id": req.resource_id, "domain": req.domain, "content_preview": "<html>...</html>"},
    }


@app.post("/exec/webhook")
def exec_webhook(req: ExecWebhookReq):
    action_id = req.action_id
    if EXECUTOR_INSECURE_ALLOW:
        return {"status": "OK", "reason_code": "ALLOW_INSECURE", "data": {"domain": req.domain, "path": req.path, "sent_chars": len(req.body)}}
    if isinstance(req.commit, dict) and req.commit.get("policy0") and req.commit.get("policy1"):
        hctx = _req_hash_context(
            external_principal=req.external_principal,
            delegation_jti=req.delegation_jti,
            contextual_targets_sha256=req.contextual_targets_sha256,
            capsule_hash=req.capsule_hash,
        )
        request_sha = request_sha256_v1(
            intent_id="PostWebhook",
            caller=str(req.caller or ""),
            session=str(req.session or ""),
            inputs={"path": str(req.path), "body": str(req.body), "recipient": str(req.recipient), "domain": str(req.domain), "text": str(req.text)},
            context=hctx,
        )
        outs, tag, code = _verify_commit_evidence(req.commit, action_id=action_id, program_id=POLICY_PROGRAM_ID, request_sha256=request_sha)
        if outs is None:
            return {"status": "DENY", "reason_code": "BAD_COMMIT_PROOF", "details": code}
        allow_pre = int(outs.get("allow_pre", 0)) & 1
        need_confirm = int(outs.get("need_confirm", 0)) & 1
        patch0 = int(outs.get("patch0", 0)) & 1
        patch1 = int(outs.get("patch1", 0)) & 1
        patch_id = (patch0 | (patch1 << 1)) & 3
        if allow_pre != 1:
            return {"status": "DENY", "reason_code": "POLICY_DENY"}
        if need_confirm == 1:
            if not bool(req.user_confirm):
                patch = SanitizePatch(patch_id, {})
                preview = apply_patch_to_message(text=req.body, patch=patch)
                return {"status": "DENY", "reason_code": "REQUIRE_CONFIRM", "data": {"body_preview": preview[:200]}}
            if not _verify_confirm_token(action_id, request_sha, req.confirm_token):
                return {"status": "DENY", "reason_code": "BAD_CONFIRM_TOKEN"}
        if not _replay_guard().check_and_mark(action_id=str(action_id)):
            return {"status": "DENY", "reason_code": "REPLAY_DENY"}
        patch = SanitizePatch(patch_id, {})
        out_body = apply_patch_to_message(text=req.body, patch=patch)
        out_domain = apply_patch_to_domain(domain=req.domain, patch=patch)
        return {
            "status": "OK",
            "reason_code": "ALLOW",
            "data": {"domain": out_domain, "path": req.path, "sent_chars": len(out_body), "commit_tag_b64": base64.b64encode(tag or b"").decode("ascii")},
        }
    return {"status": "DENY", "reason_code": "MISSING_EVIDENCE"}

@app.post("/exec/skill_install")
def exec_skill_install(req: ExecSkillInstallReq):
    action_id = req.action_id
    if isinstance(req.commit, dict) and req.commit.get("policy0") and req.commit.get("policy1"):
        hctx = _req_hash_context(external_principal=req.external_principal, delegation_jti=req.delegation_jti)
        request_sha = request_sha256_v1(
            intent_id="CommitSkillInstall",
            caller=str(req.caller or ""),
            session=str(req.session or ""),
            inputs={"skill_id": str(req.skill_id), "skill_digest": str(req.skill_digest)},
            context=hctx,
        )
        outs, tag, code = _verify_commit_evidence(req.commit, action_id=action_id, program_id=POLICY_PROGRAM_ID, request_sha256=request_sha)
        if outs is None:
            return {"status": "DENY", "reason_code": "BAD_COMMIT_PROOF", "details": code}
        allow_pre = int(outs.get("allow_pre", 0)) & 1
        need_confirm = int(outs.get("need_confirm", 0)) & 1
        if allow_pre != 1:
            return {"status": "DENY", "reason_code": "POLICY_DENY"}
        if need_confirm == 1:
            if not bool(req.user_confirm):
                return {"status": "DENY", "reason_code": "REQUIRE_CONFIRM"}
            if not _verify_confirm_token(action_id, request_sha, req.confirm_token):
                return {"status": "DENY", "reason_code": "BAD_CONFIRM_TOKEN"}
        if not _replay_guard().check_and_mark(action_id=str(action_id)):
            return {"status": "DENY", "reason_code": "REPLAY_DENY"}

        # Side effect: record enabled skill into a local registry (demo).
        # This is intentionally outside the gateway so "enable" is tied to dual proofs.
        import json
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[1]
        reg_path = Path(os.getenv("SKILL_ENABLED_PATH", "") or (repo_root / "artifact_out" / "enabled_skills.json")).expanduser()
        reg_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(reg_path.read_text(encoding="utf-8")) if reg_path.exists() else {"skills": []}
        except Exception:
            data = {"skills": []}
        if not isinstance(data, dict):
            data = {"skills": []}
        if not isinstance(data.get("skills"), list):
            data["skills"] = []
        entry = {
            "ts": int(time.time()),
            "skill_id": str(req.skill_id),
            "skill_digest": str(req.skill_digest),
            "caller": str(req.caller or ""),
            "session": str(req.session or ""),
            "commit_tag_b64": base64.b64encode(tag or b"").decode("ascii"),
        }
        data["skills"].append(entry)
        reg_path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

        # Mint a short-lived workload token for per-skill identity (skill digest bound + session bound).
        # This lets the gateway override the untrusted `caller` string with a least-privilege workload identity.
        workload_token = ""
        workload_exp_ms = 0
        key_hex = os.getenv("WORKLOAD_TOKEN_KEY", "").strip()
        if key_hex:
            try:
                from common.workload_token import mint_workload_token

                ttl_s = int(os.getenv("WORKLOAD_TOKEN_TTL_S", "3600"))
                if ttl_s < 60:
                    ttl_s = 60
                if ttl_s > 7 * 24 * 3600:
                    ttl_s = 7 * 24 * 3600
                now_ms = int(time.time() * 1000)
                workload_token = mint_workload_token(
                    key_hex=key_hex,
                    skill_digest=str(req.skill_digest),
                    session=str(req.session or ""),
                    ttl_s=ttl_s,
                    now_ms=now_ms,
                )
                workload_exp_ms = now_ms + (ttl_s * 1000)
            except Exception:
                workload_token = ""
                workload_exp_ms = 0

        return {
            "status": "OK",
            "reason_code": "ALLOW",
            "data": {
                "skill_id": req.skill_id,
                "skill_digest": req.skill_digest,
                "commit_tag_b64": base64.b64encode(tag or b"").decode("ascii"),
                "workload_caller": f"skill:{req.skill_digest}",
                "workload_token": workload_token,
                "workload_exp_ms": int(workload_exp_ms),
            },
        }

    return {"status": "DENY", "reason_code": "MISSING_EVIDENCE"}


def main():
    port = int(os.getenv("EXECUTOR_PORT", "9100"))
    access_log = bool(int(os.getenv("ACCESS_LOG", "0")))
    host = (os.getenv("EXECUTOR_BIND") or "127.0.0.1").strip() or "127.0.0.1"
    uvicorn.run("executor_server.server:app", host=host, port=port, reload=False, access_log=access_log)


if __name__ == "__main__":
    main()
