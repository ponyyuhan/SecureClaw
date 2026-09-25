from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


def _default_audit_path() -> str:
    # Keep artifacts out of the repo by default.
    return str(Path(__file__).resolve().parents[1] / "artifact_out" / "audit.jsonl")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    ts: int
    event: str
    session: str
    caller: str
    intent_id: str
    action_id: str = ""
    status: str = ""
    reason_code: str = ""
    data: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        out = {
            "ts": int(self.ts),
            "event": str(self.event),
            "session": str(self.session),
            "caller": str(self.caller),
            "intent_id": str(self.intent_id),
        }
        if self.action_id:
            out["action_id"] = str(self.action_id)
        if self.status:
            out["status"] = str(self.status)
        if self.reason_code:
            out["reason_code"] = str(self.reason_code)
        if self.data is not None:
            out["data"] = self.data
        return out


class AuditLogger:
    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._chain_key = bytes.fromhex((os.getenv("AUDIT_CHAIN_KEY_HEX") or "").strip()) if (os.getenv("AUDIT_CHAIN_KEY_HEX") or "").strip() else b""
        self._prev_hash: str = ""
        # Best-effort resume of hash-chained logs (if present).
        try:
            if self._path.exists() and self._path.stat().st_size > 0:
                # Read the last non-empty line without loading the whole file.
                data = self._path.read_bytes()
                tail = data[-16384:] if len(data) > 16384 else data
                lines = [ln for ln in tail.splitlines() if ln.strip()]
                if lines:
                    last = json.loads(lines[-1].decode("utf-8", errors="replace"))
                    if isinstance(last, dict) and isinstance(last.get("hash"), str):
                        self._prev_hash = str(last.get("hash") or "")
        except Exception:
            self._prev_hash = ""

    def log(self, ev: AuditEvent) -> None:
        # Optional tamper-evident chaining: include (prev_hash, hash) fields.
        payload = ev.to_dict()
        if self._chain_key or bool(int(os.getenv("AUDIT_CHAIN_SHA256", "1"))):
            base = dict(payload)
            base["prev_hash"] = str(self._prev_hash or "")
            msg = json.dumps(base, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
            if self._chain_key:
                digest = hmac.new(self._chain_key, msg, hashlib.sha256).hexdigest()
                base["hash_alg"] = "hmac_sha256"
            else:
                digest = hashlib.sha256(msg).hexdigest()
                base["hash_alg"] = "sha256"
            base["hash"] = str(digest)
            payload = base
            self._prev_hash = str(digest)
        line = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


_LOGGER: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    path = os.getenv("AUDIT_LOG_PATH", "").strip() or _default_audit_path()
    _LOGGER = AuditLogger(path)
    return _LOGGER


def now_ts() -> int:
    return int(time.time())
