from __future__ import annotations

import os
import re
from typing import Any, Dict

from ..handles import HandleStore
from ..memory_service import MemoryService

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xoxb-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN[ -].*?PRIVATE KEY-----"),
]

SM_DISABLED = bool(int(os.getenv("SECURECLAW_SM_DISABLED", "0")))


class MemoryExec:
    def __init__(self, handles: HandleStore, memory: MemoryService):
        self.handles = handles
        self.memory = memory

    def _classify(self, text: str) -> str:
        s = str(text or "")
        for p in _SECRET_PATTERNS:
            if p.search(s):
                return "HIGH"
        return (os.getenv("MEMORY_DEFAULT_SENSITIVITY", "MED") or "MED").strip().upper()

    def _mint_memory_handle(self, *, rec, session: str, caller: str):
        ttl = int(os.getenv("MEMORY_HANDLE_TTL_S", "900"))
        if ttl < 60:
            ttl = 60
        if ttl > 24 * 3600:
            ttl = 24 * 3600
        h = self.handles.mint(
            label="MEMORY_ENTRY",
            sensitivity=str(rec.sensitivity).upper(),
            value={
                "memory_id": rec.memory_id,
                "namespace": rec.namespace,
                "key": rec.key,
                "content": str((rec.value or {}).get("content", "")),
            },
            allowed_sinks=["Declassify", "InterAgentMessage"],
            session=session,
            ttl_seconds=ttl,
            caller=caller,
            issuer_intent="MemoryRead",
        )
        return {"handle": h.handle, "label": h.label, "sensitivity": h.sensitivity}

    def write(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        ns = str(inputs.get("namespace", "default"))
        key = str(inputs.get("key", "")).strip()
        text = str(inputs.get("content", ""))
        if not key:
            return {"status": "DENY", "summary": "Missing key.", "data": {}, "artifacts": [], "reason_code": "BAD_ARGS"}
        sens = str(inputs.get("sensitivity", "")).strip().upper()
        if sens not in ("LOW", "MED", "HIGH"):
            sens = self._classify(text)
        rec = self.memory.upsert(
            namespace=ns,
            key=key,
            value={"content": text},
            sensitivity=sens,
            session=session,
            caller=caller,
        )
        art = self._mint_memory_handle(rec=rec, session=session, caller=caller)
        return {
            "status": "OK",
            "summary": "Memory entry stored via mediated service (plaintext not returned).",
            "data": {"namespace": ns, "key": key, "memory_id": rec.memory_id, "sensitivity": rec.sensitivity},
            "artifacts": [art],
            "reason_code": "ALLOW",
        }

    def read(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        ns = str(inputs.get("namespace", "default"))
        key = str(inputs.get("key", "")).strip()
        if not key:
            return {"status": "DENY", "summary": "Missing key.", "data": {}, "artifacts": [], "reason_code": "BAD_ARGS"}
        rec = self.memory.get_by_key(namespace=ns, key=key, session=session, caller=caller)
        if rec is None:
            return {"status": "DENY", "summary": "Memory entry not found.", "data": {"namespace": ns, "key": key}, "artifacts": [], "reason_code": "MEMORY_NOT_FOUND"}
        if SM_DISABLED:
            content = str((rec.value or {}).get("content", ""))
            return {
                "status": "OK",
                "summary": "Memory entry returned as plaintext (SM disabled).",
                "data": {"namespace": ns, "key": key, "memory_id": rec.memory_id, "content": content},
                "artifacts": [],
                "reason_code": "ALLOW_SM_DISABLED",
            }
        art = self._mint_memory_handle(rec=rec, session=session, caller=caller)
        return {
            "status": "OK",
            "summary": "Memory entry returned as opaque handle.",
            "data": {"namespace": ns, "key": key, "memory_id": rec.memory_id, "sensitivity": rec.sensitivity},
            "artifacts": [art],
            "reason_code": "ALLOW",
        }

    def list_keys(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        ns = str(inputs.get("namespace", "default"))
        limit = int(inputs.get("limit", 100))
        keys = self.memory.list_keys(namespace=ns, session=session, caller=caller, limit=limit)
        return {
            "status": "OK",
            "summary": "Memory keys listed.",
            "data": {"namespace": ns, "keys": keys},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def delete(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        ns = str(inputs.get("namespace", "default"))
        key = str(inputs.get("key", "")).strip()
        if not key:
            return {"status": "DENY", "summary": "Missing key.", "data": {}, "artifacts": [], "reason_code": "BAD_ARGS"}
        ok = self.memory.revoke(namespace=ns, key=key, session=session, caller=caller)
        return {
            "status": "OK" if ok else "DENY",
            "summary": "Memory entry deleted." if ok else "Memory entry not found.",
            "data": {"namespace": ns, "key": key},
            "artifacts": [],
            "reason_code": "ALLOW" if ok else "MEMORY_NOT_FOUND",
        }
