from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from ..handles import HandleStore
from ..interagent_store import InterAgentStore

_SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xoxb-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN[ -].*?PRIVATE KEY-----"),
]

SM_DISABLED = bool(int(os.getenv("SECURECLAW_SM_DISABLED", "0")))


class InterAgentExec:
    def __init__(self, handles: HandleStore, store: InterAgentStore):
        self.handles = handles
        self.store = store

    def _contains_secret(self, text: str) -> bool:
        s = str(text or "")
        for p in _SECRET_PATTERNS:
            if p.search(s):
                return True
        return False

    def send(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        to_agent = str(inputs.get("to_agent", "")).strip()
        if not to_agent:
            return {"status": "DENY", "summary": "Missing to_agent.", "data": {}, "artifacts": [], "reason_code": "BAD_ARGS"}

        text = str(inputs.get("text", ""))
        payload_handle = str(inputs.get("payload_handle", "")).strip()
        if text and payload_handle:
            return {
                "status": "DENY",
                "summary": "Provide either text or payload_handle, not both.",
                "data": {},
                "artifacts": [],
                "reason_code": "BAD_ARGS",
            }

        if not text and not payload_handle:
            return {"status": "DENY", "summary": "Missing message payload.", "data": {}, "artifacts": [], "reason_code": "BAD_ARGS"}

        if text and SM_DISABLED:
            msg = self.store.enqueue(
                session=session,
                from_agent=caller,
                to_agent=to_agent,
                payload_handle=f"__plaintext__{text}",
                attachment_handles=[],
            )
            return {
                "status": "OK",
                "summary": "Inter-agent message enqueued (SM disabled — plaintext).",
                "data": {"message_id": msg.message_id, "to_agent": to_agent, "content": text},
                "artifacts": [],
                "reason_code": "ALLOW_SM_DISABLED",
            }

        if text:
            default_sens = (os.getenv("INTER_AGENT_DEFAULT_SENSITIVITY", "HIGH") or "HIGH").strip().upper()
            sensitivity = default_sens
            if default_sens == "MED" and self._contains_secret(text):
                sensitivity = "HIGH"
            # Strong mediation: receiver gets a fresh handle bound to the receiver identity.
            rec = self.handles.mint(
                label="INTER_AGENT_MESSAGE",
                sensitivity=sensitivity,
                value={"content": text, "to_agent": to_agent, "from_agent": caller},
                allowed_sinks=["Declassify", "InterAgentMessage"],
                session=session,
                ttl_seconds=int(os.getenv("INTER_AGENT_TTL_S", "900")),
                caller=to_agent,
                issuer_intent="SendInterAgentMessage",
            )
            payload_handle = rec.handle
            payload_artifact = {"handle": rec.handle, "label": rec.label, "sensitivity": rec.sensitivity}
        else:
            rec = self.handles.get(payload_handle)
            if not rec or rec.session != session:
                return {"status": "DENY", "summary": "Invalid payload handle.", "data": {}, "artifacts": [], "reason_code": "HANDLE_INVALID"}
            if rec.caller != caller:
                return {"status": "DENY", "summary": "Payload handle bound to different caller.", "data": {}, "artifacts": [], "reason_code": "HANDLE_CALLER_MISMATCH"}
            if "InterAgentMessage" not in (rec.allowed_sinks or []):
                return {"status": "DENY", "summary": "Handle cannot be sent via inter-agent bus.", "data": {}, "artifacts": [], "reason_code": "HANDLE_SINK_BLOCKED"}
            # Re-wrap handle for receiver to preserve mediation and caller binding.
            rec2 = self.handles.mint(
                label=str(rec.label or "INTER_AGENT_MESSAGE"),
                sensitivity=str(rec.sensitivity or "MED").upper(),
                value=rec.value,
                allowed_sinks=["Declassify", "InterAgentMessage"],
                session=session,
                ttl_seconds=int(os.getenv("INTER_AGENT_TTL_S", "900")),
                caller=to_agent,
                issuer_intent="SendInterAgentMessage",
            )
            payload_handle = rec2.handle
            payload_artifact = {"handle": rec2.handle, "label": rec2.label, "sensitivity": rec2.sensitivity}

        artifact_handles: List[str] = []
        for a in (inputs.get("artifacts", []) or []):
            if not isinstance(a, dict):
                continue
            hid = str(a.get("handle", "")).strip()
            if not hid:
                continue
            h = self.handles.get(hid)
            if not h or h.session != session:
                return {"status": "DENY", "summary": "Invalid artifact handle.", "data": {"handle": hid}, "artifacts": [], "reason_code": "HANDLE_INVALID"}
            if h.caller != caller:
                return {"status": "DENY", "summary": "Artifact handle bound to different caller.", "data": {"handle": hid}, "artifacts": [], "reason_code": "HANDLE_CALLER_MISMATCH"}
            if "InterAgentMessage" not in (h.allowed_sinks or []):
                return {"status": "DENY", "summary": "Artifact handle cannot flow to inter-agent bus.", "data": {"handle": hid}, "artifacts": [], "reason_code": "HANDLE_SINK_BLOCKED"}
            artifact_handles.append(hid)

        msg = self.store.enqueue(
            session=session,
            from_agent=caller,
            to_agent=to_agent,
            payload_handle=payload_handle,
            attachment_handles=artifact_handles,
        )
        return {
            "status": "OK",
            "summary": "Inter-agent message enqueued with opaque handles only.",
            "data": {
                "message_id": msg.message_id,
                "to_agent": to_agent,
                "payload_handle": payload_handle,
                "attachment_handles": artifact_handles,
            },
            "artifacts": [payload_artifact],
            "reason_code": "ALLOW",
        }

    def receive(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        agent_id = str(inputs.get("agent_id", caller)).strip() or caller
        if agent_id != caller:
            return {
                "status": "DENY",
                "summary": "agent_id must match caller for mediated receive.",
                "data": {"agent_id": agent_id, "caller": caller},
                "artifacts": [],
                "reason_code": "AGENT_ID_MISMATCH",
            }
        n = int(inputs.get("max_messages", 10))
        if n < 1:
            n = 1
        if n > 50:
            n = 50
        msgs = self.store.recv(session=session, to_agent=agent_id, limit=n, mark_delivered=True)
        out: list[dict[str, Any]] = []
        for m in msgs:
            out.append(
                {
                    "message_id": m.message_id,
                    "from_agent": m.from_agent,
                    "to_agent": m.to_agent,
                    "payload_handle": m.payload_handle,
                    "attachment_handles": list(m.attachment_handles),
                    "created_at": float(m.created_at),
                }
            )
        return {
            "status": "OK",
            "summary": "Inter-agent messages fetched (opaque handles only).",
            "data": {"agent_id": agent_id, "messages": out, "pending_after": self.store.count_pending(session=session, to_agent=agent_id)},
            "artifacts": [],
            "reason_code": "ALLOW",
        }
