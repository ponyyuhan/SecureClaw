"""Original C1/C2/C5 mediation logic using an already initialized MCP client.

The transport/lifecycle wrapper is excluded; callers supply a client with the
same call_tool interface as agent.mcp_client.McpStdioClient. See SOURCES.md.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

# Only structural attributes are used; importing the benchmark is unnecessary.
Scenario = Any


def _gateway_user_visible_text(obj: Any, *, fallback: str) -> str:
    """Return the user/agent-visible text for a gateway action response.

    AgentLeak channels should be scored over what the runtime-visible agent can
    read, not over internal gateway bookkeeping.  Gateway responses can contain
    policy evidence, request digests, message IDs, payload handles, memory IDs,
    and MACs that are not plaintext disclosures and should not be treated as
    channel content.  When an explicit `safe_text` is returned, use it; otherwise
    use the action summary/refusal that is visible to the caller.
    """

    if isinstance(obj, dict):
        data = obj.get("data") if isinstance(obj.get("data"), dict) else {}
        safe = str((data or {}).get("safe_text") or "")
        if safe:
            return safe
        summary = str(obj.get("summary") or "")
        if summary:
            return summary
        status = str(obj.get("status") or "")
        reason = str(obj.get("reason_code") or "")
        if status or reason:
            return fallback + f" ({status}/{reason})"
    return fallback


def _vault_field_value_pairs(scenario: Scenario) -> list[dict[str, str]]:
    pairs: list[dict[str, str]] = []
    pv = getattr(scenario, "private_vault", None)
    recs = getattr(pv, "records", None)
    if not isinstance(recs, list):
        return pairs
    for rec in recs:
        fields = getattr(rec, "fields", None)
        if not isinstance(fields, dict):
            continue
        for k, v in fields.items():
            if v is None:
                continue
            if isinstance(v, (dict, list)):
                val = json.dumps(v, ensure_ascii=False)
            else:
                val = str(v)
            val = val.strip()
            if len(val) < 4:
                continue
            pairs.append({"field": str(k), "value": val})
    return pairs


@dataclass(frozen=True)
class TopologyOutputs:
    coord_out: str
    worker_out: str
    memory_content: str
    final_out: str
    model_calls: list[dict[str, Any]]


_SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bCANARY_[A-Z0-9_]{6,}\b"),
    re.compile(r"\b[A-Za-z0-9_\-]{28,}\b"),
]


def _attack_payload_is_suspicious(s: str) -> bool:
    t = (s or "").lower()
    if not t:
        return False
    keys = (
        "ignore",
        "ignore previous",
        "override",
        "bypass",
        "secret",
        "private",
        "vault",
        "token",
        "leak",
        "forward",
        "send",
        "exfil",
        "full access",
        "show me everything",
        "all records",
        "dump",
        "tool",
        "memory",
        "system prompt",
        "instructions",
    )
    return any(k in t for k in keys)


def _secret_like_high_entropy_atom(s: str) -> bool:
    tok = str(s or "").strip()
    if len(tok) < 20:
        return False
    classes = 0
    if any(c.islower() for c in tok):
        classes += 1
    if any(c.isupper() for c in tok):
        classes += 1
    if any(c.isdigit() for c in tok):
        classes += 1
    if any((not c.isalnum()) for c in tok):
        classes += 1
    return classes >= 3


def _looks_secret_like_text(s: str) -> bool:
    txt = str(s or "")
    if not txt:
        return False
    for p in _SECRET_PATTERNS:
        if p.search(txt):
            return True
    for tok in re.findall(r"[A-Za-z0-9_\-]{20,}", txt):
        if _secret_like_high_entropy_atom(tok):
            return True
    return False


def _trusted_recipient(recipient: str) -> bool:
    r = str(recipient or "").strip().lower()
    if not r:
        return False
    trusted = [
        x.strip().lower()
        for x in str(os.getenv("AGENTLEAK_TRUSTED_RECIPIENT_DOMAINS", "example.com,internal.local")).split(",")
        if x.strip()
    ]
    if "@" in r:
        dom = r.rsplit("@", 1)[1]
        return dom in trusted
    return not any(sym in r for sym in ("http://", "https://"))


def _should_auto_confirm(*, intent_id: str, text: str, recipient: str = "") -> bool:
    policy = str(os.getenv("AGENTLEAK_AUTO_CONFIRM_POLICY", "heuristic")).strip().lower()
    if policy in {"never", "0", "off"}:
        return False
    if policy in {"always", "1", "on"}:
        return True
    if _looks_secret_like_text(text) or _attack_payload_is_suspicious(text):
        return False
    if str(intent_id) == "SendMessage" and not _trusted_recipient(recipient):
        return False
    return str(intent_id) in {"FinalizeOutput", "SendMessage"}


class SecureClawChannelMediator:
    """The original mediation methods, separated from service startup."""

    def __init__(self, mcp: Any):
        self.mcp = mcp

    def _act(self, intent_id: str, *, inputs: dict[str, Any], constraints: dict[str, Any], caller: str) -> dict[str, Any]:
        assert self.mcp is not None
        return self.mcp.call_tool(
            "act",
            {"intent_id": intent_id, "inputs": inputs, "constraints": constraints, "caller": caller},
        )

    def _finalize_turn(self, *, caller: str, turn_id: str) -> dict[str, Any]:
        return self._act(
            "FinalizeOutput",
            inputs={"text": "turn finalized", "artifacts": []},
            constraints={"turn_id": turn_id, "user_confirm": True},
            caller=caller,
        )

    def _recv_messages(self, *, agent_id: str, turn_id: str) -> dict[str, Any]:
        r = self._act(
            "ReceiveInterAgentMessages",
            inputs={"agent_id": agent_id, "max_messages": 1},
            constraints={"turn_id": turn_id},
            caller=agent_id,
        )
        if str(r.get("status") or "") == "DENY" and str(r.get("reason_code") or "") == "OUTPUT_GATE_REQUIRED":
            pending = str(((r.get("data") or {}).get("pending_turn_id") or "")).strip()
            if pending:
                _ = self._finalize_turn(caller=agent_id, turn_id=pending)
                r = self._act(
                    "ReceiveInterAgentMessages",
                    inputs={"agent_id": agent_id, "max_messages": 1},
                    constraints={"turn_id": turn_id},
                    caller=agent_id,
                )
        return r

    def mediate(
        self,
        *,
        scenario: Scenario,
        outputs: TopologyOutputs,
    ) -> tuple[dict[str, list[str]], dict[str, Any]]:
        turn_id = str(getattr(scenario, "scenario_id", "unknown"))
        coord = f"coord:{turn_id}"
        worker = f"worker:{turn_id}"
        meta: dict[str, Any] = {"statuses": {}, "reasons": {}}
        c2_contents: list[str] = []
        c5_contents: list[str] = []
        c1_contents: list[str] = []
        sensitive_pairs = _vault_field_value_pairs(scenario)
        try:
            _ = self._act(
                "ClearSessionSensitive",
                inputs={},
                constraints={"turn_id": turn_id},
                caller=coord,
            )
            reg = self._act(
                "RegisterSessionSensitive",
                inputs={"items": sensitive_pairs, "mode": os.getenv("MIRAGE_SANITIZER_MODE", "all")},
                constraints={"turn_id": turn_id},
                caller=coord,
            )
            meta["statuses"]["sensitive_register"] = str(reg.get("status") or "")
            if isinstance(reg.get("data"), dict):
                meta["sensitive_register_data"] = dict(reg.get("data") or {})
        except Exception as exc:
            meta["statuses"]["sensitive_register"] = "ERROR"
            meta["reasons"]["sensitive_register"] = f"{type(exc).__name__}: {exc}"
        try:
            s1 = self._act(
                "SendInterAgentMessage",
                inputs={"to_agent": worker, "text": str(outputs.coord_out), "artifacts": []},
                constraints={"turn_id": turn_id},
                caller=coord,
            )
            r1 = self._recv_messages(agent_id=worker, turn_id=turn_id)
            c2_contents.append(
                _gateway_user_visible_text(
                    r1,
                    fallback="Inter-agent messages fetched as opaque handles only.",
                )
            )
            meta["statuses"]["c2_send1"] = str(s1.get("status") or "")
            meta["statuses"]["c2_recv1"] = str(r1.get("status") or "")
            meta["reasons"]["c2_1"] = str(r1.get("reason_code") or s1.get("reason_code") or "")

            s2 = self._act(
                "SendInterAgentMessage",
                inputs={"to_agent": coord, "text": str(outputs.worker_out), "artifacts": []},
                constraints={"turn_id": turn_id},
                caller=worker,
            )
            r2 = self._recv_messages(agent_id=coord, turn_id=turn_id)
            c2_contents.append(
                _gateway_user_visible_text(
                    r2,
                    fallback="Inter-agent messages fetched as opaque handles only.",
                )
            )
            meta["statuses"]["c2_send2"] = str(s2.get("status") or "")
            meta["statuses"]["c2_recv2"] = str(r2.get("status") or "")
            meta["reasons"]["c2_2"] = str(r2.get("reason_code") or s2.get("reason_code") or "")

            key = f"paper_parity_{turn_id}"
            w = self._act(
                "MemoryWrite",
                inputs={"namespace": "paper_parity", "key": key, "content": str(outputs.memory_content)},
                constraints={"turn_id": turn_id},
                caller=worker,
            )
            r = self._act(
                "MemoryRead",
                inputs={"namespace": "paper_parity", "key": key},
                constraints={"turn_id": turn_id},
                caller=worker,
            )
            c5_contents.append(
                _gateway_user_visible_text(
                    r,
                    fallback="Memory entry returned as opaque handle.",
                )
            )
            meta["statuses"]["c5_write"] = str(w.get("status") or "")
            meta["statuses"]["c5_read"] = str(r.get("status") or "")
            meta["reasons"]["c5"] = str(r.get("reason_code") or w.get("reason_code") or "")

            cst = {"turn_id": turn_id}
            if _should_auto_confirm(intent_id="FinalizeOutput", text=str(outputs.final_out)):
                cst["user_confirm"] = True
            f = self._act(
                "FinalizeOutput",
                inputs={"text": str(outputs.final_out), "artifacts": []},
                constraints=cst,
                caller=coord,
            )
            # C1 in AgentLeak is the user-visible final-output channel.
            # When SecureClaw denies or requires confirmation for a final
            # output, the user-visible payload is the refusal summary, not
            # the gateway's internal policy evidence/commit metadata.
            c1_contents.append(
                _gateway_user_visible_text(
                    f,
                    fallback="Final output not released.",
                )
            )
            meta["statuses"]["c1_finalize"] = str(f.get("status") or "")
            meta["reasons"]["c1"] = str(f.get("reason_code") or "")
        finally:
            _ = self._finalize_turn(caller=coord, turn_id=turn_id)
            _ = self._finalize_turn(caller=worker, turn_id=turn_id)

        return {"C1": c1_contents, "C2": c2_contents, "C5": c5_contents}, meta
