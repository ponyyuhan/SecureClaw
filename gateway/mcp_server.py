from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import requests
from pydantic import BaseModel, Field, ValidationError

from .config import settings
from .fss_pir import PirClient, MixedPirClient, PirMixConfig
from .guardrails import ObliviousGuardrails
from .handles import HandleStore
from .http_session import session_for
from .router import IntentRouter


MCP_PROTOCOL_VERSION = "2024-11-05"


class ActArgs(BaseModel):
    intent_id: str = Field(..., description="High-level intent ID (no low-level tools).")
    inputs: Dict[str, Any] = Field(default_factory=dict)
    constraints: Dict[str, Any] = Field(default_factory=dict)
    caller: str = Field(..., description="Skill/agent identity (untrusted).")


def _send(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def _jsonrpc_result(req_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Any | None = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": int(code), "message": str(message)}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _tool_result(structured: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    # MCP "tools/call" result: provide both text and structured output.
    return {
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=True)}],
        "structuredContent": structured,
        "isError": bool(is_error),
    }


def _tools_list() -> dict[str, Any]:
    # Minimal tool definition, matching gateway/schemas/act.schema.json semantically.
    return {
        "tools": [
            {
                # Prefer the simple name "act" for MCP hosts that map tools to
                # `mcp__{server}__{tool}` identifiers (avoids dots).
                "name": "act",
                "description": "Execute a high-level intent via MIRAGE gateway. The agent cannot access low-level tools directly.",
                "inputSchema": {
                    "type": "object",
                    "required": ["intent_id", "inputs", "constraints", "caller"],
                    "properties": {
                        "intent_id": {"type": "string"},
                        "inputs": {"type": "object"},
                        "constraints": {"type": "object"},
                        "caller": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            },
            {
                # Backwards-compatible alias used by this repo's Python demo client.
                "name": "mirage.act",
                "description": "Execute a high-level intent via MIRAGE gateway. The agent cannot access low-level tools directly.",
                "inputSchema": {
                    "type": "object",
                    "required": ["intent_id", "inputs", "constraints", "caller"],
                    "properties": {
                        "intent_id": {"type": "string"},
                        "inputs": {"type": "object"},
                        "constraints": {"type": "object"},
                        "caller": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }


class MirageMcpServer:
    def __init__(self) -> None:
        self._initialized = False

        handles = HandleStore()
        base_pir = PirClient(
            policy0_url=settings.policy_servers[0],
            policy1_url=settings.policy_servers[1],
            domain_size=settings.fss_domain_size,
            policy0_uds_path=(os.getenv("POLICY0_UDS_PATH") or "").strip() or None,
            policy1_uds_path=(os.getenv("POLICY1_UDS_PATH") or "").strip() or None,
        )
        pir = base_pir

        # Optional production shaping: cover traffic + batch mixing + oblivious bundle selection.
        # Best-effort: if policy servers aren't reachable yet, fall back to the direct client.
        if bool(int(os.getenv("PIR_MIX_ENABLED", "1"))):
            try:
                meta = session_for(base_pir.policy0_url).get(f"{base_pir.policy0_url}/meta", timeout=1.5).json()
                b = (meta.get("bundle") or {}) if isinstance(meta, dict) else {}
                bundle_enabled = bool(b.get("enabled")) if isinstance(b, dict) else False
                if bundle_enabled:
                    bundle_db = str(b.get("db") or os.getenv("POLICY_BUNDLE_DB", "policy_bundle"))
                    bundle_ds = int(b.get("bundle_domain_size") or 0)
                    if bundle_ds > 0:
                        max_tokens = int(settings.max_tokens_per_message)
                        max_domains = int(os.getenv("MAX_SKILL_DOMAINS", "8"))
                        if max_domains < 1:
                            max_domains = 1
                        if max_domains > 64:
                            max_domains = 64
                        fixed_n_keys = 2 + (2 * max_tokens) + max_domains
                        mix = PirMixConfig(
                            enabled=True,
                            interval_ms=int(os.getenv("PIR_MIX_INTERVAL_MS", "50")),
                            # Default to *no padding* (pad_to=1) to keep the paper
                            # pipeline's Python policy server baseline usable.
                            # For production hiding, raise this and enable cover traffic.
                            pad_to=int(os.getenv("PIR_MIX_PAD_TO", "1")),
                            fixed_n_keys=int(fixed_n_keys),
                            db_name=bundle_db,
                            domain_size=bundle_ds,
                            timeout_s=int(os.getenv("PIR_MIX_TIMEOUT_S", "10")),
                            cover_traffic=bool(int(os.getenv("PIR_COVER_TRAFFIC", "0"))),
                            lanes=int(os.getenv("PIR_MIX_LANES", "1")),
                            max_inflight=int(os.getenv("PIR_MIX_MAX_INFLIGHT", "1")),
                            schedule_mode=str(os.getenv("PIR_MIX_SCHEDULE", "fixed")),
                        )
                        pir = MixedPirClient(base_pir, mix=mix)
            except Exception:
                pir = base_pir
        guardrails = ObliviousGuardrails(
            pir=pir,
            handles=handles,
            domain_size=settings.fss_domain_size,
            max_tokens=settings.max_tokens_per_message,
        )
        self._router = IntentRouter(handles=handles, guardrails=guardrails)

    def serve_forever(self) -> None:
        # Stdio transport: one JSON-RPC message per line.
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                # Can't recover request id.
                _send(_jsonrpc_error(None, -32700, "Parse error"))
                continue
            self._handle_message(msg)

    def _handle_message(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        req_id = msg.get("id", None)
        params = msg.get("params") or {}

        # Notifications have no id and must not be answered.
        is_notification = "id" not in msg

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "mirage-ogpp-gateway", "version": "0.1"},
                }
                if not is_notification:
                    _send(_jsonrpc_result(req_id, result))
                return

            if method == "notifications/initialized":
                self._initialized = True
                return

            if method == "tools/list":
                if not is_notification:
                    _send(_jsonrpc_result(req_id, _tools_list()))
                return

            if method == "tools/call":
                if not self._initialized:
                    if not is_notification:
                        _send(_jsonrpc_error(req_id, -32002, "Server not initialized"))
                    return

                name = params.get("name")
                arguments = params.get("arguments") or {}
                if name not in ("act", "mirage.act"):
                    if not is_notification:
                        _send(_jsonrpc_result(req_id, _tool_result({"error": "unknown tool"}, is_error=True)))
                    return

                try:
                    act = ActArgs.model_validate(arguments)
                except ValidationError as e:
                    if not is_notification:
                        _send(_jsonrpc_result(req_id, _tool_result({"error": "bad arguments", "details": e.errors()}, is_error=True)))
                    return

                # In a real system, session would bind user identity/device attestation.
                session = os.getenv("MIRAGE_SESSION_ID", "demo-session")
                obs = self._router.act(act.intent_id, act.inputs, act.constraints, caller=act.caller, session=session)
                if not is_notification:
                    _send(_jsonrpc_result(req_id, _tool_result(obs, is_error=(obs.get("status") == "DENY"))))
                return

            if method == "ping":
                if not is_notification:
                    _send(_jsonrpc_result(req_id, {}))
                return

            # Unknown method
            if not is_notification:
                _send(_jsonrpc_error(req_id, -32601, f"Method not found: {method}"))
        except Exception as e:
            if not is_notification:
                # `str(e)` is often empty for some exception types; include repr() for debuggability.
                _send(_jsonrpc_error(req_id, -32603, "Internal error", data={"error": repr(e)}))


def main() -> None:
    MirageMcpServer().serve_forever()


if __name__ == "__main__":
    main()
