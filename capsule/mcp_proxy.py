from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

import requests
from pydantic import BaseModel, Field, ValidationError

from common.uds_http import uds_post_json


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
    return {
        "content": [{"type": "text", "text": json.dumps(structured, ensure_ascii=True)}],
        "structuredContent": structured,
        "isError": bool(is_error),
    }


def _tools_list() -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": "act",
                "description": "Proxy a high-level intent to the MIRAGE gateway (UDS netless transport preferred; legacy loopback HTTP supported).",
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
                "name": "mirage.act",
                "description": "Proxy a high-level intent to the MIRAGE gateway (UDS netless transport preferred; legacy loopback HTTP supported).",
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
        ]
    }


class MirageMcpProxy:
    def __init__(self) -> None:
        self._initialized = False
        self._uds_path = (os.getenv("MIRAGE_GATEWAY_UDS_PATH") or "").strip()
        base = (os.getenv("MIRAGE_GATEWAY_HTTP_URL") or "http://127.0.0.1:8765").rstrip("/")
        self._act_url = f"{base}/act"
        self._timeout_s = float(os.getenv("MIRAGE_PROXY_TIMEOUT_S") or "30")
        self._token = (os.getenv("MIRAGE_HTTP_TOKEN") or "").strip()
        self._session = (os.getenv("MIRAGE_SESSION_ID") or "capsule-session").strip() or "capsule-session"

    def serve_forever(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _send(_jsonrpc_error(None, -32700, "Parse error"))
                continue
            self._handle_message(msg)

    def _handle_message(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        req_id = msg.get("id", None)
        params = msg.get("params") or {}
        is_notification = "id" not in msg

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "mirage-ogpp-capsule-proxy", "version": "0.1"},
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
                        _send(
                            _jsonrpc_result(
                                req_id,
                                _tool_result({"error": "bad arguments", "details": e.errors()}, is_error=True),
                            )
                        )
                    return

                obs = self._call_gateway(act)
                if not is_notification:
                    _send(_jsonrpc_result(req_id, _tool_result(obs, is_error=(obs.get("status") == "DENY"))))
                return

            if method == "ping":
                if not is_notification:
                    _send(_jsonrpc_result(req_id, {}))
                return

            if not is_notification:
                _send(_jsonrpc_error(req_id, -32601, f"Method not found: {method}"))
        except Exception as e:
            if not is_notification:
                _send(_jsonrpc_error(req_id, -32603, "Internal error", data=str(e)))

    def _call_gateway(self, act: ActArgs) -> dict[str, Any]:
        headers: dict[str, str] = {"Content-Type": "application/json", "X-Mirage-Session": self._session}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        if self._uds_path:
            try:
                st, _hdrs, data = uds_post_json(
                    uds_path=self._uds_path,
                    path="/act",
                    obj={"intent_id": act.intent_id, "inputs": act.inputs, "constraints": act.constraints, "caller": act.caller},
                    headers=headers,
                    timeout_s=self._timeout_s,
                )
            except Exception as e:
                return {"status": "DENY", "reason_code": "GATEWAY_UNREACHABLE", "details": str(e)}
            if int(st) != 200:
                return {"status": "DENY", "reason_code": "GATEWAY_HTTP_ERROR", "http_status": int(st), "details": data}
            if not isinstance(data, dict):
                return {"status": "DENY", "reason_code": "GATEWAY_BAD_RESPONSE", "details": "non-object response"}
            return data

        try:
            r = requests.post(
                self._act_url,
                json={"intent_id": act.intent_id, "inputs": act.inputs, "constraints": act.constraints, "caller": act.caller},
                headers=headers,
                timeout=self._timeout_s,
            )
        except Exception as e:
            return {"status": "DENY", "reason_code": "GATEWAY_UNREACHABLE", "details": str(e)}

        if r.status_code != 200:
            # Fail closed: treat transport errors as DENY to keep the agent from
            # interpreting transient failures as authorization.
            try:
                detail = r.json()
            except Exception:
                detail = {"text": r.text[:200]}
            return {"status": "DENY", "reason_code": "GATEWAY_HTTP_ERROR", "http_status": r.status_code, "details": detail}

        try:
            data = r.json()
        except Exception as e:
            return {"status": "DENY", "reason_code": "GATEWAY_BAD_JSON", "details": str(e)}

        if not isinstance(data, dict):
            return {"status": "DENY", "reason_code": "GATEWAY_BAD_RESPONSE", "details": "non-object response"}
        return data


def main() -> None:
    MirageMcpProxy().serve_forever()


if __name__ == "__main__":
    main()
