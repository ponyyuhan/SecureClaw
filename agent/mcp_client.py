from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional


class McpError(Exception):
    pass


@dataclass
class McpStdioClient:
    cmd: list[str]
    env: Optional[dict[str, str]] = None

    def __post_init__(self) -> None:
        e = os.environ.copy()
        if self.env:
            e.update(self.env)
        self._proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            env=e,
        )
        assert self._proc.stdin is not None
        assert self._proc.stdout is not None
        self._next_id = 1
        self._initialized = False

    def close(self) -> None:
        if getattr(self, "_proc", None) is None:
            return
        proc = self._proc
        # Close stdin to signal EOF, then terminate.
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=1.0)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass
        try:
            if proc.stdout:
                proc.stdout.close()
        except Exception:
            pass

    def __enter__(self) -> "McpStdioClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()

    def initialize(self) -> None:
        _ = self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "nanoclaw", "version": "0.1"},
            },
        )
        self.notify("notifications/initialized", {})
        self._initialized = True

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        req_id = self._next_id
        self._next_id += 1
        self._write({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}})
        return self._read_result(req_id)

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not self._initialized:
            raise McpError("client not initialized")
        res = self.request("tools/call", {"name": name, "arguments": arguments})
        if not isinstance(res, dict):
            raise McpError("bad tools/call response")
        # Prefer structuredContent; fallback to parsing text content.
        if "structuredContent" in res and isinstance(res["structuredContent"], dict):
            return res["structuredContent"]
        content = res.get("content") or []
        for c in content:
            if isinstance(c, dict) and c.get("type") == "text":
                try:
                    return json.loads(c.get("text", "{}"))
                except Exception:
                    break
        raise McpError("missing structuredContent")

    def _write(self, obj: dict[str, Any]) -> None:
        if self._proc.stdin is None:
            raise McpError("stdin closed")
        self._proc.stdin.write(json.dumps(obj, ensure_ascii=True) + "\n")
        self._proc.stdin.flush()

    def _read_result(self, req_id: int) -> Any:
        if self._proc.stdout is None:
            raise McpError("stdout closed")
        while True:
            line = self._proc.stdout.readline()
            if not line:
                raise McpError("server closed stdout")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") != req_id:
                # Ignore unrelated notifications.
                continue
            if "error" in msg:
                raise McpError(str(msg["error"]))
            return msg.get("result")
