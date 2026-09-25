from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Dict

import requests

from agent.mcp_client import McpStdioClient
from common.uds_http import uds_post_json


def _try_read(path: str) -> dict[str, Any]:
    try:
        with open(path, "rb") as f:
            _ = f.read(32)
        return {"ok": True, "note": "unexpected: read succeeded"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "details": str(e)[:200]}

def _try_exec(argv: list[str]) -> dict[str, Any]:
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2.0, check=False, text=True)
        return {
            "ok": p.returncode == 0,
            "spawned": True,
            "returncode": int(p.returncode),
            "stdout": (p.stdout or "")[:200],
            "stderr": (p.stderr or "")[:200],
            "note": "unexpected: exec succeeded" if p.returncode == 0 else "unexpected: exec was allowed but returned nonzero",
        }
    except Exception as e:
        return {"ok": False, "spawned": False, "error": type(e).__name__, "details": str(e)[:200]}


def _try_internet(url: str) -> dict[str, Any]:
    try:
        r = requests.get(url, timeout=2.0)
        return {"ok": True, "status": int(r.status_code), "note": "unexpected: internet request succeeded"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "details": str(e)[:200]}

def _try_post(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        r = requests.post(url, json=payload, timeout=2.0)
        return {"ok": True, "status": int(r.status_code), "note": "unexpected: http post succeeded"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "details": str(e)[:200]}


def _try_gateway_act() -> dict[str, Any]:
    uds = (os.getenv("MIRAGE_GATEWAY_UDS_PATH") or "").strip()
    base = (os.getenv("MIRAGE_GATEWAY_HTTP_URL") or "http://127.0.0.1:8765").rstrip("/")
    token = (os.getenv("MIRAGE_HTTP_TOKEN") or "").strip()
    session = (os.getenv("MIRAGE_SESSION_ID") or "capsule-session").strip() or "capsule-session"
    headers: dict[str, str] = {"Content-Type": "application/json", "X-Mirage-Session": session}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = {
        "intent_id": "FetchResource",
        "inputs": {"resource_id": "octocat", "domain": "api.github.com"},
        "constraints": {},
        "caller": "capsule-smoke",
    }
    if uds:
        try:
            st, _hdrs, data = uds_post_json(uds_path=uds, path="/act", obj=payload, headers=headers, timeout_s=5.0)
            return {"ok": int(st) == 200, "transport": "uds", "http_status": int(st), "body": data}
        except Exception as e:
            return {"ok": False, "transport": "uds", "error": type(e).__name__, "details": str(e)[:200]}
    try:
        r = requests.post(
            f"{base}/act",
            json=payload,
            headers=headers,
            timeout=5.0,
        )
        return {"ok": r.status_code == 200, "http_status": int(r.status_code), "body": (r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text[:200])}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "details": str(e)[:200]}


def _try_gateway_mcp() -> dict[str, Any]:
    env = {
        "MIRAGE_GATEWAY_HTTP_URL": os.getenv("MIRAGE_GATEWAY_HTTP_URL") or "http://127.0.0.1:8765",
        "MIRAGE_GATEWAY_UDS_PATH": os.getenv("MIRAGE_GATEWAY_UDS_PATH") or "",
        "MIRAGE_HTTP_TOKEN": os.getenv("MIRAGE_HTTP_TOKEN") or "",
        "MIRAGE_SESSION_ID": os.getenv("MIRAGE_SESSION_ID") or "capsule-session",
    }
    with McpStdioClient([sys.executable, "-m", "capsule.mcp_proxy"], env=env) as mcp:
        mcp.initialize()
        out = mcp.call_tool(
            "act",
            {
                "intent_id": "FetchResource",
                "inputs": {"resource_id": "octocat", "domain": "api.github.com"},
                "constraints": {},
                "caller": "capsule-smoke",
            },
        )
    return {"ok": isinstance(out, dict) and out.get("status") in ("OK", "DENY"), "response": out}


def main() -> None:
    host_secret = (os.getenv("MIRAGE_CAPSULE_SECRET_PATH") or "").strip()
    if not host_secret:
        host_secret = os.path.expanduser("~/.ssh/id_rsa")
    exfil_url = (os.getenv("MIRAGE_EXFIL_URL") or "").strip()
    expect_exec_block = bool(int(os.getenv("MIRAGE_EXPECT_EXEC_BLOCK", "1")))
    if not exfil_url or ":0/" in exfil_url or exfil_url.endswith(":0") or exfil_url.endswith(":0/exfil"):
        exfil_url = ""
    report: Dict[str, Any] = {
        "direct_fs_read": _try_read(host_secret),
        # Exec blocking is macOS sandbox-exec specific in this artifact; on Linux bwrap capsule we focus on netless transport.
        "direct_exec_true": (_try_exec(["/usr/bin/true"]) if expect_exec_block else {"skipped": True}),
        "direct_exec_sh": (_try_exec(["/bin/sh", "-c", "echo capsule_exec_ok"]) if expect_exec_block else {"skipped": True}),
        # Deterministic bypass attempt: direct HTTP POST to a local exfil server (should be blocked in netless/UDS capsule).
        "direct_exfil_post": (_try_post(exfil_url, {"k": "v", "note": "capsule_exfil_probe"}) if exfil_url else {"skipped": True}),
        # Best-effort public Internet probe (may fail even without capsule, depending on environment).
        "direct_internet": _try_internet("https://example.com/"),
        "gateway_act": _try_gateway_act(),
        "gateway_mcp_act": _try_gateway_mcp(),
    }
    sys.stdout.write(json.dumps(report, ensure_ascii=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
