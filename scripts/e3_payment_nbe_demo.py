"""E3 Payment Case Study: NBE necessity for financial effect integrity.

Demonstrates that without NBE (non-bypassable execution boundary), a compromised
runtime can redirect payments, inflate amounts, and replay transactions. With NBE
enabled, all unauthorized commits are denied at the executor boundary.

Scenarios tested:
  1. Legitimate payment (authorized, valid proof) → OK in both modes
  2. Amount manipulation (compromised runtime inflates amount) → DENY vs ALLOW_INSECURE
  3. Recipient redirect (compromised runtime changes payee) → DENY vs ALLOW_INSECURE
  4. Forged proof (compromised runtime fabricates commit tokens) → DENY vs ALLOW_INSECURE
  5. Replay attack (compromised runtime replays legitimate commit) → DENY vs ALLOW_INSECURE
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict

import requests

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def pick_port() -> int:
    s = socket.socket()
    s.bind(("", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def wait_http_ok(url: str, tries: int = 80) -> None:
    for _ in range(tries):
        try:
            r = requests.get(url, timeout=0.5)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"health check failed: {url}")


def main() -> None:
    out_dir = Path(os.getenv("OUT_DIR", str(_REPO_ROOT / "artifact_out" / "e3_payment")))
    out_dir.mkdir(parents=True, exist_ok=True)

    p0_port = pick_port()
    p1_port = pick_port()
    ex_port_secure = pick_port()
    ex_port_insecure = pick_port()

    policy0_url = f"http://127.0.0.1:{p0_port}"
    policy1_url = f"http://127.0.0.1:{p1_port}"
    executor_secure_url = f"http://127.0.0.1:{ex_port_secure}"
    executor_insecure_url = f"http://127.0.0.1:{ex_port_insecure}"

    session_id = "e3-payment-demo"
    caller = "finance-agent"
    mac_key0 = secrets.token_hex(32)
    mac_key1 = secrets.token_hex(32)

    env_common = os.environ.copy()
    env_common["PYTHONPATH"] = str(_REPO_ROOT)
    env_common["POLICY0_URL"] = policy0_url
    env_common["POLICY1_URL"] = policy1_url
    env_common["POLICY0_MAC_KEY"] = mac_key0
    env_common["POLICY1_MAC_KEY"] = mac_key1
    env_common["SIGNED_PIR"] = "1"
    env_common["MIRAGE_SESSION_ID"] = session_id
    env_common["DLP_MODE"] = "fourgram"

    subprocess.run([sys.executable, "-m", "policy_server.build_dbs"], check=True, env=env_common)

    procs: list[subprocess.Popen[str]] = []
    report: dict[str, Any] = {"status": "ERROR", "scenarios": [], "summary": {}}

    try:
        # Start 2 policy servers
        for sid, port, mac in [("0", p0_port, mac_key0), ("1", p1_port, mac_key1)]:
            env = env_common.copy()
            env["SERVER_ID"] = sid
            env["PORT"] = str(port)
            env["POLICY_MAC_KEY"] = mac
            procs.append(subprocess.Popen([sys.executable, "-m", "policy_server.server"], env=env, text=True))

        # Start secure executor (NBE on)
        env_sec = env_common.copy()
        env_sec["EXECUTOR_PORT"] = str(ex_port_secure)
        env_sec["EXECUTOR_INSECURE_ALLOW"] = "0"
        env_sec["EXECUTOR_URL"] = executor_secure_url
        procs.append(subprocess.Popen([sys.executable, "-m", "executor_server.server"], env=env_sec, text=True))

        # Start insecure executor (NBE off)
        env_insec = env_common.copy()
        env_insec["EXECUTOR_PORT"] = str(ex_port_insecure)
        env_insec["EXECUTOR_INSECURE_ALLOW"] = "1"
        env_insec["EXECUTOR_URL"] = executor_insecure_url
        procs.append(subprocess.Popen([sys.executable, "-m", "executor_server.server"], env=env_insec, text=True))

        wait_http_ok(f"{policy0_url}/health")
        wait_http_ok(f"{policy1_url}/health")
        wait_http_ok(f"{executor_secure_url}/health")
        wait_http_ok(f"{executor_insecure_url}/health")

        # ── Get legitimate payment proof via gateway (MCP) ──
        from agent.mcp_client import McpStdioClient

        env_gw = env_common.copy()
        env_gw["EXECUTOR_URL"] = executor_secure_url

        with McpStdioClient([sys.executable, "-m", "gateway.mcp_server"], env=env_gw) as mcp:
            mcp.initialize()
            # Legitimate payment: $100 to vendor
            legit = mcp.call_tool("act", {
                "intent_id": "CheckMessagePolicy",
                "inputs": {
                    "channel": "payment",
                    "recipient": "alice@example.com",
                    "domain": "example.com",
                    "text": "Payment of $100.00 for Invoice #2847",
                    "artifacts": [],
                },
                "constraints": {},
                "caller": caller,
            })
            # Second legitimate payment (for replay test)
            legit2 = mcp.call_tool("act", {
                "intent_id": "CheckMessagePolicy",
                "inputs": {
                    "channel": "payment",
                    "recipient": "alice@example.com",
                    "domain": "example.com",
                    "text": "Payment of $200.00 for Invoice #2848",
                    "artifacts": [],
                },
                "constraints": {},
                "caller": caller,
            })

        evidence = (legit.get("data") or {}).get("evidence") or {}
        commit = evidence.get("commit") or {}
        action_id = str((commit.get("policy0") or {}).get("action_id") or "")

        evidence2 = (legit2.get("data") or {}).get("evidence") or {}
        commit2 = evidence2.get("commit") or {}
        action_id2 = str((commit2.get("policy0") or {}).get("action_id") or "")

        base_req = {
            "action_id": action_id,
            "channel": "payment",
            "recipient": "alice@example.com",
            "domain": "example.com",
            "text": "Payment of $100.00 for Invoice #2847",
            "artifacts": [],
            "dlp_mode": "fourgram",
            "evidence": {},
            "commit": commit,
            "caller": caller,
            "session": session_id,
            "user_confirm": False,
        }

        def test_scenario(name: str, req: dict, description: str) -> dict:
            """Test a scenario against both executors and record results."""
            r_sec = requests.post(f"{executor_secure_url}/exec/send_message", json=req, timeout=5).json()
            r_insec = requests.post(f"{executor_insecure_url}/exec/send_message", json=req, timeout=5).json()
            scenario = {
                "name": name,
                "description": description,
                "nbe_on": {"status": r_sec.get("status"), "reason_code": r_sec.get("reason_code")},
                "nbe_off": {"status": r_insec.get("status"), "reason_code": r_insec.get("reason_code")},
            }
            report["scenarios"].append(scenario)
            return scenario

        # ── Scenario 1: Legitimate payment (valid proof) ──
        test_scenario(
            "legitimate_payment",
            base_req,
            "Authorized $100 payment to alice@example.com with valid dual-proof",
        )

        # ── Scenario 2: Amount manipulation ──
        # Compromised runtime inflates amount from $100 to $10,000
        req_amount = dict(base_req)
        req_amount["text"] = "Payment of $10,000.00 for Invoice #2847"
        req_amount["action_id"] = action_id + "-amount"  # Fresh action_id to avoid replay
        test_scenario(
            "amount_manipulation",
            req_amount,
            "Compromised runtime changes $100 to $10,000 — request hash mismatch",
        )

        # ── Scenario 3: Recipient redirect ──
        # Compromised runtime redirects payment to attacker
        req_redirect = dict(base_req)
        req_redirect["recipient"] = "attacker@evil.com"
        req_redirect["domain"] = "evil.com"
        req_redirect["action_id"] = action_id + "-redir"
        test_scenario(
            "recipient_redirect",
            req_redirect,
            "Compromised runtime redirects payment to attacker@evil.com",
        )

        # ── Scenario 4: Forged proof ──
        # Compromised runtime fabricates commit proof shares
        req_forged = dict(base_req)
        req_forged["action_id"] = action_id + "-forged"
        forged_commit = {}
        for k in ("policy0", "policy1"):
            if commit.get(k):
                fc = dict(commit[k])
                if fc.get("tag_b64"):
                    raw = bytearray(base64.b64decode(fc["tag_b64"]))
                    if raw:
                        raw[0] ^= 0xFF
                    fc["tag_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
                forged_commit[k] = fc
        req_forged["commit"] = forged_commit
        test_scenario(
            "forged_proof",
            req_forged,
            "Compromised runtime fabricates commit proof shares (bit-flip MAC)",
        )

        # ── Scenario 5: Replay attack ──
        # First use the second legitimate payment normally
        req2 = dict(base_req)
        req2["action_id"] = action_id2
        req2["text"] = "Payment of $200.00 for Invoice #2848"
        req2["commit"] = commit2
        # Consume the legitimate commit first
        requests.post(f"{executor_secure_url}/exec/send_message", json=req2, timeout=5)
        # Now replay the same commit
        test_scenario(
            "replay_attack",
            req2,
            "Compromised runtime replays a legitimate payment commit",
        )

        # ── Build summary ──
        nbe_on_denials = sum(1 for s in report["scenarios"] if s["nbe_on"]["status"] == "DENY")
        nbe_off_denials = sum(1 for s in report["scenarios"] if s["nbe_off"]["status"] == "DENY")
        nbe_on_allows = sum(1 for s in report["scenarios"] if s["nbe_on"]["status"] == "OK")
        nbe_off_allows = sum(1 for s in report["scenarios"] if s["nbe_off"]["status"] == "OK")

        report["summary"] = {
            "total_scenarios": len(report["scenarios"]),
            "nbe_on": {"allowed": nbe_on_allows, "denied": nbe_on_denials},
            "nbe_off": {"allowed": nbe_off_allows, "denied": nbe_off_denials},
            "unauthorized_commits_prevented_by_nbe": nbe_off_allows - nbe_on_allows,
            "verdict": "NBE_NECESSARY" if nbe_off_allows > nbe_on_allows else "NO_DIFFERENCE",
        }
        report["status"] = "OK"

    finally:
        for p in procs:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    # Write report
    report_path = out_dir / "e3_payment_report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # Write markdown summary
    md_lines = [
        "# E3 Payment Case Study: NBE Necessity for Financial Effects\n",
        f"**Status**: {report['status']}\n",
        "## Scenarios\n",
        "| # | Scenario | Description | NBE On | NBE Off |",
        "|---|----------|-------------|--------|---------|",
    ]
    for i, s in enumerate(report["scenarios"], 1):
        nbe_on = f"{s['nbe_on']['status']} ({s['nbe_on']['reason_code']})"
        nbe_off = f"{s['nbe_off']['status']} ({s['nbe_off']['reason_code']})"
        md_lines.append(f"| {i} | {s['name']} | {s['description']} | {nbe_on} | {nbe_off} |")

    sm = report.get("summary", {})
    md_lines.extend([
        "",
        "## Summary\n",
        f"- NBE On: {sm.get('nbe_on', {}).get('allowed', 0)} allowed, {sm.get('nbe_on', {}).get('denied', 0)} denied",
        f"- NBE Off: {sm.get('nbe_off', {}).get('allowed', 0)} allowed, {sm.get('nbe_off', {}).get('denied', 0)} denied",
        f"- **Unauthorized commits prevented by NBE: {sm.get('unauthorized_commits_prevented_by_nbe', 0)}**",
        f"- Verdict: **{sm.get('verdict', 'UNKNOWN')}**",
        "",
        "## Interpretation\n",
        "With NBE enabled, the executor verifies dual commit-proof shares (MAC-bound to request hash,",
        "session, caller, and delegation context). Any modification to the payment amount, recipient, or",
        "proof tokens causes the request hash to mismatch, and the commit is denied.",
        "",
        "Without NBE (`EXECUTOR_INSECURE_ALLOW=1`), the executor accepts ALL commits without proof",
        "verification. A compromised runtime can redirect payments, inflate amounts, replay transactions,",
        "and forge proofs — all without detection at the effect boundary.",
    ])

    md_path = out_dir / "e3_payment_report.md"
    md_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    print(f"E3 payment report: {report_path}")
    print(f"E3 payment markdown: {md_path}")
    print(f"Summary: {json.dumps(sm, indent=2)}")
    return


if __name__ == "__main__":
    main()
