from __future__ import annotations

import base64
import hashlib
import hmac
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


def call_act(mcp: McpStdioClient, intent_id: str, inputs: Dict[str, Any], constraints: Dict[str, Any], caller: str) -> Dict[str, Any]:
    return mcp.call_tool(
        "act",
        {"intent_id": intent_id, "inputs": inputs, "constraints": constraints, "caller": caller},
    )


def _mutate_b64(s: str) -> str:
    if not s:
        return "AAAA"
    # Flip one byte and keep a valid base64 payload.
    raw = bytearray(base64.b64decode(s))
    if not raw:
        raw = bytearray(b"\x00")
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def _expect_status(name: str, obj: Dict[str, Any], want: str) -> tuple[bool, Dict[str, Any]]:
    got = str(obj.get("status") or "")
    ok = got.upper() == want.upper()
    return ok, {"name": name, "ok": ok, "want": want, "got": got, "reason_code": obj.get("reason_code"), "details": obj.get("details")}


def main() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    # Ensure repo imports work even when executed as a standalone script.
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from agent.mcp_client import McpStdioClient

    out_dir = Path(os.getenv("OUT_DIR", str(repo_root / "artifact_out")))
    out_dir.mkdir(parents=True, exist_ok=True)

    p0_port = int(os.getenv("P0_PORT", str(pick_port())))
    p1_port = int(os.getenv("P1_PORT", str(pick_port())))
    ex_port = int(os.getenv("EX_PORT", str(pick_port())))

    policy0_url = os.getenv("POLICY0_URL", f"http://127.0.0.1:{p0_port}")
    policy1_url = os.getenv("POLICY1_URL", f"http://127.0.0.1:{p1_port}")
    executor_url = os.getenv("EXECUTOR_URL", f"http://127.0.0.1:{ex_port}")
    session_id = os.getenv("MIRAGE_SESSION_ID", "proof-check-session")
    caller = "proof-checker"
    dummy_domain = os.getenv("DUMMY_DOMAIN", "example.com")

    policy0_mac_key = os.getenv("POLICY0_MAC_KEY", secrets.token_hex(32))
    policy1_mac_key = os.getenv("POLICY1_MAC_KEY", secrets.token_hex(32))

    env_common = os.environ.copy()
    env_common["PYTHONPATH"] = str(repo_root)
    env_common["POLICY0_URL"] = policy0_url
    env_common["POLICY1_URL"] = policy1_url
    env_common["EXECUTOR_URL"] = executor_url
    env_common["POLICY0_MAC_KEY"] = policy0_mac_key
    env_common["POLICY1_MAC_KEY"] = policy1_mac_key
    env_common["SIGNED_PIR"] = "1"
    env_common["MIRAGE_SESSION_ID"] = session_id
    env_common["DLP_MODE"] = "fourgram"
    # The synthetic test driver acts as the trusted confirmation service.
    confirm_key = secrets.token_bytes(32)
    env_common["SECURECLAW_CONFIRM_TOKEN_KEY_HEX"] = confirm_key.hex()

    subprocess.run([sys.executable, "-m", "policy_server.build_dbs"], check=True, env=env_common)

    procs: list[subprocess.Popen[str]] = []
    report: dict[str, Any] = {"status": "ERROR", "checks": []}
    try:
        env0 = env_common.copy()
        env0["SERVER_ID"] = "0"
        env0["PORT"] = str(p0_port)
        env0["POLICY_MAC_KEY"] = policy0_mac_key
        p0 = subprocess.Popen([sys.executable, "-m", "policy_server.server"], env=env0, text=True)
        procs.append(p0)

        env1 = env_common.copy()
        env1["SERVER_ID"] = "1"
        env1["PORT"] = str(p1_port)
        env1["POLICY_MAC_KEY"] = policy1_mac_key
        p1 = subprocess.Popen([sys.executable, "-m", "policy_server.server"], env=env1, text=True)
        procs.append(p1)

        envx = env_common.copy()
        envx["EXECUTOR_PORT"] = str(ex_port)
        ex = subprocess.Popen([sys.executable, "-m", "executor_server.server"], env=envx, text=True)
        procs.append(ex)

        wait_http_ok(f"{policy0_url}/health")
        wait_http_ok(f"{policy1_url}/health")
        wait_http_ok(f"{executor_url}/health")

        with McpStdioClient([sys.executable, "-m", "gateway.mcp_server"], env=env_common) as mcp:
            mcp.initialize()
            chk = call_act(
                mcp,
                "CheckMessagePolicy",
                inputs={
                    "channel": "email",
                    "recipient": "alice@example.com",
                    # Keep domain aligned with the gateway's request-hash binding for send intents.
                    "domain": dummy_domain,
                    "text": "Hello Alice from formal check.",
                    "artifacts": [],
                },
                constraints={},
                caller=caller,
            )
            chk_confirm = call_act(
                mcp,
                "CheckMessagePolicy",
                inputs={
                    "channel": "email",
                    "recipient": "alice@example.com",
                    "domain": dummy_domain,
                    "text": "Synthetic AKIA fixture for confirmation path.",
                    "artifacts": [],
                },
                constraints={},
                caller=caller,
            )
            chk_confirm2 = call_act(
                mcp,
                "CheckMessagePolicy",
                inputs={
                    "channel": "email",
                    "recipient": "alice@example.com",
                    "domain": dummy_domain,
                    "text": "Synthetic AKIA fixture for confirmation path.",
                    "artifacts": [],
                },
                constraints={},
                caller=caller,
            )
            # Extended bypass suite: additional gateway calls for positive controls.
            chk_extra1 = call_act(
                mcp,
                "CheckMessagePolicy",
                inputs={
                    "channel": "email",
                    "recipient": "bob@example.com",
                    "domain": dummy_domain,
                    "text": "Hello Bob, second valid request.",
                    "artifacts": [],
                },
                constraints={},
                caller=caller,
            )
            chk_extra2 = call_act(
                mcp,
                "CheckMessagePolicy",
                inputs={
                    "channel": "email",
                    "recipient": "alice@example.com",
                    "domain": dummy_domain,
                    "text": "Third valid request with different text.",
                    "artifacts": [],
                },
                constraints={},
                caller=caller,
            )

        evidence = ((chk.get("data") or {}).get("evidence") or {})
        commit = (evidence.get("commit") or {})
        action_id = str(((commit.get("policy0") or {}).get("action_id") or ""))
        evidence_confirm = ((chk_confirm.get("data") or {}).get("evidence") or {})
        commit_confirm = (evidence_confirm.get("commit") or {})
        action_id_confirm = str(((commit_confirm.get("policy0") or {}).get("action_id") or ""))
        evidence_confirm2 = ((chk_confirm2.get("data") or {}).get("evidence") or {})
        commit_confirm2 = (evidence_confirm2.get("commit") or {})
        action_id_confirm2 = str(((commit_confirm2.get("policy0") or {}).get("action_id") or ""))

        evidence_extra1 = ((chk_extra1.get("data") or {}).get("evidence") or {})
        commit_extra1 = (evidence_extra1.get("commit") or {})
        action_id_extra1 = str(((commit_extra1.get("policy0") or {}).get("action_id") or ""))
        evidence_extra2 = ((chk_extra2.get("data") or {}).get("evidence") or {})
        commit_extra2 = (evidence_extra2.get("commit") or {})
        action_id_extra2 = str(((commit_extra2.get("policy0") or {}).get("action_id") or ""))

        base_req = {
            "action_id": action_id,
            "channel": "email",
            "recipient": "alice@example.com",
            "domain": dummy_domain,
            "text": "Hello Alice from formal check.",
            "artifacts": [],
            "dlp_mode": "fourgram",
            "evidence": {},
            "commit": commit,
            "caller": caller,
            "session": session_id,
            "user_confirm": False,
        }

        valid = requests.post(f"{executor_url}/exec/send_message", json=base_req, timeout=5).json()
        c_ok, c_item = _expect_status("valid_dual_proof_accepts", valid, "OK")
        report["checks"].append(c_item)

        # Replay should be rejected (best-effort anti-replay guard keyed by action_id).
        replay = requests.post(f"{executor_url}/exec/send_message", json=base_req, timeout=5).json()
        c_ok_r, c_item_r = _expect_status("replay_denied", replay, "DENY")
        c_item_r["reason_code"] = replay.get("reason_code")
        report["checks"].append(c_item_r)

        # Session binding: changing session should invalidate request_sha256 binding.
        req_sess = dict(base_req)
        req_sess["session"] = "other-session"
        r_sess = requests.post(f"{executor_url}/exec/send_message", json=req_sess, timeout=5).json()
        c_ok_s, c_item_s = _expect_status("session_binding_denied", r_sess, "DENY")
        c_item_s["reason_code"] = r_sess.get("reason_code")
        c_item_s["details"] = r_sess.get("details")
        report["checks"].append(c_item_s)

        # Caller binding: changing caller should invalidate request_sha256 binding.
        req_caller = dict(base_req)
        req_caller["caller"] = "other-caller"
        r_caller = requests.post(f"{executor_url}/exec/send_message", json=req_caller, timeout=5).json()
        c_ok_c, c_item_c = _expect_status("caller_binding_denied", r_caller, "DENY")
        c_item_c["reason_code"] = r_caller.get("reason_code")
        c_item_c["details"] = r_caller.get("details")
        report["checks"].append(c_item_c)

        # Hash-context binding (DAS): external principal / delegation jti are part of request hash context.
        req_ctx_principal = dict(base_req)
        req_ctx_principal["external_principal"] = "principal-A"
        r_ctx_principal = requests.post(f"{executor_url}/exec/send_message", json=req_ctx_principal, timeout=5).json()
        c_ok_ctx_p, c_item_ctx_p = _expect_status("hctx_external_principal_binding_denied", r_ctx_principal, "DENY")
        c_item_ctx_p["reason_code"] = r_ctx_principal.get("reason_code")
        c_item_ctx_p["details"] = r_ctx_principal.get("details")
        report["checks"].append(c_item_ctx_p)

        req_ctx_jti = dict(base_req)
        req_ctx_jti["delegation_jti"] = "dlg-jti-1"
        r_ctx_jti = requests.post(f"{executor_url}/exec/send_message", json=req_ctx_jti, timeout=5).json()
        c_ok_ctx_j, c_item_ctx_j = _expect_status("hctx_delegation_jti_binding_denied", r_ctx_jti, "DENY")
        c_item_ctx_j["reason_code"] = r_ctx_jti.get("reason_code")
        c_item_ctx_j["details"] = r_ctx_jti.get("details")
        report["checks"].append(c_item_ctx_j)

        req_missing = dict(base_req)
        req_missing["commit"] = {"policy0": (commit or {}).get("policy0")}
        r_missing = requests.post(f"{executor_url}/exec/send_message", json=req_missing, timeout=5).json()
        c_ok2, c_item2 = _expect_status("missing_policy1_denied", r_missing, "DENY")
        report["checks"].append(c_item2)

        req_bad_mac = json.loads(json.dumps(base_req))
        p0p = ((req_bad_mac.get("commit") or {}).get("policy0") or {})
        p0p["mac_b64"] = _mutate_b64(str(p0p.get("mac_b64") or ""))
        req_bad_mac["commit"]["policy0"] = p0p
        r_bad_mac = requests.post(f"{executor_url}/exec/send_message", json=req_bad_mac, timeout=5).json()
        c_ok3, c_item3 = _expect_status("tampered_mac_denied", r_bad_mac, "DENY")
        report["checks"].append(c_item3)

        req_bad_hash = dict(base_req)
        req_bad_hash["text"] = base_req["text"] + " tamper"
        r_bad_hash = requests.post(f"{executor_url}/exec/send_message", json=req_bad_hash, timeout=5).json()
        c_ok4, c_item4 = _expect_status("request_hash_binding_denied", r_bad_hash, "DENY")
        report["checks"].append(c_item4)

        req_bad_action = dict(base_req)
        req_bad_action["action_id"] = f"wrong-{action_id}"
        r_bad_action = requests.post(f"{executor_url}/exec/send_message", json=req_bad_action, timeout=5).json()
        c_ok5, c_item5 = _expect_status("action_id_binding_denied", r_bad_action, "DENY")
        report["checks"].append(c_item5)

        req_expired = json.loads(json.dumps(base_req))
        p0e = ((req_expired.get("commit") or {}).get("policy0") or {})
        p1e = ((req_expired.get("commit") or {}).get("policy1") or {})
        p0e["ts"] = int(time.time()) - 10_000
        p1e["ts"] = int(time.time()) - 10_000
        req_expired["commit"]["policy0"] = p0e
        req_expired["commit"]["policy1"] = p1e
        r_expired = requests.post(f"{executor_url}/exec/send_message", json=req_expired, timeout=5).json()
        c_ok6, c_item6 = _expect_status("expired_proof_denied", r_expired, "DENY")
        report["checks"].append(c_item6)

        # --- Extended bypass suite (Phase 2) ---

        # Future-timestamped proof: ts far in the future exceeds MAC_TTL_S.
        req_future = json.loads(json.dumps(base_req))
        p0f = ((req_future.get("commit") or {}).get("policy0") or {})
        p1f = ((req_future.get("commit") or {}).get("policy1") or {})
        p0f["ts"] = int(time.time()) + 10_000
        p1f["ts"] = int(time.time()) + 10_000
        req_future["commit"]["policy0"] = p0f
        req_future["commit"]["policy1"] = p1f
        r_future = requests.post(f"{executor_url}/exec/send_message", json=req_future, timeout=5).json()
        _, c_future = _expect_status("future_timestamp_denied", r_future, "DENY")
        report["checks"].append(c_future)

        # Server-ID swap: set policy0.server_id = 1 (violates sid0==0 constraint).
        req_sid_swap = json.loads(json.dumps(base_req))
        p0s = ((req_sid_swap.get("commit") or {}).get("policy0") or {})
        p0s["server_id"] = 1
        req_sid_swap["commit"]["policy0"] = p0s
        r_sid_swap = requests.post(f"{executor_url}/exec/send_message", json=req_sid_swap, timeout=5).json()
        _, c_sid = _expect_status("server_id_swap_denied", r_sid_swap, "DENY")
        report["checks"].append(c_sid)

        # Cross-commit mixup: policy0 from one request, policy1 from another (mismatched action_ids).
        req_cross = json.loads(json.dumps(base_req))
        req_cross["commit"] = {
            "policy0": (commit or {}).get("policy0"),
            "policy1": (commit_confirm or {}).get("policy1"),
        }
        r_cross = requests.post(f"{executor_url}/exec/send_message", json=req_cross, timeout=5).json()
        _, c_cross = _expect_status("cross_commit_mixup_denied", r_cross, "DENY")
        report["checks"].append(c_cross)

        # Wrong proof version: policy0.v = 2 instead of 1.
        req_badver = json.loads(json.dumps(base_req))
        p0v = ((req_badver.get("commit") or {}).get("policy0") or {})
        p0v["v"] = 2
        req_badver["commit"]["policy0"] = p0v
        r_badver = requests.post(f"{executor_url}/exec/send_message", json=req_badver, timeout=5).json()
        _, c_badver = _expect_status("wrong_proof_version_denied", r_badver, "DENY")
        report["checks"].append(c_badver)

        # Empty commit: no policy proofs at all.
        req_empty = dict(base_req)
        req_empty["commit"] = {}
        r_empty = requests.post(f"{executor_url}/exec/send_message", json=req_empty, timeout=5).json()
        _, c_empty = _expect_status("empty_commit_denied", r_empty, "DENY")
        report["checks"].append(c_empty)

        # Missing both policies: commit with null policy entries.
        req_null_pol = dict(base_req)
        req_null_pol["commit"] = {"policy0": None, "policy1": None}
        r_null_pol = requests.post(f"{executor_url}/exec/send_message", json=req_null_pol, timeout=5).json()
        _, c_null_pol = _expect_status("null_policies_denied", r_null_pol, "DENY")
        report["checks"].append(c_null_pol)

        # Recipient tampered: change recipient after commit (hash mismatch).
        req_recip = json.loads(json.dumps(base_req))
        req_recip["recipient"] = "attacker@evil.com"
        r_recip = requests.post(f"{executor_url}/exec/send_message", json=req_recip, timeout=5).json()
        _, c_recip = _expect_status("recipient_tampered_denied", r_recip, "DENY")
        report["checks"].append(c_recip)

        # Channel tampered: change channel after commit (hash mismatch).
        req_chan = json.loads(json.dumps(base_req))
        req_chan["channel"] = "sms"
        r_chan = requests.post(f"{executor_url}/exec/send_message", json=req_chan, timeout=5).json()
        _, c_chan = _expect_status("channel_tampered_denied", r_chan, "DENY")
        report["checks"].append(c_chan)

        # Domain tampered: change domain after commit (hash mismatch).
        req_dom = json.loads(json.dumps(base_req))
        req_dom["domain"] = "evil.org"
        r_dom = requests.post(f"{executor_url}/exec/send_message", json=req_dom, timeout=5).json()
        _, c_dom = _expect_status("domain_tampered_denied", r_dom, "DENY")
        report["checks"].append(c_dom)

        # Capsule hash injection: add capsule_hash to a request that was committed without one.
        req_capsule = json.loads(json.dumps(base_req))
        req_capsule["capsule_hash"] = "injected-capsule-hash-abc123"
        r_capsule = requests.post(f"{executor_url}/exec/send_message", json=req_capsule, timeout=5).json()
        _, c_capsule = _expect_status("capsule_hash_injection_denied", r_capsule, "DENY")
        report["checks"].append(c_capsule)

        # Missing action_id: empty string action_id.
        req_no_aid = dict(base_req)
        req_no_aid["action_id"] = ""
        r_no_aid = requests.post(f"{executor_url}/exec/send_message", json=req_no_aid, timeout=5).json()
        _, c_no_aid = _expect_status("missing_action_id_denied", r_no_aid, "DENY")
        report["checks"].append(c_no_aid)

        # Chained: expired proof + text tamper (multiple mutations).
        req_chained = json.loads(json.dumps(base_req))
        req_chained["text"] = base_req["text"] + " chained tamper"
        p0ch = ((req_chained.get("commit") or {}).get("policy0") or {})
        p1ch = ((req_chained.get("commit") or {}).get("policy1") or {})
        p0ch["ts"] = int(time.time()) - 10_000
        p1ch["ts"] = int(time.time()) - 10_000
        req_chained["commit"]["policy0"] = p0ch
        req_chained["commit"]["policy1"] = p1ch
        r_chained = requests.post(f"{executor_url}/exec/send_message", json=req_chained, timeout=5).json()
        _, c_chained = _expect_status("chained_expired_plus_tamper_denied", r_chained, "DENY")
        report["checks"].append(c_chained)

        # Chained: MAC flip + recipient change.
        req_chain2 = json.loads(json.dumps(base_req))
        req_chain2["recipient"] = "attacker2@evil.com"
        p0c2 = ((req_chain2.get("commit") or {}).get("policy0") or {})
        p0c2["mac_b64"] = _mutate_b64(str(p0c2.get("mac_b64") or ""))
        req_chain2["commit"]["policy0"] = p0c2
        r_chain2 = requests.post(f"{executor_url}/exec/send_message", json=req_chain2, timeout=5).json()
        _, c_chain2 = _expect_status("chained_mac_plus_recipient_denied", r_chain2, "DENY")
        report["checks"].append(c_chain2)

        # Positive control: second valid request to a different recipient.
        req_extra1 = {
            "action_id": action_id_extra1,
            "channel": "email",
            "recipient": "bob@example.com",
            "domain": dummy_domain,
            "text": "Hello Bob, second valid request.",
            "artifacts": [],
            "dlp_mode": "fourgram",
            "evidence": {},
            "commit": commit_extra1,
            "caller": caller,
            "session": session_id,
            "user_confirm": False,
        }
        r_extra1 = requests.post(f"{executor_url}/exec/send_message", json=req_extra1, timeout=5).json()
        _, c_extra1 = _expect_status("valid_second_recipient_accepts", r_extra1, "OK")
        report["checks"].append(c_extra1)

        # Positive control: third valid request with different text (same allowed recipient).
        req_extra2 = {
            "action_id": action_id_extra2,
            "channel": "email",
            "recipient": "alice@example.com",
            "domain": dummy_domain,
            "text": "Third valid request with different text.",
            "artifacts": [],
            "dlp_mode": "fourgram",
            "evidence": {},
            "commit": commit_extra2,
            "caller": caller,
            "session": session_id,
            "user_confirm": False,
        }
        r_extra2 = requests.post(f"{executor_url}/exec/send_message", json=req_extra2, timeout=5).json()
        _, c_extra2 = _expect_status("valid_third_request_accepts", r_extra2, "OK")
        report["checks"].append(c_extra2)

        # Cross-session replay of valid second request (action_id_extra1 was consumed above).
        req_cross_sess = dict(req_extra1)
        req_cross_sess["session"] = "hijacked-session"
        r_cross_sess = requests.post(f"{executor_url}/exec/send_message", json=req_cross_sess, timeout=5).json()
        _, c_cross_sess = _expect_status("cross_session_replay_denied", r_cross_sess, "DENY")
        report["checks"].append(c_cross_sess)

        # Confirmation-gated path (PEI/confirm semantics):
        # same message/proof with need_confirm=1 must deny without explicit confirmation.
        req_need_confirm = {
            "action_id": action_id_confirm,
            "channel": "email",
            "recipient": "alice@example.com",
            "domain": dummy_domain,
            "text": "Synthetic AKIA fixture for confirmation path.",
            "artifacts": [],
            "dlp_mode": "fourgram",
            "evidence": {},
            "commit": commit_confirm,
            "caller": caller,
            "session": session_id,
            "user_confirm": False,
        }
        r_need_confirm = requests.post(f"{executor_url}/exec/send_message", json=req_need_confirm, timeout=5).json()
        c_ok7, c_item7 = _expect_status("need_confirm_denied_without_user_confirm", r_need_confirm, "DENY")
        c_item7["reason_code"] = r_need_confirm.get("reason_code")
        report["checks"].append(c_item7)

        req_confirm_ok = dict(req_need_confirm)
        req_confirm_ok["action_id"] = action_id_confirm2
        req_confirm_ok["commit"] = commit_confirm2
        req_confirm_ok["user_confirm"] = True
        # A Boolean supplied by the runtime is insufficient in the bound-token mode.
        no_token = requests.post(f"{executor_url}/exec/send_message", json=req_confirm_ok, timeout=5).json()
        _, no_token_check = _expect_status("confirmation_boolean_without_token_denied", no_token, "DENY")
        no_token_check["ok"] = bool(no_token_check["ok"] and no_token.get("reason_code") == "BAD_CONFIRM_TOKEN")
        req_confirm_ok["confirm_token"] = hmac.new(
            confirm_key,
            f"{action_id_confirm}|{(commit_confirm.get('policy0') or {}).get('request_sha256', '')}".encode(),
            hashlib.sha256,
        ).hexdigest()
        wrong_token = requests.post(f"{executor_url}/exec/send_message", json=req_confirm_ok, timeout=5).json()
        _, wrong_token_check = _expect_status("confirmation_token_for_other_action_denied", wrong_token, "DENY")
        wrong_token_check["ok"] = bool(wrong_token_check["ok"] and wrong_token.get("reason_code") == "BAD_CONFIRM_TOKEN")
        report["confirmation_binding_checks"] = [no_token_check, wrong_token_check]
        req_confirm_ok["confirm_token"] = hmac.new(
            confirm_key,
            f"{action_id_confirm2}|{(commit_confirm2.get('policy0') or {}).get('request_sha256', '')}".encode(),
            hashlib.sha256,
        ).hexdigest()
        r_confirm_ok = requests.post(f"{executor_url}/exec/send_message", json=req_confirm_ok, timeout=5).json()
        c_ok8, c_item8 = _expect_status("need_confirm_accepts_with_user_confirm", r_confirm_ok, "OK")
        c_item8["reason_code"] = r_confirm_ok.get("reason_code")

        # This fixture contains a configured DLP marker, so confirmation must be required.
        c_item7["expect_gate"] = True
        c_item7["ok"] = bool(c_ok7 and r_need_confirm.get("reason_code") == "REQUIRE_CONFIRM")
        c_item8["ok"] = bool(c_ok8)
        report["checks"].append(c_item8)

        all_ok = all(bool(x.get("ok")) for x in report["checks"] + report["confirmation_binding_checks"])
        n_attacks = sum(1 for x in report["checks"] if x.get("want", "").upper() == "DENY" and x.get("got", "").upper() == "DENY" and x.get("ok"))
        n_controls = sum(1 for x in report["checks"] if x.get("want", "").upper() == "OK" and x.get("got", "").upper() == "OK" and x.get("ok"))
        report["status"] = "OK" if all_ok else "FAIL"
        report["n_checks"] = len(report["checks"])
        report["n_attacks_denied"] = n_attacks
        report["n_controls_passed"] = n_controls
        report["theorem"] = "T1_dual_proof_binding_and_confirm_safety"
        report["notes"] = (
            "Extended bypass suite: acceptance requires dual valid commit proofs bound to request "
            "context (including hctx, capsule hash, timestamps), with explicit confirmation gating, "
            "anti-replay, session/caller binding, and cross-commit integrity."
        )

    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    out_path = out_dir / "security_game_nbe.json"
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(str(out_path))
    if report.get("status") != "OK":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
