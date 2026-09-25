import os
from typing import Dict, Any
from ..handles import HandleStore
from ..egress_policy import EgressPolicyEngine
from ..executor_client import get_executor_client
from .constraint_utils import policy_constraints

class NetExec:
    def __init__(self, handles: HandleStore, policy: EgressPolicyEngine):
        self.handles = handles
        self.policy = policy

    def check_fetch_policy(self, inputs: Dict[str, Any], constraints: Dict[str, Any] | None = None, session: str = "", caller: str = "unknown") -> Dict[str, Any]:
        """Dry-run network policy without performing the fetch."""
        resource_id = str(inputs.get("resource_id", "example"))
        domain = str(inputs.get("domain", "example.com"))
        pv_constraints = policy_constraints(constraints)
        pv = self.policy.preview(
            intent_id="CheckFetchPolicy",
            inputs={"resource_id": resource_id, "domain": domain, "recipient": str(inputs.get("recipient", "")), "text": str(inputs.get("text", ""))},
            constraints=pv_constraints,
            session=session,
            caller=caller,
        )
        if not pv.get("allow_pre", False):
            return {
                "status": "DENY",
                "summary": "Network fetch would be blocked by policy (dry-run).",
                "data": {"domain": domain, "resource_id": resource_id, "tx_id": pv.get("tx_id"), "patch": pv.get("patch"), "evidence": pv.get("evidence")},
                "artifacts": [],
                "reason_code": str(pv.get("reason_code") or "POLICY_DENY"),
            }
        if pv.get("need_confirm", False):
            return {
                "status": "DENY",
                "summary": "Network fetch requires explicit user confirmation (dry-run).",
                "data": {"domain": domain, "resource_id": resource_id, "tx_id": pv.get("tx_id"), "patch": pv.get("patch"), "evidence": pv.get("evidence")},
                "artifacts": [],
                "reason_code": "REQUIRE_CONFIRM",
            }
        return {
            "status": "OK",
            "summary": "Network fetch would be allowed by policy (dry-run).",
            "data": {"domain": domain, "resource_id": resource_id, "tx_id": pv.get("tx_id"), "patch": pv.get("patch"), "evidence": pv.get("evidence")},
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def fetch(self, inputs: Dict[str, Any], constraints: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        # Demo: only allow fetching a resource_id that maps to a domain.
        resource_id = str(inputs.get("resource_id", "example"))
        domain = str(inputs.get("domain", "example.com"))
        tx_id = str(inputs.get("tx_id") or "").strip()
        user_confirm = bool((constraints or {}).get("user_confirm", False))
        exec_constraints = policy_constraints(constraints, user_confirm=user_confirm)
        pv_constraints = policy_constraints(constraints)

        if not tx_id:
            pv = self.policy.preview(
                intent_id="FetchResource",
                inputs={"resource_id": resource_id, "domain": domain, "recipient": str(inputs.get("recipient", "")), "text": str(inputs.get("text", ""))},
                constraints=pv_constraints,
                session=session,
                caller=caller,
            )
            if not pv.get("allow_pre", False):
                return {
                    "status": "DENY",
                    "summary": "Network fetch blocked by policy.",
                    "data": {"domain": domain, "tx_id": pv.get("tx_id"), "patch": pv.get("patch")},
                    "artifacts": [],
                    "reason_code": str(pv.get("reason_code") or "POLICY_DENY"),
                }
            if pv.get("need_confirm", False) and not user_confirm:
                confirm_data: dict = {"domain": domain, "tx_id": pv.get("tx_id"), "patch": pv.get("patch")}
                if pv.get("confirm_token"):
                    confirm_data["confirm_token"] = str(pv["confirm_token"])
                return {
                    "status": "DENY",
                    "summary": "Network fetch requires explicit user confirmation.",
                    "data": confirm_data,
                    "artifacts": [],
                    "reason_code": "REQUIRE_CONFIRM",
                }
            tx_id = str(pv.get("tx_id") or "")

        auth = self.policy.commit_from_tx(
            tx_id=tx_id,
            intent_id="FetchResource",
            constraints=exec_constraints,
            session=session,
            caller=caller,
        )
        if auth.get("status") != "OK":
            return auth
        auth_data = (auth.get("data") or {})
        commit_ev = auth_data.get("commit_evidence") or {}
        action_id = str(auth_data.get("action_id") or "")
        request_sha256 = str(auth_data.get("request_sha256") or "")
        auth_context = auth_data.get("auth_context") if isinstance(auth_data.get("auth_context"), dict) else {}

        ex = get_executor_client()
        if ex is None:
            return {
                "status": "OK",
                "summary": "Fetched resource (no external executor configured; demo stub).",
                "data": {"resource_id": resource_id, "domain": domain, "content_preview": "<html>...</html>", "tx": {"action_id": action_id, "request_sha256": request_sha256}},
                "artifacts": [],
                "reason_code": "ALLOW_INSECURE_NO_EXECUTOR",
            }
        if not isinstance(commit_ev, dict) or not commit_ev.get("policy0") or not commit_ev.get("policy1"):
            return {"status": "DENY", "summary": "Missing commit evidence for executor enforcement.", "data": {"domain": domain}, "artifacts": [], "reason_code": "MISSING_EVIDENCE"}
        dummy_recipient = os.getenv("DUMMY_RECIPIENT", "alice@example.com")
        dummy_text = os.getenv("DUMMY_TEXT", "hello world")
        resp = ex.fetch(
            action_id=action_id,
            resource_id=resource_id,
            domain=domain,
            evidence={},
            commit=commit_ev,
            caller=caller,
            session=session,
            user_confirm=bool(user_confirm),
            confirm_token=str((constraints or {}).get("confirm_token") or ""),
            recipient=str(dummy_recipient),
            text=str(dummy_text),
            external_principal=str(auth_context.get("external_principal") or ""),
            delegation_jti=str(auth_context.get("delegation_jti") or ""),
            contextual_targets_sha256=str(auth_context.get("contextual_targets_sha256") or ""),
            capsule_hash=str(auth_context.get("capsule_hash") or ""),
        )
        if resp.get("status") != "OK":
            return {
                "status": "DENY",
                "summary": "Executor denied the action.",
                "data": {"domain": domain},
                "artifacts": [],
                "reason_code": str(resp.get("reason_code") or "EXECUTOR_DENY"),
            }
        return {
            "status": "OK",
            "summary": "Fetched resource (executor stub).",
            "data": resp.get("data") or {"resource_id": resource_id, "domain": domain, "content_preview": "<html>...</html>", "tx": {"action_id": action_id, "request_sha256": request_sha256}},
            "artifacts": [],
            "reason_code": "ALLOW",
        }
