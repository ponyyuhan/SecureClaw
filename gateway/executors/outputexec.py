from __future__ import annotations

import os
from typing import Any, Dict

from common.output_sanitizer import get_output_sanitizer
from common.sanitize import SanitizePatch, apply_patch_to_message
from ..egress_policy import EgressPolicyEngine
from ..leakage_budget import LeakageBudget
from .constraint_utils import policy_constraints


class OutputExec:
    """
    C1 final output gate.

    Forces each final assistant output through policy checks + optional confirm,
    then accounts leakage against the channel budget.
    """

    def __init__(self, policy: EgressPolicyEngine, budget: LeakageBudget):
        self.policy = policy
        self.budget = budget

    def finalize_output(self, inputs: Dict[str, Any], constraints: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        text = str(inputs.get("text", ""))
        artifacts = inputs.get("artifacts", []) or []
        user_confirm = bool((constraints or {}).get("user_confirm", False))
        pv_constraints = policy_constraints(constraints)
        confirm_always = bool(int(os.getenv("MIRAGE_FINAL_OUTPUT_CONFIRM_ALWAYS", "1")))

        pv = self.policy.preview(
            intent_id="CheckMessagePolicy",
            inputs={
                "channel": "assistant_output",
                "recipient": "alice@example.com",
                "domain": "",
                "text": text,
                "artifacts": list(artifacts),
            },
            constraints=pv_constraints,
            session=session,
            caller=caller,
        )
        allow_pre = bool(pv.get("allow_pre", False))
        need_confirm = bool(pv.get("need_confirm", False)) or confirm_always
        if not allow_pre:
            return {
                "status": "DENY",
                "summary": "Final output blocked by output gate policy.",
                "data": {
                    "tx_id": pv.get("tx_id"),
                    "reason_code": pv.get("reason_code"),
                    "patch": pv.get("patch"),
                    "evidence": pv.get("evidence"),
                },
                "artifacts": [],
                "reason_code": str(pv.get("reason_code") or "POLICY_DENY"),
            }
        if need_confirm and not user_confirm:
            return {
                "status": "DENY",
                "summary": "Final output requires explicit user confirmation.",
                "data": {"tx_id": pv.get("tx_id"), "patch": pv.get("patch"), "evidence": pv.get("evidence")},
                "artifacts": [],
                "reason_code": "REQUIRE_CONFIRM",
            }

        if need_confirm:
            tx_id = str(pv.get("tx_id") or "")
            auth = self.policy.commit_from_tx(
                tx_id=tx_id,
                intent_id="CheckMessagePolicy",
                constraints=policy_constraints(constraints, user_confirm=True),
                session=session,
                caller=caller,
            )
            if str(auth.get("status") or "") != "OK":
                return auth

        p = pv.get("patch") if isinstance(pv.get("patch"), dict) else {}
        patch = SanitizePatch(
            int(p.get("patch_id", 0)),
            dict(p.get("params", {}) if isinstance(p.get("params"), dict) else {}),
        )
        safe_text = apply_patch_to_message(text=text, patch=patch)
        safe_text, sanitize_meta = get_output_sanitizer().sanitize(session=session, text=safe_text)

        dec = self.budget.consume(session=session, caller=caller, channel="C1", units=len(safe_text))
        if not dec.ok:
            return {
                "status": "DENY",
                "summary": "Final output blocked by leakage budget.",
                "data": {"budget": dec.to_dict(), "tx_id": pv.get("tx_id")},
                "artifacts": [],
                "reason_code": "LEAKAGE_BUDGET_EXCEEDED",
            }
        return {
            "status": "OK",
            "summary": "Final output approved by output gate.",
            "data": {
                "safe_text": safe_text,
                "budget": dec.to_dict(),
                "tx_id": pv.get("tx_id"),
                "evidence": pv.get("evidence"),
                "sanitize": sanitize_meta,
            },
            "artifacts": [],
            "reason_code": "ALLOW",
        }
