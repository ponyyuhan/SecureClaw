import os
from typing import Dict, Any

from .handles import HandleStore
from .executors.fsexec import FSExec
from .executors.msgexec import MsgExec
from .executors.cryptoexec import CryptoExec
from .executors.netexec import NetExec
from .executors.webhookexec import WebhookExec
from .executors.skillexec import SkillExec
from .executors.interagentexec import InterAgentExec
from .executors.memoryexec import MemoryExec
from .executors.outputexec import OutputExec
from .guardrails import ObliviousGuardrails
from .egress_policy import EgressPolicyEngine
from .skill_policy import SkillIngressPolicyEngine
from .skill_store import SkillStore
from .tx_store import TxStore
from .memory_service import MemoryService
from .interagent_store import InterAgentStore
from .leakage_budget import LeakageBudget
from .turn_gate import TurnGate
from .capabilities import get_effective_capabilities
from .delegation_store import DelegationStore
from .audit import AuditEvent, get_audit_logger, now_ts
from common.delegation_token import parse_and_verify_delegation_token
from common.output_sanitizer import get_output_sanitizer
from common.workload_token import verify_workload_token

class IntentRouter:
    def __init__(self, handles: HandleStore, guardrails: ObliviousGuardrails):
        self.handles = handles
        self.guardrails = guardrails
        self.tx_store = TxStore()
        self.budget = LeakageBudget()
        self.policy = EgressPolicyEngine(pir=guardrails.pir, handles=handles, tx_store=self.tx_store, domain_size=guardrails.domain_size, max_tokens=guardrails.max_tokens)
        self.skill_policy = SkillIngressPolicyEngine(pir=guardrails.pir, tx_store=self.tx_store, domain_size=guardrails.domain_size, max_tokens=guardrails.max_tokens)
        self.skill_store = SkillStore()
        self.memory_service = MemoryService()
        self.inter_agent_store = InterAgentStore()
        self.delegations = DelegationStore()
        self.fs = FSExec(handles)
        self.msg = MsgExec(handles, self.policy)
        self.crypto = CryptoExec(handles, self.tx_store, budget=self.budget)
        self.net = NetExec(handles, self.policy)
        self.webhook = WebhookExec(handles, self.policy)
        self.skill = SkillExec(handles, self.skill_policy, self.skill_store)
        self.inter_agent = InterAgentExec(handles, self.inter_agent_store)
        self.memory = MemoryExec(handles, self.memory_service)
        self.output = OutputExec(self.policy, self.budget)
        self.turn_gate = TurnGate()

    @staticmethod
    def _handle_session_sensitive(
        intent_id: str,
        inputs: Dict[str, Any],
        session: str,
        caller: str,
        audit: Any,
    ) -> Dict[str, Any]:
        sanitizer = get_output_sanitizer()
        if intent_id == "RegisterSessionSensitive":
            raw_items = (inputs or {}).get("items")
            if not isinstance(raw_items, list):
                raw_items = []
            mode = str((inputs or {}).get("mode") or "always_sensitive")
            stats = sanitizer.register_session_values(session=session, items=raw_items, mode=mode)
            obs = {
                "status": "OK",
                "summary": "Session sensitive values registered.",
                "data": dict(stats),
                "artifacts": [],
                "reason_code": "ALLOW",
            }
        else:
            stats = sanitizer.clear_session(session=session)
            obs = {
                "status": "OK",
                "summary": "Session sensitive values cleared.",
                "data": dict(stats),
                "artifacts": [],
                "reason_code": "ALLOW",
            }
        audit.log(
            AuditEvent(
                ts=now_ts(),
                event="act_result",
                session=session,
                caller=caller,
                intent_id=intent_id,
                status=str(obs.get("status", "")),
                reason_code=str(obs.get("reason_code", "")),
            )
        )
        return obs

    @staticmethod
    def _is_side_effect_intent(intent_id: str) -> bool:
        i = str(intent_id or "")
        return i in {
            "SendMessage",
            "FetchResource",
            "PostWebhook",
            "CommitSkillInstall",
            "SendInterAgentMessage",
            "ReceiveInterAgentMessages",
            "MemoryWrite",
            "MemoryRead",
            "MemoryList",
            "MemoryDelete",
            "Declassify",
            "FinalizeOutput",
            "RevokeHandle",
            "RevokeSession",
            "RevokeDelegation",
        }

    def act(self, intent_id: str, inputs: Dict[str, Any], constraints: Dict[str, Any], caller: str, session: str) -> Dict[str, Any]:
        audit = get_audit_logger()
        orig_caller = caller
        if intent_id in ("RegisterSessionSensitive", "ClearSessionSensitive"):
            return self._handle_session_sensitive(intent_id, inputs, session, caller, audit)
        # Optional per-skill workload identity: if present and valid, override the untrusted caller string.
        wt = None
        token = None
        if isinstance(constraints, dict):
            token = constraints.get("workload_token") or constraints.get("workload_token_b64")
        if isinstance(token, str) and token.strip():
            key_hex = os.getenv("WORKLOAD_TOKEN_KEY", "").strip()
            wt = verify_workload_token(key_hex=key_hex, token=token.strip(), session=session)
            if wt is None:
                obs = {
                    "status": "DENY",
                    "summary": "Invalid workload token.",
                    "data": {"caller": str(orig_caller), "intent_id": str(intent_id)},
                    "artifacts": [],
                    "reason_code": "WORKLOAD_TOKEN_INVALID",
                }
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=str(orig_caller), intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs
            caller = f"skill:{wt.skill_digest}"

        c0 = dict(constraints or {})
        auth_ctx = c0.get("_auth_ctx") if isinstance(c0.get("_auth_ctx"), dict) else {}
        external_principal = str(c0.get("external_principal") or auth_ctx.get("external_principal") or "").strip()
        delegation_token = str(c0.get("delegation_token") or "").strip()
        delegation_jti = ""
        if delegation_token:
            key_hex = (os.getenv("DELEGATION_TOKEN_KEY") or "").strip()
            chk = parse_and_verify_delegation_token(
                key_hex=key_hex,
                token=delegation_token,
                expected_session=session,
                expected_subject=caller,
                expected_intent=intent_id,
            )
            if not chk.ok or chk.token is None:
                obs = {
                    "status": "DENY",
                    "summary": "Delegation token verification failed.",
                    "data": {"caller": str(caller), "intent_id": str(intent_id), "reason_code": str(chk.code)},
                    "artifacts": [],
                    "reason_code": str(chk.code),
                }
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=str(caller), intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs
            tok = chk.token
            delegation_jti = str(tok.jti)
            if self.delegations.is_revoked(delegation_jti):
                obs = {
                    "status": "DENY",
                    "summary": "Delegation token revoked.",
                    "data": {"caller": str(caller), "intent_id": str(intent_id), "delegation_jti": delegation_jti},
                    "artifacts": [],
                    "reason_code": "DELEGATION_REVOKED",
                }
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=str(caller), intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs
            if external_principal and external_principal != tok.iss:
                obs = {
                    "status": "DENY",
                    "summary": "External principal mismatches delegation issuer.",
                    "data": {"runtime_external_principal": external_principal, "delegation_issuer": tok.iss},
                    "artifacts": [],
                    "reason_code": "EXTERNAL_PRINCIPAL_MISMATCH",
                }
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=str(caller), intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs
            external_principal = str(tok.iss)

        if external_principal and self._is_side_effect_intent(intent_id):
            req_dlg = bool(int(os.getenv("DELEGATION_REQUIRED_FOR_EXTERNAL", "1") or "1"))
            if req_dlg and not delegation_jti:
                obs = {
                    "status": "DENY",
                    "summary": "External principal requires a delegation token for side effects.",
                    "data": {"external_principal": external_principal, "intent_id": str(intent_id)},
                    "artifacts": [],
                    "reason_code": "DELEGATION_REQUIRED",
                }
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=str(caller), intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs

        constraints2 = dict(c0)
        merged_ctx = dict(auth_ctx)
        if external_principal:
            merged_ctx["external_principal"] = external_principal
            constraints2["external_principal"] = external_principal
        if delegation_jti:
            merged_ctx["delegation_jti"] = delegation_jti
        if merged_ctx:
            constraints2["_auth_ctx"] = merged_ctx

        audit.log(
            AuditEvent(
                ts=now_ts(),
                event="act_request",
                session=session,
                caller=caller,
                intent_id=intent_id,
                data={
                    "input_keys": sorted(list((inputs or {}).keys())),
                    "orig_caller": str(orig_caller),
                    "workload_skill_digest": (wt.skill_digest if wt else ""),
                    "external_principal": external_principal,
                    "delegation_jti": delegation_jti,
                },
            )
        )

        caps = get_effective_capabilities(caller, external_principal=(external_principal or None))
        if not caps.allow_intent(intent_id):
            obs = {
                "status": "DENY",
                "summary": "Caller capability does not allow this intent.",
                "data": {"caller": caller, "intent_id": intent_id, "external_principal": external_principal},
                "artifacts": [],
                "reason_code": ("PRINCIPAL_CAPABILITY_DENY" if external_principal else "CAPABILITY_DENY"),
            }
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs

        if intent_id != "FinalizeOutput":
            ok_turn, code_turn, turn_data = self.turn_gate.on_non_finalize(
                session=session,
                caller=caller,
                turn_id=str((constraints2 or {}).get("turn_id", "")),
            )
            if not ok_turn:
                obs = {
                    "status": "DENY",
                    "summary": "Per-turn final output gate not satisfied.",
                    "data": turn_data,
                    "artifacts": [],
                    "reason_code": code_turn,
                }
                audit.log(
                    AuditEvent(
                        ts=now_ts(),
                        event="act_result",
                        session=session,
                        caller=caller,
                        intent_id=intent_id,
                        status=str(obs.get("status", "")),
                        reason_code=str(obs.get("reason_code", "")),
                    )
                )
                return obs

        # Level 2: the agent cannot choose low-level tools; only intents exist.
        if intent_id == "ReadFile":
            obs = self.fs.read_file(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ReadSecret":
            obs = self.crypto.read_secret(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "UseCredential":
            obs = self.crypto.use_credential(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "Declassify":
            obs = self.crypto.declassify(inputs, constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckMessagePolicy":
            obs = self.msg.check_message_policy(inputs, constraints=constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "SendMessage":
            obs = self.msg.send_message(inputs, constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckWebhookPolicy":
            obs = self.webhook.check_webhook_policy(inputs, constraints=constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "PostWebhook":
            obs = self.webhook.post_webhook(inputs, constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "FetchResource":
            obs = self.net.fetch(inputs, constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckFetchPolicy":
            obs = self.net.check_fetch_policy(inputs, constraints=constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "WriteWorkspaceFile":
            obs = self.fs.write_workspace_file(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "DescribeHandle":
            obs = self.crypto.describe_handle(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "RevokeHandle":
            obs = self.crypto.revoke_handle(inputs, constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "RevokeSession":
            obs = self.crypto.revoke_session(inputs, constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "RevokeDelegation":
            user_confirm = bool((constraints2 or {}).get("user_confirm", False))
            jti = str((inputs or {}).get("delegation_jti") or "").strip()
            if not user_confirm:
                obs = {"status": "DENY", "summary": "Delegation revocation requires explicit user confirmation.", "data": {"delegation_jti": jti}, "artifacts": [], "reason_code": "REQUIRE_CONFIRM"}
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs
            if not jti:
                obs = {"status": "DENY", "summary": "Missing delegation_jti.", "data": {}, "artifacts": [], "reason_code": "BAD_ARGS"}
                audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
                return obs
            ok = self.delegations.revoke(jti=jti, session=session, caller=caller, reason=str((inputs or {}).get("reason") or ""))
            obs = {"status": "OK" if ok else "DENY", "summary": "Delegation revoked." if ok else "Delegation revocation failed.", "data": {"delegation_jti": jti}, "artifacts": [], "reason_code": "ALLOW" if ok else "DELEGATION_REVOKE_FAILED"}
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ListWorkspaceFiles":
            obs = self.fs.list_workspace_files(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ReadWorkspaceFile":
            obs = self.fs.read_workspace_file(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ImportSkill":
            obs = self.skill.import_skill(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "DescribeSkill":
            obs = self.skill.describe_skill(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CheckSkillInstallPolicy":
            obs = self.skill.check_skill_install_policy(inputs, constraints=constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "CommitSkillInstall":
            obs = self.skill.commit_skill_install(inputs, constraints2, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ListEnabledSkills":
            obs = self.skill.list_enabled_skills(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "SendInterAgentMessage":
            obs = self.inter_agent.send(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "ReceiveInterAgentMessages":
            obs = self.inter_agent.receive(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "MemoryWrite":
            obs = self.memory.write(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "MemoryRead":
            obs = self.memory.read(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "MemoryList":
            obs = self.memory.list_keys(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "MemoryDelete":
            obs = self.memory.delete(inputs, session=session, caller=caller)
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        if intent_id == "FinalizeOutput":
            obs = self.output.finalize_output(inputs, constraints2, session=session, caller=caller)
            if str(obs.get("status", "")) == "OK":
                okf, codef, dataf = self.turn_gate.on_finalize(
                    session=session,
                    caller=caller,
                    turn_id=str((constraints2 or {}).get("turn_id", "")),
                )
                if not okf:
                    obs = {
                        "status": "DENY",
                        "summary": "Final output gate metadata mismatch.",
                        "data": dataf,
                        "artifacts": [],
                        "reason_code": codef,
                    }
            audit.log(AuditEvent(ts=now_ts(), event="act_result", session=session, caller=caller, intent_id=intent_id, status=str(obs.get("status", "")), reason_code=str(obs.get("reason_code", ""))))
            return obs
        return {
            "status": "DENY",
            "summary": f"Unknown intent_id: {intent_id}",
            "data": {},
            "artifacts": [],
            "reason_code": "UNKNOWN_INTENT",
        }
