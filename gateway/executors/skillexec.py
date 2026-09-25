from __future__ import annotations

import os
from typing import Any, Dict

from common.sanitize import PATCH_NOOP, SanitizePatch

from ..executor_client import get_executor_client
from ..handles import HandleStore
from ..skill_ingress import extract_install_tokens, extract_skill_ingress_features, sanitize_skill_markdown
from ..skill_policy import SkillIngressPolicyEngine
from ..skill_store import SkillStore


class SkillExec:
    def __init__(self, handles: HandleStore, policy: SkillIngressPolicyEngine, store: SkillStore):
        self.handles = handles
        self.policy = policy
        self.store = store

    def import_skill(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        # MVP: accept only local zip/dir sources to keep artifact deterministic.
        source = str(inputs.get("zip_path") or inputs.get("path") or inputs.get("source") or "").strip()
        if not source:
            return {"status": "DENY", "summary": "Missing skill source (zip_path/path).", "data": {}, "artifacts": [], "reason_code": "BAD_REQUEST"}

        hint = str(inputs.get("skill_id_hint") or "").strip() or None
        try:
            staged = self.store.stage(source=source, skill_id_hint=hint)
            skill_md = self.store.read_skill_md(staged)
        except Exception as e:
            return {"status": "DENY", "summary": "Failed to stage skill package.", "data": {"error": str(e)}, "artifacts": [], "reason_code": "STAGE_FAILED"}

        # Store the package as a HIGH handle so the agent cannot read raw SKILL.md by default.
        rec = self.handles.mint(
            label="SKILL_PACKAGE",
            sensitivity="HIGH",
            value={
                "skill_id": staged.skill_id,
                "skill_digest": staged.digest,
                "staged_dir": staged.staged_dir,
                "skill_md_relpath": staged.skill_md_relpath,
                "skill_md": skill_md,
                "file_count": staged.file_count,
            },
            allowed_sinks=["CheckSkillInstallPolicy", "DescribeSkill"],
            session=session,
            caller=caller,
            issuer_intent="ImportSkill",
            ttl_seconds=int(os.getenv("SKILL_PKG_TTL_S", "600")),
        )
        return {
            "status": "OK",
            "summary": "Skill package staged (no code executed). Returning an opaque handle.",
            "data": {"skill_id": staged.skill_id, "skill_digest": staged.digest, "file_count": staged.file_count},
            "artifacts": [{"handle": rec.handle, "label": rec.label, "sensitivity": rec.sensitivity}],
            "reason_code": "SKILL_IMPORTED",
        }

    def describe_skill(self, inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        hid = str(inputs.get("skill_pkg_handle") or inputs.get("handle") or "").strip()
        if not hid:
            return {"status": "DENY", "summary": "Missing handle.", "data": {}, "artifacts": [], "reason_code": "BAD_REQUEST"}
        rec = self.handles.get(hid)
        if not rec:
            return {"status": "DENY", "summary": "Unknown or expired handle.", "data": {}, "artifacts": [], "reason_code": "HANDLE_NOT_FOUND"}
        if rec.session != session:
            return {"status": "DENY", "summary": "Handle bound to a different session.", "data": {}, "artifacts": [], "reason_code": "HANDLE_SESSION_MISMATCH"}
        if rec.caller != caller:
            return {"status": "DENY", "summary": "Handle bound to a different caller.", "data": {}, "artifacts": [], "reason_code": "HANDLE_CALLER_MISMATCH"}
        if rec.label != "SKILL_PACKAGE":
            return {"status": "DENY", "summary": "Handle is not a skill package.", "data": {}, "artifacts": [], "reason_code": "BAD_HANDLE_LABEL"}

        v = rec.value if isinstance(rec.value, dict) else {}
        skill_md = str(v.get("skill_md") or "")
        feats = extract_skill_ingress_features(text=skill_md, max_domains=int(os.getenv("MAX_SKILL_DOMAINS", "16")))
        install_tokens = extract_install_tokens(text=skill_md, max_tokens=16)
        safe = sanitize_skill_markdown(text=skill_md, max_chars=int(os.getenv("SKILL_MD_MAX_CHARS", "2000")))
        risk: list[str] = []
        if install_tokens:
            risk.append("download_execute")
        if feats.has_base64_obf:
            risk.append("obfuscation")
        if feats.domains:
            risk.append("external_network_refs")
        expl = []
        if "download_execute" in risk:
            expl.append("Doc suggests download-and-execute install patterns (e.g., curl|bash / wget|sh).")
        if "obfuscation" in risk:
            expl.append("Doc contains base64-like payloads or decode instructions (often used to hide staged loaders).")
        if "external_network_refs" in risk:
            expl.append("Doc references external domains/IPs (potential staged download infrastructure).")
        if not expl:
            expl.append("No high-risk install/obfuscation markers detected in the doc (best-effort heuristic).")
        return {
            "status": "OK",
            "summary": "Sanitized skill description (raw SKILL.md withheld).",
            "data": {
                "skill_id": str(v.get("skill_id") or ""),
                "skill_digest": str(v.get("skill_digest") or ""),
                "domains": feats.domains,
                "install_tokens_present": bool(install_tokens),
                "has_exec_marker": feats.has_exec_marker,
                "has_base64_obf": feats.has_base64_obf,
                "risk_categories": risk,
                # Do not leak exact IOC rules; this is a human-facing template.
                "risk_explanation": " ".join(expl),
                "skill_md_sanitized": safe,
            },
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def check_skill_install_policy(self, inputs: Dict[str, Any], constraints: Dict[str, Any] | None = None, session: str = "", caller: str = "unknown") -> Dict[str, Any]:
        hid = str(inputs.get("skill_pkg_handle") or inputs.get("handle") or "").strip()
        if not hid:
            return {"status": "DENY", "summary": "Missing skill_pkg_handle.", "data": {}, "artifacts": [], "reason_code": "BAD_REQUEST"}
        rec = self.handles.get(hid)
        if not rec:
            return {"status": "DENY", "summary": "Unknown or expired handle.", "data": {}, "artifacts": [], "reason_code": "HANDLE_NOT_FOUND"}
        if rec.session != session:
            return {"status": "DENY", "summary": "Handle bound to a different session.", "data": {}, "artifacts": [], "reason_code": "HANDLE_SESSION_MISMATCH"}
        if rec.caller != caller:
            return {"status": "DENY", "summary": "Handle bound to a different caller.", "data": {}, "artifacts": [], "reason_code": "HANDLE_CALLER_MISMATCH"}
        if rec.label != "SKILL_PACKAGE":
            return {"status": "DENY", "summary": "Handle is not a skill package.", "data": {}, "artifacts": [], "reason_code": "BAD_HANDLE_LABEL"}

        v = rec.value if isinstance(rec.value, dict) else {}
        skill_id = str(v.get("skill_id") or "")
        skill_digest = str(v.get("skill_digest") or "")
        skill_md = str(v.get("skill_md") or "")
        feats = extract_skill_ingress_features(text=skill_md, max_domains=int(os.getenv("MAX_SKILL_DOMAINS", "16")))
        install_tokens = extract_install_tokens(text=skill_md, max_tokens=16)

        auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
        pv = self.policy.preview(
            skill_id=skill_id,
            skill_digest=skill_digest,
            skill_md=skill_md,
            domains=feats.domains,
            base64_obf=bool(feats.has_base64_obf),
            session=session,
            caller=caller,
            auth_context=dict(auth_ctx) if auth_ctx else None,
        )

        risk: list[str] = []
        if install_tokens:
            risk.append("download_execute")
        if feats.has_base64_obf:
            risk.append("obfuscation")
        if str(pv.get("reason_code") or "") == "IOC_BLOCKED":
            risk.append("ioc_match")
        expl = []
        if "ioc_match" in risk:
            expl.append("Known-bad infrastructure match (IOC). Exact indicator is withheld.")
        if "download_execute" in risk:
            expl.append("Suspicious install semantics markers found (download-and-execute).")
        if "obfuscation" in risk:
            expl.append("Obfuscation markers found (base64-like content).")
        if not expl:
            expl.append("No high-risk markers found by ingress checks (best-effort).")

        if not pv.get("allow_pre", False):
            return {
                "status": "DENY",
                "summary": "Skill install blocked by policy (dry-run).",
                "data": {
                    "skill_id": skill_id,
                    "skill_digest": skill_digest,
                    "tx_id": pv.get("tx_id"),
                    "patch": pv.get("patch"),
                    "evidence": pv.get("evidence"),
                    "risk_categories": risk,
                    "risk_explanation": " ".join(expl),
                },
                "artifacts": [],
                "reason_code": str(pv.get("reason_code") or "POLICY_DENY"),
            }
        if pv.get("need_confirm", False):
            skill_confirm_data: dict = {
                "skill_id": skill_id,
                "skill_digest": skill_digest,
                "tx_id": pv.get("tx_id"),
                "patch": pv.get("patch"),
                "evidence": pv.get("evidence"),
                "risk_categories": risk,
                "risk_explanation": " ".join(expl),
            }
            if pv.get("confirm_token"):
                skill_confirm_data["confirm_token"] = str(pv["confirm_token"])
            return {
                "status": "DENY",
                "summary": "Skill install requires explicit user confirmation (dry-run).",
                "data": skill_confirm_data,
                "artifacts": [],
                "reason_code": "REQUIRE_CONFIRM",
            }
        return {
            "status": "OK",
            "summary": "Skill would be allowed by policy (dry-run).",
            "data": {
                "skill_id": skill_id,
                "skill_digest": skill_digest,
                "tx_id": pv.get("tx_id"),
                "patch": pv.get("patch"),
                "evidence": pv.get("evidence"),
                "risk_categories": risk,
                "risk_explanation": " ".join(expl),
            },
            "artifacts": [],
            "reason_code": "ALLOW",
        }

    def commit_skill_install(self, inputs: Dict[str, Any], constraints: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        tx_id = str(inputs.get("tx_id") or "").strip()
        if not tx_id:
            return {"status": "DENY", "summary": "Missing tx_id.", "data": {}, "artifacts": [], "reason_code": "BAD_REQUEST"}

        user_confirm = bool((constraints or {}).get("user_confirm", False))
        auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
        auth = self.policy.commit_from_tx(
            tx_id=tx_id,
            constraints={"user_confirm": user_confirm, "_auth_ctx": dict(auth_ctx)} if auth_ctx else {"user_confirm": user_confirm},
            session=session,
            caller=caller,
        )
        if auth.get("status") != "OK":
            return auth

        d = auth.get("data") or {}
        commit_ev = d.get("commit_evidence") or {}
        action_id = str(d.get("action_id") or "")
        request_sha256 = str(d.get("request_sha256") or "")
        skill_id = str(d.get("skill_id") or "")
        skill_digest = str(d.get("skill_digest") or "")

        ex = get_executor_client()
        if ex is None:
            # Demo fallback: if executor is not configured, do not actually enable.
            return {
                "status": "OK",
                "summary": "Skill install authorized (no executor configured; demo stub).",
                "data": {"skill_id": skill_id, "skill_digest": skill_digest, "tx": {"action_id": action_id, "request_sha256": request_sha256}},
                "artifacts": [],
                "reason_code": "ALLOW_INSECURE_NO_EXECUTOR",
            }

        if not isinstance(commit_ev, dict) or not commit_ev.get("policy0") or not commit_ev.get("policy1"):
            return {"status": "DENY", "summary": "Missing commit evidence for executor enforcement.", "data": {"skill_id": skill_id}, "artifacts": [], "reason_code": "MISSING_EVIDENCE"}

        resp = ex.install_skill(
            action_id=action_id,
            skill_id=skill_id,
            skill_digest=skill_digest,
            commit=commit_ev,
            caller=caller,
            session=session,
            user_confirm=bool(user_confirm),
            confirm_token=str((constraints or {}).get("confirm_token") or ""),
            external_principal=str(auth_ctx.get("external_principal") or ""),
            delegation_jti=str(auth_ctx.get("delegation_jti") or ""),
        )
        if resp.get("status") != "OK":
            return {"status": "DENY", "summary": "Executor denied skill install.", "data": {"skill_id": skill_id}, "artifacts": [], "reason_code": str(resp.get("reason_code") or "EXECUTOR_DENY")}

        return {"status": "OK", "summary": "Skill enabled (executor registry).", "data": resp.get("data") or {"skill_id": skill_id, "skill_digest": skill_digest}, "artifacts": [], "reason_code": "ALLOW"}

    def list_enabled_skills(self, _inputs: Dict[str, Any], session: str, caller: str = "unknown") -> Dict[str, Any]:
        _ = session
        _ = caller
        skills = self.store.list_enabled()
        return {"status": "OK", "summary": "Enabled skills.", "data": {"skills": skills}, "artifacts": [], "reason_code": "ALLOW"}
