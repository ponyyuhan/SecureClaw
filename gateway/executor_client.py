from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from .http_session import session_for


@dataclass(frozen=True, slots=True)
class ExecutorClient:
    base_url: str

    def send_message(
        self,
        *,
        action_id: str,
        channel: str,
        recipient: str,
        text: str,
        artifacts: list[dict[str, Any]],
        dlp_mode: str,
        evidence: dict[str, Any] | None = None,
        commit: dict[str, Any] | None = None,
        caller: str = "",
        session: str = "",
        user_confirm: bool = False,
        confirm_token: str = "",
        domain: str = "",
        external_principal: str = "",
        delegation_jti: str = "",
        contextual_targets_sha256: str = "",
        capsule_hash: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "action_id": action_id,
            "channel": channel,
            "recipient": recipient,
            "domain": domain,
            "text": text,
            "artifacts": artifacts or [],
            "dlp_mode": dlp_mode,
            "evidence": evidence or {},
            "commit": commit or {},
            "caller": caller,
            "session": session,
            "user_confirm": bool(user_confirm),
            "confirm_token": str(confirm_token or ""),
            "external_principal": str(external_principal or ""),
            "delegation_jti": str(delegation_jti or ""),
            "contextual_targets_sha256": str(contextual_targets_sha256 or ""),
            "capsule_hash": str(capsule_hash or ""),
        }
        u = str(self.base_url).rstrip("/")
        r = session_for(u).post(f"{u}/exec/send_message", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()

    def fetch(
        self,
        *,
        action_id: str,
        resource_id: str,
        domain: str,
        evidence: dict[str, Any] | None = None,
        commit: dict[str, Any] | None = None,
        caller: str = "",
        session: str = "",
        user_confirm: bool = False,
        confirm_token: str = "",
        recipient: str = "",
        text: str = "",
        external_principal: str = "",
        delegation_jti: str = "",
        contextual_targets_sha256: str = "",
        capsule_hash: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "action_id": action_id,
            "resource_id": resource_id,
            "domain": domain,
            "evidence": evidence or {},
            "commit": commit or {},
            "caller": caller,
            "session": session,
            "user_confirm": bool(user_confirm),
            "confirm_token": str(confirm_token or ""),
            "recipient": recipient,
            "text": text,
            "external_principal": str(external_principal or ""),
            "delegation_jti": str(delegation_jti or ""),
            "contextual_targets_sha256": str(contextual_targets_sha256 or ""),
            "capsule_hash": str(capsule_hash or ""),
        }
        u = str(self.base_url).rstrip("/")
        r = session_for(u).post(f"{u}/exec/fetch", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()

    def webhook(
        self,
        *,
        action_id: str,
        domain: str,
        path: str,
        body: str,
        evidence: dict[str, Any] | None = None,
        commit: dict[str, Any] | None = None,
        caller: str = "",
        session: str = "",
        user_confirm: bool = False,
        confirm_token: str = "",
        recipient: str = "",
        text: str = "",
        external_principal: str = "",
        delegation_jti: str = "",
        contextual_targets_sha256: str = "",
        capsule_hash: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "action_id": action_id,
            "domain": domain,
            "path": path,
            "body": body,
            "evidence": evidence or {},
            "commit": commit or {},
            "caller": caller,
            "session": session,
            "user_confirm": bool(user_confirm),
            "confirm_token": str(confirm_token or ""),
            "recipient": recipient,
            "text": text,
            "external_principal": str(external_principal or ""),
            "delegation_jti": str(delegation_jti or ""),
            "contextual_targets_sha256": str(contextual_targets_sha256 or ""),
            "capsule_hash": str(capsule_hash or ""),
        }
        u = str(self.base_url).rstrip("/")
        r = session_for(u).post(f"{u}/exec/webhook", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()

    def install_skill(
        self,
        *,
        action_id: str,
        skill_id: str,
        skill_digest: str,
        commit: dict[str, Any] | None = None,
        caller: str = "",
        session: str = "",
        user_confirm: bool = False,
        confirm_token: str = "",
        external_principal: str = "",
        delegation_jti: str = "",
    ) -> Dict[str, Any]:
        payload = {
            "action_id": action_id,
            "skill_id": skill_id,
            "skill_digest": skill_digest,
            "commit": commit or {},
            "caller": caller,
            "session": session,
            "user_confirm": bool(user_confirm),
            "confirm_token": str(confirm_token or ""),
            "external_principal": str(external_principal or ""),
            "delegation_jti": str(delegation_jti or ""),
        }
        u = str(self.base_url).rstrip("/")
        r = session_for(u).post(f"{u}/exec/skill_install", json=payload, timeout=10)
        r.raise_for_status()
        return r.json()


def get_executor_client() -> Optional[ExecutorClient]:
    url = os.getenv("EXECUTOR_URL", "").strip()
    if not url:
        return None
    return ExecutorClient(base_url=url.rstrip("/"))
