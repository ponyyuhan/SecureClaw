from __future__ import annotations

import os
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, ValidationError

from .config import settings
from .federated_auth import verify_federated_ingress
from .fss_pir import PirClient
from .guardrails import ObliviousGuardrails
from .handles import HandleStore
from .router import IntentRouter


class ActArgs(BaseModel):
    intent_id: str = Field(..., description="High-level intent ID (no low-level tools).")
    inputs: Dict[str, Any] = Field(default_factory=dict)
    constraints: Dict[str, Any] = Field(default_factory=dict)
    caller: str = Field(..., description="Skill/agent identity (untrusted).")


def _require_bearer_token(authorization: str | None) -> None:
    """
    Optional HTTP auth layer for the capsule transport.

    If MIRAGE_HTTP_TOKEN is set, requests must include:
      Authorization: Bearer <token>
    """

    token = (os.getenv("MIRAGE_HTTP_TOKEN") or "").strip()
    if not token:
        return
    if not authorization or authorization.strip() != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="missing/invalid bearer token")


def _resolve_session(x_mirage_session: str | None) -> str:
    # Session binding is enforced inside the gateway (trusted side) so sealed handles
    # are useless outside the issuing session.
    # For capsule use-cases, the proxy sets X-Mirage-Session.
    return (x_mirage_session or os.getenv("MIRAGE_SESSION_ID") or "demo-session").strip() or "demo-session"


app = FastAPI(title="MIRAGE Gateway (HTTP)", version="0.1")

_handles = HandleStore()
_pir = PirClient(
    policy0_url=settings.policy_servers[0],
    policy1_url=settings.policy_servers[1],
    domain_size=settings.fss_domain_size,
    policy0_uds_path=(os.getenv("POLICY0_UDS_PATH") or "").strip() or None,
    policy1_uds_path=(os.getenv("POLICY1_UDS_PATH") or "").strip() or None,
)
_guardrails = ObliviousGuardrails(
    pir=_pir,
    handles=_handles,
    domain_size=settings.fss_domain_size,
    max_tokens=settings.max_tokens_per_message,
)
_router = IntentRouter(handles=_handles, guardrails=_guardrails)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True}


@app.post("/act")
def act(
    payload: dict[str, Any],
    authorization: str | None = Header(default=None),
    x_mirage_session: str | None = Header(default=None),
    x_mirage_external_principal: str | None = Header(default=None),
    x_mirage_delegation_token: str | None = Header(default=None),
    x_mtls_client_cert_sha256: str | None = Header(default=None),
    x_forwarded_client_cert_sha256: str | None = Header(default=None),
    x_mirage_sig_kid: str | None = Header(default=None),
    x_mirage_sig: str | None = Header(default=None),
    x_mirage_sig_ts_ms: str | None = Header(default=None),
    x_mirage_sig_nonce: str | None = Header(default=None),
    x_mirage_proof_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_bearer_token(authorization)
    session = _resolve_session(x_mirage_session)

    try:
        act_args = ActArgs.model_validate(payload)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail={"error": "bad arguments", "details": e.errors()})

    fd = verify_federated_ingress(
        method="POST",
        path="/act",
        payload=payload if isinstance(payload, dict) else {},
        session=session,
        external_principal=str(x_mirage_external_principal or ""),
        mtls_client_cert_sha256=str(x_mtls_client_cert_sha256 or x_forwarded_client_cert_sha256 or ""),
        sig_kid=str(x_mirage_sig_kid or ""),
        sig_value=str(x_mirage_sig or ""),
        sig_ts_ms=str(x_mirage_sig_ts_ms or ""),
        sig_nonce=str(x_mirage_sig_nonce or ""),
        proof_token=str(x_mirage_proof_token or ""),
    )
    if not fd.ok:
        raise HTTPException(status_code=403, detail={"error": "federated_auth_failed", "reason_code": fd.code})

    constraints = dict(act_args.constraints or {})
    # HTTP ingress identity is trusted input; runtime-provided constraints are not.
    c_ext = str((constraints or {}).get("external_principal") or "").strip()
    if fd.external_principal:
        if c_ext and c_ext != fd.external_principal:
            raise HTTPException(
                status_code=400,
                detail={"error": "external_principal_mismatch", "runtime": c_ext, "ingress": fd.external_principal},
            )
        constraints["external_principal"] = fd.external_principal
    if isinstance(x_mirage_delegation_token, str) and x_mirage_delegation_token.strip():
        constraints["delegation_token"] = x_mirage_delegation_token.strip()
    auth_ctx = dict(fd.auth_context or {})
    if auth_ctx:
        old_ctx = constraints.get("_auth_ctx")
        if isinstance(old_ctx, dict):
            merged = dict(old_ctx)
            merged.update(auth_ctx)
            constraints["_auth_ctx"] = merged
        else:
            constraints["_auth_ctx"] = auth_ctx

    obs = _router.act(
        act_args.intent_id,
        act_args.inputs,
        constraints,
        caller=act_args.caller,
        session=session,
    )
    return obs


def main() -> None:
    host = (os.getenv("MIRAGE_HTTP_BIND") or "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.getenv("MIRAGE_HTTP_PORT") or os.getenv("PORT") or "8765")
    uds = (os.getenv("MIRAGE_HTTP_UDS") or "").strip()
    if uds:
        # UDS transport lets the capsule run with network fully disabled.
        # Ensure we can (re)bind deterministically.
        try:
            if os.path.exists(uds):
                os.unlink(uds)
        except Exception:
            pass
        uvicorn.run(app, uds=uds, log_level=os.getenv("LOG_LEVEL", "info"))
        return
    uvicorn.run(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
