import os
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Any, Dict, List

from .config import settings
from .handles import HandleStore
from .fss_pir import PirClient
from .guardrails import ObliviousGuardrails
from .router import IntentRouter

app = FastAPI(title="MIRAGE-OG++ Gateway", version="0.1")

handles = HandleStore()
pir = PirClient(
    policy0_url=settings.policy_servers[0],
    policy1_url=settings.policy_servers[1],
    domain_size=settings.fss_domain_size,
    policy0_uds_path=(os.getenv("POLICY0_UDS_PATH") or "").strip() or None,
    policy1_uds_path=(os.getenv("POLICY1_UDS_PATH") or "").strip() or None,
)
guardrails = ObliviousGuardrails(
    pir=pir,
    handles=handles,
    domain_size=settings.fss_domain_size,
    max_tokens=settings.max_tokens_per_message,
)
router = IntentRouter(handles=handles, guardrails=guardrails)

class ActRequest(BaseModel):
    intent_id: str = Field(..., description="High-level intent ID (no low-level tools).")
    inputs: Dict[str, Any] = Field(default_factory=dict)
    constraints: Dict[str, Any] = Field(default_factory=dict)
    caller: str = Field(..., description="Skill/agent identity (untrusted).")

@app.get("/health")
def health():
    return {"ok": True, "policy_servers": settings.policy_servers, "domain_size": settings.fss_domain_size}

@app.post("/act")
def act(req: ActRequest):
    # In a real system, session would be bound to user identity, device attestation, etc.
    session = "demo-session"
    return router.act(req.intent_id, req.inputs, req.constraints, caller=req.caller, session=session)

def main():
    uvicorn.run("gateway.app:app", host="0.0.0.0", port=settings.gateway_port, reload=False)

if __name__ == "__main__":
    main()
