from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Set
import os

import yaml


@dataclass(frozen=True, slots=True)
class Capabilities:
    allowed_intents: Set[str]
    egress: Dict[str, bool]

    def allow_intent(self, intent_id: str) -> bool:
        return str(intent_id) in self.allowed_intents

    def egress_ok(self, *, kind: str) -> bool:
        # kind: "send_message" | "fetch_resource" | "post_webhook"
        return bool(self.egress.get(str(kind), False))


_CACHE: Optional[Dict[str, Any]] = None


def _load_cfg() -> Dict[str, Any]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    p = os.getenv("CAPABILITIES_PATH", "").strip()
    if not p:
        p = str(Path(__file__).resolve().parent / "capabilities.yaml")
    try:
        _CACHE = yaml.safe_load(Path(p).read_text(encoding="utf-8")) or {}
    except Exception:
        _CACHE = {}
    if not isinstance(_CACHE, dict):
        _CACHE = {}
    return _CACHE


def _resolve_subject_cfg(subjects: Dict[str, Any], subject: str) -> Dict[str, Any]:
    s = str(subject or "")
    c = subjects.get(s) if isinstance(subjects, dict) else None
    if isinstance(c, dict):
        return c
    if isinstance(subjects, dict):
        best_key = ""
        best_cfg = None
        for k, v in subjects.items():
            ks = str(k)
            if not ks.endswith("*"):
                continue
            prefix = ks[:-1]
            if not prefix:
                continue
            if s.startswith(prefix) and len(prefix) > len(best_key):
                if isinstance(v, dict):
                    best_key = prefix
                    best_cfg = v
        if isinstance(best_cfg, dict):
            return best_cfg
    return {}


def _caps_from_cfg(*, base: Dict[str, Any], override: Dict[str, Any]) -> Capabilities:
    allow_intents = override.get("allow_intents", base.get("allow_intents", []))
    if not isinstance(allow_intents, list):
        allow_intents = []
    allowed_set = set(str(x) for x in allow_intents if x)

    egress0 = base.get("egress") if isinstance(base.get("egress"), dict) else {}
    egress1 = override.get("egress") if isinstance(override.get("egress"), dict) else {}
    egress: Dict[str, bool] = {}
    for k, v in dict(egress0).items():
        egress[str(k)] = bool(v)
    for k, v in dict(egress1).items():
        egress[str(k)] = bool(v)

    return Capabilities(allowed_intents=allowed_set, egress=egress)


def intersect_capabilities(a: Capabilities, b: Capabilities) -> Capabilities:
    allowed = set(a.allowed_intents) & set(b.allowed_intents)
    keys = set(a.egress.keys()) | set(b.egress.keys())
    egress: Dict[str, bool] = {}
    for k in keys:
        egress[str(k)] = bool(a.egress.get(k, False) and b.egress.get(k, False))
    return Capabilities(allowed_intents=allowed, egress=egress)


def get_capabilities(caller: str) -> Capabilities:
    cfg = _load_cfg()
    default = cfg.get("default") if isinstance(cfg.get("default"), dict) else {}
    callers = cfg.get("callers") if isinstance(cfg.get("callers"), dict) else {}
    caller_cfg = _resolve_subject_cfg(callers, str(caller))
    return _caps_from_cfg(base=default, override=caller_cfg)


def get_principal_capabilities(external_principal: str) -> Capabilities:
    cfg = _load_cfg()
    default_actor = cfg.get("default") if isinstance(cfg.get("default"), dict) else {}
    default_principal = cfg.get("principal_default")
    if not isinstance(default_principal, dict):
        default_principal = default_actor
    principals = cfg.get("principals") if isinstance(cfg.get("principals"), dict) else {}
    p_cfg = _resolve_subject_cfg(principals, str(external_principal))
    return _caps_from_cfg(base=default_principal, override=p_cfg)


def get_effective_capabilities(caller: str, external_principal: str | None = None) -> Capabilities:
    actor_caps = get_capabilities(caller)
    p = str(external_principal or "").strip()
    if not p:
        return actor_caps
    principal_caps = get_principal_capabilities(p)
    return intersect_capabilities(actor_caps, principal_caps)
