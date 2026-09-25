from __future__ import annotations

from typing import Any, Dict

from common.canonical import sha256_hex


def _clean_contextual_targets(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        value = str(item or "").strip()
        if not value:
            continue
        norm = value.lower()
        if norm in seen:
            continue
        seen.add(norm)
        out.append(value)
    return out[:64]


def policy_constraints(constraints: Dict[str, Any] | None, *, user_confirm: bool | None = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
    if auth_ctx:
        out["_auth_ctx"] = dict(auth_ctx)
    contextual_targets = _clean_contextual_targets((constraints or {}).get("contextual_targets"))
    if contextual_targets:
        out["contextual_targets"] = list(contextual_targets)
    query_anchored_targets = _clean_contextual_targets((constraints or {}).get("query_anchored_targets"))
    if query_anchored_targets:
        out["query_anchored_targets"] = list(query_anchored_targets)
    capsule_hash = str((constraints or {}).get("capsule_hash") or "").strip()
    if capsule_hash:
        out["capsule_hash"] = capsule_hash
    if user_confirm is not None:
        out["user_confirm"] = bool(user_confirm)
    return out


def request_auth_context(constraints: Dict[str, Any] | None) -> Dict[str, Any]:
    auth_ctx = (constraints or {}).get("_auth_ctx") if isinstance((constraints or {}).get("_auth_ctx"), dict) else {}
    out: Dict[str, Any] = {}
    external_principal = str((auth_ctx or {}).get("external_principal") or "").strip()
    delegation_jti = str((auth_ctx or {}).get("delegation_jti") or "").strip()
    if external_principal:
        out["external_principal"] = external_principal
    if delegation_jti:
        out["delegation_jti"] = delegation_jti
    normalized_targets = sorted({str(x or "").strip().lower() for x in _clean_contextual_targets((constraints or {}).get("contextual_targets")) if str(x or "").strip()})
    if normalized_targets:
        out["contextual_targets_sha256"] = sha256_hex("|".join(normalized_targets).encode("utf-8"))
    return out
