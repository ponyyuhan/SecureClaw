from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict


PATCH_NOOP = 0
PATCH_REDACT = 1
PATCH_CLAMP_LEN = 2
PATCH_REWRITE_DOMAIN_TO_PROXY = 3


def patch_name(patch_id: int) -> str:
    pid = int(patch_id)
    if pid == PATCH_NOOP:
        return "NOOP"
    if pid == PATCH_REDACT:
        return "REDACT"
    if pid == PATCH_CLAMP_LEN:
        return "CLAMP_LEN"
    if pid == PATCH_REWRITE_DOMAIN_TO_PROXY:
        return "REWRITE_DOMAIN_TO_PROXY"
    return f"UNKNOWN({pid})"


_REDACT_RES = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xoxb-[A-Za-z0-9-]+"),
    re.compile(r"-----BEGIN[ -].*?PRIVATE KEY-----", flags=re.DOTALL),
    # Fallback coarse markers (demo).
    re.compile(r"BEGIN PRIVATE KEY"),
    re.compile(r"OPENSSH PRIVATE KEY"),
]


@dataclass(frozen=True, slots=True)
class SanitizePatch:
    patch_id: int
    params: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"patch_id": int(self.patch_id), "patch_name": patch_name(self.patch_id), "params": dict(self.params or {})}


def apply_patch_to_message(*, text: str, patch: SanitizePatch) -> str:
    pid = int(patch.patch_id)
    s = str(text or "")
    if pid == PATCH_NOOP:
        return s
    if pid == PATCH_REDACT:
        out = s
        for r in _REDACT_RES:
            out = r.sub("[REDACTED]", out)
        return out
    if pid == PATCH_CLAMP_LEN:
        max_chars = int((patch.params or {}).get("max_chars", 256))
        if max_chars < 16:
            max_chars = 16
        if max_chars > 4096:
            max_chars = 4096
        return s[:max_chars]
    # PATCH_REWRITE_DOMAIN_TO_PROXY is not a text transform; handled elsewhere.
    return s


def apply_patch_to_domain(*, domain: str, patch: SanitizePatch) -> str:
    pid = int(patch.patch_id)
    d = str(domain or "")
    if pid == PATCH_REWRITE_DOMAIN_TO_PROXY:
        return str((patch.params or {}).get("proxy_domain") or "proxy.example.com")
    return d

