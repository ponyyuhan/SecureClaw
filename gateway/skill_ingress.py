from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Set, Tuple
from urllib.parse import urlparse


def _normalize_defanged(s: str) -> str:
    # Normalize common "defanged" IOC notations used in threat reports.
    out = str(s or "")
    out = out.replace("hxxps://", "https://").replace("hxxp://", "http://")
    out = out.replace("hxxps", "https").replace("hxxp", "http")
    out = out.replace("[:]", ":").replace("[.]", ".")
    out = out.replace("(.)", ".")
    return out


_URL_RE = re.compile(r"(https?://[^\s)>\"]+)", flags=re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?:(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?",
    flags=re.IGNORECASE,
)

# High-risk "install semantics" markers often used by malicious skill packages.
_EXEC_MARKER_RES = [
    re.compile(r"\bcurl\b", flags=re.IGNORECASE),
    re.compile(r"\bwget\b", flags=re.IGNORECASE),
    re.compile(r"\bpowershell\b", flags=re.IGNORECASE),
    re.compile(r"\binvoke-expression\b", flags=re.IGNORECASE),
    re.compile(r"\bchmod\s*\+x\b", flags=re.IGNORECASE),
    re.compile(r"\b(base64)\b", flags=re.IGNORECASE),
    re.compile(r"\|\s*(bash|sh)\b", flags=re.IGNORECASE),
]

_BASE64_LONG_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")

_PIPE_BASH_RE = re.compile(r"\|\s*bash\b", flags=re.IGNORECASE)
_PIPE_SH_RE = re.compile(r"\|\s*sh\b", flags=re.IGNORECASE)
_CURL_RE = re.compile(r"\bcurl\b", flags=re.IGNORECASE)
_WGET_RE = re.compile(r"\bwget\b", flags=re.IGNORECASE)
_BASE64_DECODE_RE = re.compile(r"\bbase64\b[^\n]{0,200}-\s*d\b", flags=re.IGNORECASE)
_CHMOD_X_RE = re.compile(r"\bchmod\s*\+\s*x\b", flags=re.IGNORECASE)
_POWERSHELL_RE = re.compile(r"\bpowershell\b", flags=re.IGNORECASE)
_IEX_RE = re.compile(r"\binvoke-expression\b", flags=re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SkillIngressFeatures:
    domains: List[str]
    has_exec_marker: bool
    has_base64_obf: bool


def _extract_urls(text: str) -> List[str]:
    t = _normalize_defanged(text)
    return [m.group(1) for m in _URL_RE.finditer(t)]


def _domain_from_url(u: str) -> str:
    try:
        p = urlparse(u)
    except Exception:
        return ""
    host = (p.hostname or "").strip().lower()
    return host


def _extract_domains_from_text(text: str) -> List[str]:
    t = _normalize_defanged(text).replace("\u200b", "")  # strip zero-width spaces if present
    out: Set[str] = set()

    # URLs first (most accurate).
    for u in _extract_urls(t):
        d = _domain_from_url(u)
        if d:
            out.add(d)

    # Also catch bare domains / IPs in text (including defanged variants).
    for m in _DOMAIN_RE.finditer(t):
        raw = (m.group(0) or "").strip().lower()
        raw = raw.strip(").,;\"'<>[]{}")
        # drop port if present
        host = raw.split(":", 1)[0]
        if host:
            out.add(host)
    return sorted(out)


def extract_skill_ingress_features(*, text: str, max_domains: int = 16) -> SkillIngressFeatures:
    s = str(text or "")
    domains = _extract_domains_from_text(s)
    if max_domains > 0:
        domains = domains[: int(max_domains)]

    has_exec = any(r.search(s) is not None for r in _EXEC_MARKER_RES)
    has_b64 = ("base64" in s.lower()) or (_BASE64_LONG_RE.search(s) is not None)
    return SkillIngressFeatures(domains=domains, has_exec_marker=bool(has_exec), has_base64_obf=bool(has_b64))

def extract_install_tokens(*, text: str, max_tokens: int = 16) -> List[str]:
    """Extract canonicalized "install semantics" tokens from SKILL.md.

    These tokens are used for PIR membership against the `banned_install_tokens` DB.
    We keep the token set small and structured to avoid noisy 4-gram collisions.
    """
    s = _normalize_defanged(str(text or ""))
    out: Set[str] = set()

    has_curl = _CURL_RE.search(s) is not None
    has_wget = _WGET_RE.search(s) is not None
    has_bash = _PIPE_BASH_RE.search(s) is not None
    has_sh = _PIPE_SH_RE.search(s) is not None

    if has_curl and has_bash:
        out.add("curl|bash")
    if has_wget and has_sh:
        out.add("wget|sh")

    if has_bash:
        out.add("|bash")
    if has_sh:
        out.add("|sh")

    if _BASE64_DECODE_RE.search(s) is not None:
        out.add("base64 -d")
    if _CHMOD_X_RE.search(s) is not None:
        out.add("chmod +x")
    if _POWERSHELL_RE.search(s) is not None:
        out.add("powershell")
    if _IEX_RE.search(s) is not None:
        out.add("invoke-expression")

    toks = sorted(out)
    if max_tokens < 1:
        max_tokens = 1
    if max_tokens > 64:
        max_tokens = 64
    return toks[: int(max_tokens)]


def sanitize_skill_markdown(*, text: str, redact_links: bool = True, redact_code_blocks: bool = True, max_chars: int = 2000) -> str:
    """Produce a safe-to-display summary of SKILL.md for humans/agents.

    This is intentionally conservative: it removes executable-looking guidance and makes links inert.
    """
    s = str(text or "")
    if redact_code_blocks:
        # Remove fenced code blocks (```...```) entirely.
        s = re.sub(r"```.*?```", "```[REDACTED CODE BLOCK]```", s, flags=re.DOTALL)
        # Remove indented shell blocks (best-effort).
        s = re.sub(r"(?m)^(?:\\s{4}.*\\n)+", "    [REDACTED INDENTED BLOCK]\n", s)

    # Redact obvious download-and-execute chains.
    s = re.sub(r"(?i)\\bcurl\\b[^\\n]{0,200}\\|[^\\n]{0,80}\\b(bash|sh)\\b", "[REDACTED: curl|sh]", s)
    s = re.sub(r"(?i)\\bwget\\b[^\\n]{0,200}\\|[^\\n]{0,80}\\b(bash|sh)\\b", "[REDACTED: wget|sh]", s)
    s = re.sub(r"(?i)\\bbase64\\b[^\\n]{0,200}", "[REDACTED: base64 decode]", s)
    s = re.sub(r"(?i)\\bpowershell\\b[^\\n]{0,200}", "[REDACTED: powershell]", s)

    if redact_links:
        s = re.sub(r"(?i)https?://[^\\s)>\"]+", "[REDACTED URL]", s)
        # Defanged IOCs (hxxp) should also be redacted in display.
        s = re.sub(r"(?i)hxxps?://[^\\s)>\"]+", "[REDACTED URL]", s)

    if max_chars < 256:
        max_chars = 256
    if max_chars > 20000:
        max_chars = 20000
    return s[: int(max_chars)]
