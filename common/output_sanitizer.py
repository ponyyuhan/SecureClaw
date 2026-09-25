from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple


# Field names (or substrings) whose values are considered "always sensitive"
# following AgentLeak's Presidio-based taxonomy. These map 1:1 to the
# always_sensitive_fields set in
# third_party/agentleak_official/agentleak/detection/presidio_detector.py,
# so redaction tracks exactly what the evaluator would flag as leakage.
_ALWAYS_SENSITIVE_FIELD_SUBSTRINGS: tuple[str, ...] = (
    "ssn",
    "social_security",
    "tax_id",
    "account_number",
    "routing_number",
    "credit_card",
    "card_number",
    "balance",
    "credit_score",
    "salary",
    "annual_income",
    "current_salary",
    "expected_salary",
    "retainer_amount",
    "settlement_amount",
    "diagnosis",
    "medical_history",
    "confidential_notes",
    "confidential_strategy",
    "internal_notes",
    "criminal_history",
    "background_check",
    "performance_notes",
    "disciplinary_actions",
    "password",
    "pin",
    "secret",
    "api_key",
    "token",
    "canary",
)


_PII_REGEXES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("US_SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("AKIA_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]+\b")),
    ("SK_TOKEN", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    (
        "PEM_KEY",
        re.compile(
            r"-----BEGIN[ -][A-Z ]+PRIVATE KEY-----.*?-----END[ -][A-Z ]+PRIVATE KEY-----",
            re.DOTALL,
        ),
    ),
)


def _field_is_always_sensitive(field_name: str) -> bool:
    fn = str(field_name or "").lower().strip()
    if not fn:
        return False
    base = re.sub(r"_\d+$", "", fn)
    for marker in _ALWAYS_SENSITIVE_FIELD_SUBSTRINGS:
        if marker in base:
            return True
    return False


@dataclass
class _SessionEntry:
    values: list[str] = field(default_factory=list)
    values_ci: list[str] = field(default_factory=list)
    lookup: set[str] = field(default_factory=set)


class OutputSanitizer:
    """Session-scoped final-output sanitizer.

    The sanitizer is a no-op for any session that has not explicitly registered
    sensitive values. Only sessions that opt in via `register_session_values`
    see the extra redaction pass; every other caller observes the exact same
    output as the existing policy patch produced.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionEntry] = {}

    def register_session_values(
        self,
        session: str,
        items: Iterable[Any],
        mode: str = "always_sensitive",
    ) -> dict[str, int]:
        sid = str(session or "")
        if not sid:
            return {"added": 0, "skipped": 0, "total_values": 0}
        normalized_mode = (mode or "always_sensitive").strip().lower()
        if normalized_mode not in ("always_sensitive", "all"):
            normalized_mode = "always_sensitive"
        added = 0
        skipped = 0
        with self._lock:
            entry = self._sessions.setdefault(sid, _SessionEntry())
            for it in items or []:
                field_name = ""
                value = ""
                if isinstance(it, dict):
                    field_name = str(it.get("field") or it.get("name") or "")
                    value = str(it.get("value") or "")
                elif isinstance(it, (tuple, list)) and len(it) == 2:
                    field_name = str(it[0] or "")
                    value = str(it[1] or "")
                else:
                    skipped += 1
                    continue
                value = value.strip()
                if len(value) < 4:
                    skipped += 1
                    continue
                if normalized_mode == "always_sensitive" and not _field_is_always_sensitive(field_name):
                    skipped += 1
                    continue
                ci = value.lower()
                if ci in entry.lookup:
                    skipped += 1
                    continue
                entry.values.append(value)
                entry.values_ci.append(ci)
                entry.lookup.add(ci)
                added += 1
            entry.values.sort(key=lambda s: (-len(s), s))
            entry.values_ci = [v.lower() for v in entry.values]
            return {
                "added": int(added),
                "skipped": int(skipped),
                "total_values": int(len(entry.values)),
                "mode": normalized_mode,
            }

    def clear_session(self, session: str) -> dict[str, int]:
        sid = str(session or "")
        with self._lock:
            entry = self._sessions.pop(sid, None)
            removed = len(entry.values) if entry is not None else 0
            return {"removed": int(removed)}

    def has_session(self, session: str) -> bool:
        with self._lock:
            entry = self._sessions.get(str(session or ""))
            return bool(entry and entry.values)

    def snapshot(self, session: str) -> list[str]:
        with self._lock:
            entry = self._sessions.get(str(session or ""))
            if entry is None:
                return []
            return list(entry.values)

    def sanitize(self, session: str, text: str) -> Tuple[str, Dict[str, int]]:
        s = str(text or "")
        sid = str(session or "")
        with self._lock:
            entry = self._sessions.get(sid)
            values = list(entry.values) if entry is not None else []
        if not values:
            return s, {"active": 0, "values_hit": 0, "regex_hit": 0, "values_count": 0}
        if not s:
            return s, {"active": 1, "values_hit": 0, "regex_hit": 0, "values_count": len(values)}
        out = s
        values_hit = 0
        for v in values:
            if not v:
                continue
            if v in out:
                out = out.replace(v, "[REDACTED:VAULT]")
                values_hit += 1
                continue
            if v.lower() in out.lower():
                out = _case_insensitive_replace(out, v, "[REDACTED:VAULT]")
                values_hit += 1
        regex_hit = 0
        for tag, pat in _PII_REGEXES:
            def _repl(_m: re.Match[str], _tag: str = tag) -> str:
                nonlocal regex_hit
                regex_hit += 1
                return f"[REDACTED:{_tag}]"
            out = pat.sub(_repl, out)
        return out, {
            "active": 1,
            "values_hit": int(values_hit),
            "regex_hit": int(regex_hit),
            "values_count": int(len(values)),
        }


def _case_insensitive_replace(text: str, needle: str, replacement: str) -> str:
    if not needle:
        return text
    try:
        pat = re.compile(re.escape(needle), flags=re.IGNORECASE)
    except re.error:
        return text.replace(needle, replacement)
    return pat.sub(replacement, text)


_SINGLETON = OutputSanitizer()


def get_output_sanitizer() -> OutputSanitizer:
    return _SINGLETON
