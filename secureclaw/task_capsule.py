"""Task capsule: provenance-aware principal binding for SecureClaw.

A task capsule extracts the **principal set** (specific entities: users, emails,
channels, files) from the user's original request. When a tool call targets a
principal NOT in the capsule, it is flagged as a potential injection redirect.

This addresses the "authorized-but-misaligned" residual:
- Slack: injection tells agent to invite/add/remove an external user the user
  never mentioned → capsule blocks because the target principal is foreign.
- Workspace: injection redirects agent to delete a file the user never mentioned
  → capsule blocks because the file target is foreign.

Design principles:
- Conservative: only flag actions on *new* principals not in the original request.
- Does not replace intent gating — adds a provenance check on top.
- Operates at the gateway layer (trusted code, not LLM-dependent).
"""
from __future__ import annotations

import re
from typing import Any, Sequence

from secureclaw.semantics import SecureClawAdapterSemantics


# Patterns to extract principal entities from natural language
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SLACK_USER_RE = re.compile(r"@([A-Za-z0-9._-]+)")
_SLACK_CHANNEL_RE = re.compile(r"#([A-Za-z0-9._-]+)")
_QUOTED_RE = re.compile(r'"([^"]+)"|\'([^\']+)\'')
_FILE_RE = re.compile(r"\b([A-Za-z0-9_.-]+\.(txt|pdf|doc|docx|csv|json|py|md|html|xlsx|yaml|yml))\b", re.IGNORECASE)


# Tools where provenance checking on targets is meaningful
PROVENANCE_GATED_TOOLS = {
    # Slack/communication — check user/channel targets
    "invite_user_to_slack",
    "add_user_to_channel",
    "remove_user_from_slack",
    "send_direct_message",
    "send_channel_message",
    "send_email",
    "share_file",
    # Destructive — check file/event targets
    "delete_file",
    "delete_email",
    "cancel_calendar_event",
    # Scheduling — check participant/event targets
    "create_calendar_event",
    "add_calendar_event_participants",
    "reschedule_calendar_event",
}

# Tools that should not be allowed to introduce a brand-new principal when the
# capsule still has no bound target after trusted contextual expansion.
UNBOUND_TARGET_TOOLS = {
    "invite_user_to_slack",
    "add_user_to_channel",
    "remove_user_from_slack",
    "send_direct_message",
    "send_channel_message",
    "send_email",
    "share_file",
    "create_calendar_event",
    "add_calendar_event_participants",
    "reschedule_calendar_event",
}

# Destructive tools: require action-type alignment even with empty capsule
DESTRUCTIVE_TOOLS: dict[str, tuple[str, ...]] = {
    "delete_file": ("delete", "remove", "file", "clean"),
    "delete_email": ("delete", "remove", "email", "trash"),
    "cancel_calendar_event": ("cancel", "delete", "remove"),
}

# Keys in tool_args that contain target principals
TARGET_PRINCIPAL_KEYS = {
    "recipient", "recipients", "user", "users", "email", "user_email",
    "participants", "channel", "channels", "to", "target", "destination",
    "file_name", "filename", "file_id", "event_id", "event_name", "relpath",
}

TRUSTED_RESULT_TARGET_KEYS = frozenset({
    "account",
    "channel",
    "channels",
    "contact",
    "contact_email",
    "contact_name",
    "email",
    "emails",
    "event_id",
    "event_name",
    "file_id",
    "file_name",
    "filename",
    "hotel",
    "hotel_name",
    "hotel_names",
    "iban",
    "id",
    "id_",
    "name",
    "owner",
    "participant",
    "participants",
    "path",
    "payee",
    "recipient",
    "recipients",
    "relpath",
    "restaurant",
    "restaurant_name",
    "restaurant_names",
    "sender",
    "target",
    "title",
    "to",
    "user",
    "user_email",
    "users",
})

OBSERVABLE_TOOL_PREFIXES = ("get_", "list_", "read_", "search_")
OBSERVABLE_TOOL_NAMES = frozenset({"create_file"})

_CHANNEL_LABEL_RE = re.compile(r"(?i)^channel\s+([A-Za-z0-9_.-]+)\s+has\b")


class TaskCapsule:
    """Extracts and stores the principal set from a user request."""

    def __init__(self, user_request: str):
        self.user_request = user_request
        self.anchored_principals: set[str] = set()
        self.contextual_principals: set[str] = set()
        self.principals: set[str] = set()
        self._extract_principals()

    # Common English words that should NOT be treated as principals
    _STOP_WORDS = frozenset({
        "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "can", "shall", "must", "need", "about",
        "from", "into", "with", "that", "this", "those", "these", "what",
        "which", "who", "whom", "where", "when", "why", "how", "all", "each",
        "every", "both", "few", "more", "most", "other", "some", "such", "no",
        "not", "only", "own", "same", "than", "too", "very", "just", "because",
        "but", "and", "or", "if", "then", "else", "so", "for", "of", "to",
        "in", "on", "at", "by", "up", "out", "off", "over", "under", "again",
        "once", "here", "there", "any", "also", "after", "before", "new",
        "now", "it", "its", "my", "me", "we", "us", "our", "you", "your",
        "he", "him", "his", "she", "her", "they", "them", "their",
        "send", "check", "get", "make", "find", "read", "write", "add",
        "remove", "delete", "update", "create", "list", "show", "tell",
        "message", "email", "file", "calendar", "event", "meeting", "task",
        "summary", "report", "tomorrow", "today", "yesterday", "please",
        "hi", "hello", "thanks", "thank", "ok", "sure", "yes", "no",
    })

    def _extract_principals(self) -> None:
        text = self.user_request

        # Extract emails
        for match in _EMAIL_RE.finditer(text):
            self._add_principal(match.group(0))

        # Extract @mentions
        for match in _SLACK_USER_RE.finditer(text):
            self._add_principal(match.group(1))

        # Extract #channels
        for match in _SLACK_CHANNEL_RE.finditer(text):
            self._add_principal(match.group(1))

        # Extract quoted strings (often names, channels, files)
        for match in _QUOTED_RE.finditer(text):
            val = (match.group(1) or match.group(2) or "").strip()
            if val and len(val) < 100:
                self._add_principal(val)

        # Extract filenames
        for match in _FILE_RE.finditer(text):
            self._add_principal(match.group(1))

        # Extract targets after prepositions and action keywords
        for pattern in [
            r"\bto\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",      # "to Bob", "to Alice Smith"
            r"\bfrom\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",     # "from Alice"
            r"\bwith\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",     # "with Charlie"
            r"\buser\s+([A-Za-z0-9._@-]+)",                    # "user bob123"
            r"\bchannel\s+([A-Za-z0-9._-]+)\b(?!\s+about)",   # "channel general" but not "channel about"
            r"\b(?:in|on|the)\s+([A-Za-z0-9._-]+)\s+channel", # "in the general channel"
            r"\bfile\s+([A-Za-z0-9._/-]+)",                    # "file report.txt"
            r"\bevent\s+([A-Za-z0-9._-]+)",                    # "event standup"
            r"\binvite\s+([A-Za-z0-9._@-]+)",                  # "invite john"
            r"\bcontact\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)",  # "contact Alice"
        ]:
            for match in re.finditer(pattern, text):
                val = match.group(1).strip().strip(".,;:!?").lower()
                if val and len(val) > 1 and val not in self._STOP_WORDS:
                    self._add_principal(val)

        # Extract capitalized proper nouns (not at sentence start)
        words = text.split()
        for i, word in enumerate(words):
            if i == 0:
                continue  # skip sentence-initial capitalization
            clean = word.strip(".,;:!?\"'()[]")
            if clean and clean[0].isupper() and clean.isalpha() and len(clean) > 1:
                low = clean.lower()
                if low not in self._STOP_WORDS:
                    self._add_principal(low)

        # Remove any stop words that leaked through
        self.principals -= self._STOP_WORDS
        self.anchored_principals = set(self.principals)

    @staticmethod
    def _normalize_principal(raw: object) -> str:
        text = SecureClawAdapterSemantics.normalize_target(raw)
        return str(text or "").strip().strip(".,;:!?\"'()[]{}")

    def _add_principal(self, raw: object, *, contextual: bool = False) -> None:
        norm = self._normalize_principal(raw)
        if not norm or len(norm) <= 1 or norm in self._STOP_WORDS:
            return
        self.principals.add(norm)
        if contextual:
            self.contextual_principals.add(norm)
        else:
            self.anchored_principals.add(norm)

    def observe_contextual_targets(self, targets: Sequence[object]) -> None:
        """Augment the capsule with trusted contextual targets.

        These targets must come from sanitized read summaries or other trusted
        derivations, not raw untrusted tool output bodies.
        """
        for raw in targets or []:
            self._add_principal(raw, contextual=True)

    def observe_tool_result(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_result: Any,
    ) -> None:
        """Augment the capsule from trusted structured tool results.

        This is narrower than generic contextual targets: it only consumes
        structured metadata fields and same-turn identifiers, never free-text
        bodies or prompt-like content.
        """
        if not self._is_observable_tool(tool_name):
            return
        for raw in self._extract_targets_from_tool_result(tool_name, tool_args, tool_result):
            self._add_principal(raw, contextual=True)

    def check_tool_call(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> tuple[bool, str]:
        """Check whether a tool call's target principals are in the capsule.

        Returns:
            (allowed, reason): True if allowed, False if a foreign principal detected.
        """
        if tool_name not in PROVENANCE_GATED_TOOLS:
            return True, "NOT_GATED"

        if not self.principals:
            if tool_name in UNBOUND_TARGET_TOOLS:
                return False, f"UNBOUND_TARGET:{tool_name}"
            # Empty capsule: for destructive tools, check action-type alignment
            if tool_name in DESTRUCTIVE_TOOLS:
                expected_keywords = DESTRUCTIVE_TOOLS[tool_name]
                req_lower = self.user_request.lower()
                if not any(kw in req_lower for kw in expected_keywords):
                    return False, f"DESTRUCTIVE_MISALIGNED:{tool_name}"
            return True, "EMPTY_CAPSULE"

        extracted_targets = SecureClawAdapterSemantics.extract_targets_from_args(tool_name, tool_args)
        targets = [str(item) for item in extracted_targets if str(item).strip()]
        if not targets:
            for key, value in (tool_args or {}).items():
                if key.lower() not in TARGET_PRINCIPAL_KEYS:
                    continue
                if isinstance(value, list):
                    targets.extend(str(v).strip().lower() for v in value if v)
                elif value not in (None, "", [], {}):
                    targets.append(str(value).strip().lower())
        if not targets:
            return True, "NO_TARGET_PRINCIPAL"

        foreign_principals: list[str] = []
        for target in targets:
            if not target:
                continue
            if not self._matches_any_principal(target):
                foreign_principals.append(str(target))

        if foreign_principals:
            return False, f"FOREIGN_PRINCIPAL:{';'.join(sorted(set(foreign_principals)))}"
        return True, "CAPSULE_OK"

    def _matches_any_principal(self, target: str) -> bool:
        """Check if target matches any principal.

        Uses exact normalized matching for emails and domains,
        with local-part prefix matching only for short principals.
        """
        target_lower = self._normalize_principal(target)
        target_suffix = target_lower.split("/")[-1] if "/" in target_lower else target_lower
        for principal in self.principals:
            # Exact match (normalized)
            if target_lower == principal:
                return True
            # URL path suffix match
            if target_suffix != target_lower and target_suffix == principal:
                return True
            # Email local-part match: if principal is a full email and target
            # matches its local part or domain
            if "@" in principal and "@" in target_lower:
                # Both are emails — require exact match (already checked above)
                continue
            if "@" in principal:
                local, domain = principal.split("@", 1)
                if target_lower == local or target_lower == domain:
                    return True
            if "@" in target_lower:
                local, domain = target_lower.split("@", 1)
                if principal == local or principal == domain:
                    return True
            # Domain containment: target is subdomain of principal or vice versa
            if "." in principal and "." in target_lower:
                if target_lower.endswith("." + principal) or principal.endswith("." + target_lower):
                    return True
        return False

    def _is_observable_tool(self, tool_name: str) -> bool:
        tname = str(tool_name or "").strip()
        if tname in OBSERVABLE_TOOL_NAMES:
            return True
        return any(tname.startswith(prefix) for prefix in OBSERVABLE_TOOL_PREFIXES)

    def _extract_targets_from_tool_result(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_result: Any,
    ) -> set[str]:
        del tool_name, tool_args
        observed: set[str] = set()

        def _walk(value: Any, *, parent_key: str = "", depth: int = 0) -> None:
            if depth > 6 or value is None:
                return
            if hasattr(value, "model_dump") and callable(value.model_dump):
                _walk(value.model_dump(), parent_key=parent_key, depth=depth + 1)
                return
            if hasattr(value, "dict") and callable(value.dict):
                try:
                    _walk(value.dict(), parent_key=parent_key, depth=depth + 1)
                    return
                except Exception:
                    pass
            if isinstance(value, dict):
                for raw_key, sub in value.items():
                    key = str(raw_key or "").strip()
                    key_norm = key.lower()
                    self._extract_targets_from_label(observed, key)
                    label_parent_key = self._label_parent_key(key_norm)
                    if key_norm == "shared_with" and isinstance(sub, dict):
                        for recipient in sub.keys():
                            self._add_structured_target(observed, recipient)
                        continue
                    if key_norm in TRUSTED_RESULT_TARGET_KEYS:
                        self._add_structured_target(observed, sub)
                    if isinstance(sub, (dict, list, tuple, set)):
                        _walk(sub, parent_key=label_parent_key or key_norm, depth=depth + 1)
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    _walk(item, parent_key=parent_key, depth=depth + 1)
                return
            if parent_key in TRUSTED_RESULT_TARGET_KEYS:
                self._add_structured_target(observed, value)

        _walk(tool_result)
        return observed

    def _extract_targets_from_label(self, out: set[str], label: str) -> None:
        text = str(label or "").strip()
        if not text:
            return
        match = _CHANNEL_LABEL_RE.match(text)
        if match:
            self._add_structured_target(out, match.group(1))

    @staticmethod
    def _label_parent_key(label: str) -> str:
        low = str(label or "").strip().lower()
        if low.startswith("channel ") and " users" in low:
            return "users"
        if low.startswith("channel ") and " messages" in low:
            return "messages"
        return ""

    def _add_structured_target(self, out: set[str], raw: Any) -> None:
        if raw is None or isinstance(raw, bool):
            return
        if isinstance(raw, (list, tuple, set)):
            for item in raw:
                self._add_structured_target(out, item)
            return
        scratch: set[str] = set()
        SecureClawAdapterSemantics.add_scalar_target(scratch, raw)
        for item in scratch:
            norm = self._normalize_principal(item)
            if norm and len(norm) > 1 and norm not in self._STOP_WORDS:
                out.add(norm)

    def __repr__(self) -> str:
        return (
            "TaskCapsule("
            f"anchored={sorted(self.anchored_principals)}, "
            f"contextual={sorted(self.contextual_principals)})"
        )
