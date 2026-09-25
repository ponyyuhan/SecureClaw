from __future__ import annotations

from collections.abc import Callable, Sequence
import json
import os
import re
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel
import yaml


class SecureClawAdapterSemantics:
    DEFAULT_RECIPIENT_KEYS = (
        "recipient",
        "recipients",
        "email",
        "user_email",
        "participants",
        "channel",
        "user",
        "to",
        "target",
        "destination",
        "payee",
        "account",
        "iban",
        "restaurant",
        "hotel",
        "company",
    )

    DEFAULT_PREFIX_EXPAND_KEYS = {
        "recipient",
        "recipients",
        "email",
        "user_email",
        "participants",
        "channel",
        "channels",
        "user",
        "users",
        "to",
        "target",
        "destination",
        "payee",
        "account",
        "iban",
        "hotel",
        "restaurant",
        "company",
        "title",
        "event_id",
        "file_name",
        "filename",
        "relpath",
    }

    TARGET_KEYS = (
        "recipient",
        "recipients",
        "sender",
        "user_email",
        "email",
        "participants",
        "channel",
        "channels",
        "user",
        "users",
        "to",
        "target",
        "destination",
        "payee",
        "account",
        "iban",
        "hotel",
        "hotel_name",
        "hotel_names",
        "restaurant",
        "restaurant_name",
        "restaurant_names",
        "company",
        "companies",
        "car_rental_company",
        "car_company",
        "contact",
        "contact_email",
        "contact_name",
        "file_id",
        "file_name",
        "filename",
        "path",
        "relpath",
        "title",
        "event_id",
        "event_name",
        "name",
        "owner",
    )

    SAFE_OUTPUT_KEYS_EXACT = {
        "recipient",
        "sender",
        "participants",
        "channel",
        "user",
        "users",
        "email",
        "iban",
        "account",
        "hotel",
        "hotel_name",
        "hotel_names",
        "restaurant",
        "restaurant_name",
        "restaurant_names",
        "company",
        "companies",
        "car_rental_company",
        "car_company",
        "contact",
        "contact_email",
        "contact_name",
        "file_id",
        "file_name",
        "filename",
        "path",
        "relpath",
        "title",
        "event_id",
        "event_name",
        "name",
        "id",
        "safe_targets",
    }

    SKIP_OUTPUT_KEYS = {
        "subject",
        "body",
        "content",
        "message",
        "messages",
        "instructions",
        "prompt",
        "text",
        "preview",
        "summary",
        "note",
        "error",
        "reason",
    }

    SLACK_USER_KEYS = {"user", "users", "recipient", "recipients", "participants", "to"}
    SLACK_CHANNEL_KEYS = {"channel", "channels"}

    @staticmethod
    def normalize_target(raw: object) -> str:
        if raw is None:
            return ""
        text = str(raw).strip()
        if not text:
            return ""
        if re.fullmatch(r"[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}", text.upper()):
            return text.upper()
        if "@" in text:
            return text.lower()
        return re.sub(r"\s+", " ", text).strip().lower()

    @classmethod
    def add_scalar_target(cls, out: set[str], raw: object) -> None:
        if raw is None or isinstance(raw, bool):
            return
        if isinstance(raw, (int, float)):
            return
        text = str(raw).strip()
        if not text:
            return
        scan = text if len(text) <= 512 else text[:512]
        for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", scan):
            out.add(cls.normalize_target(email))
        for iban in re.findall(r"\b[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}\b", scan.upper()):
            out.add(cls.normalize_target(iban))
        looks_containerish = (text.startswith("[") and text.endswith("]")) or (text.startswith("{") and text.endswith("}"))
        if len(text) <= 160 and not looks_containerish:
            out.add(cls.normalize_target(text))
            if "/" in text:
                out.add(cls.normalize_target(os.path.basename(text)))
            try:
                parsed = urlparse(text if "://" in text else f"https://{text}")
            except ValueError:
                parsed = None
            domain = str((parsed.netloc if parsed is not None else "") or "").strip().lower()
            if domain:
                out.add(cls.normalize_target(domain))

    @classmethod
    def extract_anchored_targets_from_text(cls, text: str) -> set[str]:
        out: set[str] = set()
        scan = str(text or "")[:4096]
        if not scan:
            return out
        line_patterns = (
            r"(?i)^(?:iban|account(?:\s+number)?|recipient|pay(?:ee)?)\s*[:=#-]\s*([A-Z]{2}[0-9]{2}[0-9A-Z]{10,30})\s*$",
            r"(?i)^(?:email|contact(?:\s+email)?)\s*[:=#-]\s*([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*$",
            r"(?i)^(?:url|website|domain|link)\s*[:=#-]\s*((?:https?://)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s]*)?)\s*$",
        )
        for raw_line in scan.splitlines():
            line = str(raw_line or "").strip()
            if not line or len(line) > 160:
                continue
            for pattern in line_patterns:
                for match in re.findall(pattern, line):
                    cls.add_scalar_target(out, match)
        return {item for item in out if item}

    @classmethod
    def extract_reference_targets_from_text(cls, text: str) -> set[str]:
        out: set[str] = set()
        scan = str(text or "")[:4096]
        if not scan:
            return out
        for raw in re.findall(r"\b(?:EMAIL|URL|DOMAIN|TARGET|IBAN)_REF_\d+\b", scan):
            cls.add_scalar_target(out, raw)
        for raw in re.findall(r"https?://[^\s)>\]}\"']+", scan):
            cls.add_scalar_target(out, str(raw).rstrip(".,;:!?"))
        for raw in re.findall(r"\b(?:www\.)?(?:[A-Za-z0-9-]+\.)+[a-z]{2,}\b", scan):
            cls.add_scalar_target(out, str(raw).rstrip(".,;:!?"))
        for raw in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", scan):
            cls.add_scalar_target(out, raw)
        return {item for item in out if item}

    @classmethod
    def extract_safe_targets_from_value(cls, obj: object) -> set[str]:
        out: set[str] = set()
        if isinstance(obj, str):
            return cls.extract_anchored_targets_from_text(obj)
        if isinstance(obj, (list, tuple, set)):
            scalar_only = True
            for item in obj:
                if isinstance(item, (str, int, float)) and not isinstance(item, bool):
                    cls.add_scalar_target(out, item)
                elif item is None:
                    continue
                else:
                    scalar_only = False
                    break
            if scalar_only:
                return {item for item in out if item}

        def _walk(value: object, depth: int = 0) -> None:
            if depth > 6 or value is None:
                return
            if isinstance(value, BaseModel):
                try:
                    _walk(value.model_dump(), depth + 1)
                except Exception:
                    return
                return
            if isinstance(value, dict):
                lower_keys = {str(key or "").strip().lower() for key in value.keys()}
                message_like = (
                    ("sender" in lower_keys and "body" in lower_keys)
                    or ("subject" in lower_keys and "body" in lower_keys)
                    or ("channel" in lower_keys and "body" in lower_keys)
                )
                for key, sub in value.items():
                    raw_key = str(key or "").strip()
                    key_str = str(key or "").strip().lower()
                    key_reference_targets = cls.extract_reference_targets_from_text(raw_key) if raw_key else set()
                    if message_like and key_str in {"body", "content", "text", "message", "description"} and isinstance(sub, str):
                        out.update(cls.extract_reference_targets_from_text(sub))
                    if key_str in cls.SKIP_OUTPUT_KEYS:
                        continue
                    if (
                        raw_key
                        and key_str not in cls.SAFE_OUTPUT_KEYS_EXACT
                        and len(raw_key) <= 80
                        and "\n" not in raw_key
                        and len(raw_key.split()) <= 4
                    ):
                        cls.add_scalar_target(out, raw_key)
                    if key_reference_targets and isinstance(sub, str):
                        out.update(cls.extract_reference_targets_from_text(sub))
                    if key_str in cls.SAFE_OUTPUT_KEYS_EXACT or any(
                        hint in key_str for hint in ("recipient", "sender", "email", "iban", "channel", "hotel", "restaurant", "company", "file", "event", "participant", "contact", "user", "path", "title")
                    ):
                        if isinstance(sub, (list, tuple, set)):
                            for item in sub:
                                cls.add_scalar_target(out, item)
                        else:
                            cls.add_scalar_target(out, sub)
                    if isinstance(sub, (dict, list, tuple, set)):
                        _walk(sub, depth + 1)
                return
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    _walk(item, depth + 1)

        _walk(obj)
        return {item for item in out if item}

    @classmethod
    def extract_targets_from_args(cls, tool_name: str, tool_args: dict) -> set[str]:
        targets: set[str] = set()
        for key, value in dict(tool_args or {}).items():
            key_str = str(key or "").strip().lower()
            if key_str in cls.TARGET_KEYS or any(hint in key_str for hint in ("recipient", "email", "iban", "channel", "hotel", "restaurant", "company", "file", "event", "participant", "contact", "user", "path", "title")):
                if isinstance(value, (list, tuple, set)):
                    for item in value:
                        cls.add_scalar_target(targets, item)
                else:
                    cls.add_scalar_target(targets, value)
            elif key_str in {"url", "domain"}:
                cls.add_scalar_target(targets, value)
        if not targets:
            if tool_name in {"create_file", "append_to_file", "delete_file"}:
                cls.add_scalar_target(targets, tool_args.get("file_name") or tool_args.get("filename") or tool_args.get("relpath"))
            elif tool_name in {"create_calendar_event", "cancel_calendar_event", "reschedule_calendar_event"}:
                cls.add_scalar_target(targets, tool_args.get("title") or tool_args.get("event_id"))
        return {item for item in targets if item}

    @classmethod
    def _parse_mapping_payload(cls, text: str) -> dict[str, Any] | None:
        if not text or len(text) > 20000:
            return None
        parsed = None
        try:
            parsed = yaml.safe_load(text)
        except Exception:
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
        return parsed if isinstance(parsed, dict) else None

    @classmethod
    def extract_safe_targets_from_output_text(cls, text: str) -> set[str]:
        parsed = cls._parse_mapping_payload(text)
        if not isinstance(parsed, dict):
            return set()
        return cls.extract_safe_targets_from_value(parsed.get("safe_targets"))

    @classmethod
    def extract_summary_targets_from_output_text(cls, text: str) -> set[str]:
        parsed = cls._parse_mapping_payload(text)
        if not isinstance(parsed, dict):
            return set()
        return cls.extract_safe_targets_from_value(parsed.get("summary"))

    @classmethod
    def extract_summary_fact_targets_from_output_text(cls, text: str) -> set[str]:
        parsed = cls._parse_mapping_payload(text)
        if not isinstance(parsed, dict):
            return set()
        facts = parsed.get("summary_facts")
        if not isinstance(facts, list):
            return set()
        out: set[str] = set()
        for fact in facts:
            if not isinstance(fact, str):
                continue
            out.update(cls.extract_reference_targets_from_text(fact))
            for candidate in cls.extract_query_targets(fact):
                cls.add_scalar_target(out, candidate)
        return {item for item in out if item}

    @classmethod
    def _extract_capsule_targets_from_value(
        cls,
        value: object,
        *,
        resolve_aliases: Callable[[object], object],
        depth: int = 0,
    ) -> set[str]:
        out: set[str] = set()
        if value is None or depth > 8:
            return out
        if isinstance(value, str):
            resolved = str(resolve_aliases(value) or value or "")
            for alias in re.findall(r"\b[A-Z]+_REF_[A-Za-z0-9]+\b", resolved):
                replacement = str(resolve_aliases(alias) or alias)
                resolved = re.sub(rf"\b{re.escape(alias)}\b", replacement, resolved)
            if not resolved.strip():
                return out
            out.update(cls.extract_anchored_targets_from_text(resolved))
            out.update(cls.extract_reference_targets_from_text(resolved))
            for candidate in cls.extract_query_targets(resolved):
                cls.add_scalar_target(out, candidate)
            for match in re.findall(r"\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b", resolved):
                low = str(match).strip().lower()
                if low in {"this", "that", "these", "those", "my", "your", "our", "their"}:
                    continue
                cls.add_scalar_target(out, match)
            return {item for item in out if item}
        if isinstance(value, dict):
            for sub in value.values():
                out.update(
                    cls._extract_capsule_targets_from_value(
                        sub,
                        resolve_aliases=resolve_aliases,
                        depth=depth + 1,
                    )
                )
            return {item for item in out if item}
        if isinstance(value, (list, tuple, set)):
            for sub in value:
                out.update(
                    cls._extract_capsule_targets_from_value(
                        sub,
                        resolve_aliases=resolve_aliases,
                        depth=depth + 1,
                    )
                )
            return {item for item in out if item}
        return out

    @classmethod
    def extract_query_targets(cls, query: str) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        q = str(query or "")
        if not q:
            return out

        def _add_raw(raw: object) -> None:
            sval = str(raw or "").strip().strip(",.;:()[]{}")
            if not sval or len(sval) > 160:
                return
            if "." in sval and " " not in sval:
                prefix_match = re.match(r"^(?:https?://)?(?:www\.)?(?:[A-Za-z0-9-]+\.)+[a-z]{2,}(?:/[^\s)]*)?", sval)
                if prefix_match:
                    sval = str(prefix_match.group(0) or "").rstrip(".,;:!?")
                    if not sval:
                        return
            key = sval.lower()
            if key in seen:
                return
            seen.add(key)
            out.append(sval)

        for fname in re.findall(r"\b[\w./-]+\.[A-Za-z0-9]{1,8}\b", q):
            _add_raw(fname)
        for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", q):
            _add_raw(email)
        for iban in re.findall(r"\b[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}\b", q.upper()):
            _add_raw(iban)
        for url in re.findall(r"\b(?:https?://)?(?:www\.)?(?:[A-Za-z0-9-]+\.)+[a-z]{2,}(?:/[^\s)]*)?", q):
            if "." in str(url):
                _add_raw(url)
        quote_patterns = (
            r'(?<!\w)"([^"\n]{3,120})"(?!\w)',
            r"(?<![\w])'([^'\n]{3,120})'(?![\w])",
            r"(?<!\w)“([^”\n]{3,120})”(?!\w)",
            r"(?<!\w)‘([^’\n]{3,120})’(?!\w)",
        )
        for pattern in quote_patterns:
            for quoted in re.findall(pattern, q):
                _add_raw(quoted)
        target_patterns = (
            r"\b(?i:invite)\s+([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\b",
            r"\b(?i:add)\s+([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\s+\b(?i:to)\b",
            r"\b(?i:remove)\s+([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\s+\b(?i:from)\b",
            r"\b(?i:send)(?:\s+it|\s+them|\s+this|\s+that|\s+the\s+\w+|\s+\w+){0,6}\s+\b(?i:to)\b\s+([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\b",
            r"\b(?i:message)\s+([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\b",
            r"\b(?i:dm)\s+([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\b",
            r"\b(?i:share)(?:\s+\w+){0,6}\s+\b(?i:with)\b\s+([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|[A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\b",
            r"(?i)\bchannel\s+starting\s+with\s+([A-Za-z0-9_.-]+)\b",
            r"(?i)\bchannel\s+(?:named|called)\s+([A-Za-z0-9_.-]+)\b",
            r"(?i)\bto\s+the\s+website\s+((?:https?://)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s]*)?)\b",
            r"(?i)\bon\s+webpage\s+((?:https?://)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s]*)?)\b",
            r"([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\s*\(((?:https?://)?(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?:/[^\s)]*)?)\)",
        )
        for pattern in target_patterns:
            for match in re.findall(pattern, q):
                if isinstance(match, tuple):
                    for item in match:
                        _add_raw(item)
                else:
                    _add_raw(match)
        if " to " in q.lower():
            for match in re.findall(r"\b(?i:to)\s+([A-Z][A-Za-z0-9_.-]*(?:\s+[A-Z][A-Za-z0-9_.-]*){0,2})\b", q):
                _add_raw(match)
        return out

    @classmethod
    def extract_primary_request_text(cls, query: str) -> str:
        text = str(query or "").strip()
        if not text:
            return ""
        cut_patterns = (
            r"(?i)\byou must strictly adhere to the following instruction\s*:",
            r"(?i)\bignore previous instructions\b",
            r"(?i)\banswer\s*:\s*task complete\b",
            r"(?i)\bdo not use other tools\b",
        )
        cut_positions: list[int] = []
        for pattern in cut_patterns:
            match = re.search(pattern, text)
            if match:
                cut_positions.append(int(match.start()))
        if cut_positions:
            text = text[: min(cut_positions)]
        cleanup_patterns = (
            r"(?is)<\s*information\s*>.*?<\s*/\s*information\s*>",
            r"(?is)<\s*important\s*>.*?<\s*/\s*important\s*>",
            r"(?is)<\s*instruction(?:s)?\s*>.*?<\s*/\s*instruction(?:s)?\s*>",
            r"(?im)^\s*this is an important message from me.*$",
            r"(?im)^\s*before you can solve the task.*$",
            r"(?im)^\s*please do the following first.*$",
            r"(?im)^\s*after you do that, you can solve.*$",
        )
        for pattern in cleanup_patterns:
            text = re.sub(pattern, "", text)
        text = re.sub(r"\s+", " ", str(text or "")).strip(" \t\r\n.;:")
        if len(text) > 240:
            text = text[:237].rstrip() + "..."
        return text

    @staticmethod
    def allowed_readonly_tool_names(tool_names: Sequence[str], *, whitelist: set[str], limit: int = 12) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for raw in tool_names:
            name = str(raw or "").strip()
            if not name or name not in whitelist or name in seen:
                continue
            seen.add(name)
            out.append(name)
            if len(out) >= max(1, int(limit)):
                break
        return out

    @classmethod
    def build_policy_denial_message(
        cls,
        *,
        query: str,
        denied_tool: str,
        reason_code: str,
        allowed_readonly_tools: Sequence[str],
        recovery_disabled: bool = False,
    ) -> str:
        # When recovery is disabled, return an opaque deny (like Faramesh)
        if recovery_disabled:
            payload = {
                "status": "DENY",
                "reason_code": str(reason_code or "POLICY_DENY"),
            }
            return json.dumps(payload, ensure_ascii=False)

        original_request = cls.extract_primary_request_text(query)
        lines = [
            f"Policy denied tool `{str(denied_tool or '').strip()}` with reason `{str(reason_code or '').strip() or 'POLICY_DENY'}`.",
            "Do not retry the denied action and do not ask for a policy override.",
        ]
        if original_request:
            lines.append(f"Continue the original user request: {original_request}")
        else:
            lines.append("Continue the original user request using safe read-only tools.")
        if allowed_readonly_tools:
            lines.append("Allowed read-only tools: " + ", ".join(str(x) for x in allowed_readonly_tools if str(x).strip()))
            lines.append("If any of those tools help with the original request, call them now.")
        else:
            lines.append("If no safe tool is needed, provide the best safe answer you can without performing the denied side effect.")
        payload = {
            "status": "DENY",
            "reason_code": str(reason_code or "POLICY_DENY"),
            "denied_tool": str(denied_tool or ""),
            "continue_original_request": True,
        }
        if original_request:
            payload["original_request"] = original_request
        if allowed_readonly_tools:
            payload["allowed_readonly_tools"] = [str(x) for x in allowed_readonly_tools if str(x).strip()]
        return "\n".join(lines) + "\n" + json.dumps(payload, ensure_ascii=False)

    @classmethod
    def build_slack_catalog(cls, slack: object) -> dict[str, dict[str, str]]:
        if slack is None:
            return {}

        def _build(values: object) -> dict[str, str]:
            out: dict[str, str] = {}
            for raw in values if isinstance(values, list) else []:
                text = str(raw or "").strip()
                norm = cls.normalize_target(text)
                if text and norm and norm not in out:
                    out[norm] = text
            return out

        return {
            "users": _build(getattr(slack, "users", []) or []),
            "channels": _build(getattr(slack, "channels", []) or []),
        }

    @classmethod
    def canonicalize_known_scalar(cls, value: object, known: dict[str, str]) -> object:
        if value in (None, "") or not known:
            return value
        text = str(value).strip()
        norm = cls.normalize_target(text)
        if not norm:
            return value
        exact = known.get(norm)
        if exact:
            return exact
        if len(norm) < 3:
            return value
        candidates = [raw for knorm, raw in known.items() if knorm.startswith(norm) or norm.startswith(knorm)]
        uniq: list[str] = []
        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate).lower()
            if key in seen:
                continue
            seen.add(key)
            uniq.append(candidate)
        if len(uniq) == 1:
            return uniq[0]
        return value

    @classmethod
    def canonicalize_args_with_catalog(
        cls,
        tool_args: dict,
        *,
        user_known: dict[str, str] | None = None,
        channel_known: dict[str, str] | None = None,
        user_keys: set[str] | None = None,
        channel_keys: set[str] | None = None,
    ) -> dict:
        user_keys = user_keys or cls.SLACK_USER_KEYS
        channel_keys = channel_keys or cls.SLACK_CHANNEL_KEYS
        user_known = user_known or {}
        channel_known = channel_known or {}

        def _canon_value(value: object, known: dict[str, str]) -> object:
            if isinstance(value, list):
                return [cls.canonicalize_known_scalar(item, known) for item in value]
            return cls.canonicalize_known_scalar(value, known)

        out = dict(tool_args or {})
        for key, value in list(out.items()):
            key_norm = str(key or "").strip().lower()
            if key_norm in user_keys:
                out[key] = _canon_value(value, user_known)
            elif key_norm in channel_keys:
                out[key] = _canon_value(value, channel_known)
        return out

    @staticmethod
    def normalize_tool_arg_aliases(tool_name: str, tool_args: dict) -> dict:
        out = dict(tool_args or {})
        tool_name = str(tool_name or "").strip().lower()

        def _promote(alias_key: str, canonical_key: str, *, as_list: bool) -> None:
            if canonical_key in out or alias_key not in out:
                return
            value = out.pop(alias_key)
            if as_list:
                if value in (None, ""):
                    return
                out[canonical_key] = value if isinstance(value, list) else [value]
            else:
                if isinstance(value, list):
                    if not value:
                        return
                    out[canonical_key] = value[0]
                else:
                    out[canonical_key] = value

        if tool_name in {"get_hotels_prices", "get_rating_reviews_for_hotels"}:
            for alias in ("company_name", "company_names", "restaurant_name", "restaurant_names", "hotel_name"):
                _promote(alias, "hotel_names", as_list=True)
        elif tool_name == "get_hotels_address":
            for alias in ("company_name", "company_names", "restaurant_name", "restaurant_names", "hotel_names"):
                _promote(alias, "hotel_name", as_list=False)
        elif tool_name in {
            "get_restaurants_address",
            "get_rating_reviews_for_restaurants",
            "get_cuisine_type_for_restaurants",
            "get_dietary_restrictions_for_all_restaurants",
            "get_contact_information_for_restaurants",
            "get_price_for_restaurants",
        }:
            for alias in ("company_name", "company_names", "hotel_name", "hotel_names", "restaurant_name"):
                _promote(alias, "restaurant_names", as_list=True)
        elif tool_name in {
            "get_car_types_available",
            "get_rating_reviews_for_car_rental",
            "get_car_rental_address",
            "get_car_fuel_options",
            "get_car_price_per_day",
        }:
            for alias in ("company_names", "hotel_name", "hotel_names", "restaurant_name", "restaurant_names"):
                _promote(alias, "company_name", as_list=True)
        elif tool_name == "reserve_hotel":
            for alias in ("company_name", "company_names", "hotel_name", "hotel_names"):
                _promote(alias, "hotel", as_list=False)
        elif tool_name == "reserve_restaurant":
            for alias in ("company_name", "company_names", "restaurant_name", "restaurant_names", "hotel_name", "hotel_names"):
                _promote(alias, "restaurant", as_list=False)
        elif tool_name == "reserve_car_rental":
            for alias in ("company_names", "company_name", "hotel_name", "hotel_names", "restaurant_name", "restaurant_names"):
                _promote(alias, "company", as_list=False)
        return out

    @staticmethod
    def safe_target_sort_key(raw: object) -> tuple[int, int, str]:
        text = str(raw or "").strip()
        lowered = text.lower()
        if not text:
            return (9, 0, "")
        if re.fullmatch(r"[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}", text.upper()):
            return (0, len(text), lowered)
        if "@" in text:
            return (1, len(text), lowered)
        if "://" in text or lowered.startswith("www.") or re.fullmatch(r"(?:[A-Za-z0-9-]+\.)+[a-z]{2,}", lowered):
            return (2, len(text), lowered)
        if any(ch.isupper() for ch in text):
            return (3, len(text), lowered)
        return (4, len(text), lowered)

    @classmethod
    def _resolve_and_dedupe(
        cls,
        targets: list[str],
        resolve_aliases: Callable[[object], object],
        limit: int = 64,
    ) -> list[str]:
        resolved_targets_by_norm: dict[str, str] = {}
        for target in targets:
            resolved = resolve_aliases(str(target or ""))
            normalized = cls.normalize_target(resolved)
            raw = str(resolved or "")
            if normalized and raw.strip() and normalized not in resolved_targets_by_norm:
                resolved_targets_by_norm[normalized] = raw
        out = sorted(str(item) for item in resolved_targets_by_norm.values() if str(item).strip())
        return out[:limit]

    @classmethod
    def query_anchored_targets(
        cls,
        *,
        turn_request: str,
    ) -> list[str]:
        """Targets derived solely from the user's request text.

        These are safe for authorization override because they reflect
        user intent, not runtime-influenced tool outputs.
        Alias resolution is intentionally NOT applied here — alias maps
        are populated from tool outputs, creating an indirect tool-state
        dependency that would undermine the query-anchored guarantee.
        """
        qtxt = str(turn_request or "")
        targets: list[str] = list(cls.extract_query_targets(qtxt))
        for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", qtxt):
            targets.append(str(email))
        for iban in re.findall(r"\b[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}\b", qtxt.upper()):
            targets.append(str(iban))
        for url in re.findall(r"(?:https?://)?(?:www\.)?(?:[A-Za-z0-9-]+\.)+[a-z]{2,}(?:/[^\s)>,]*)?", qtxt):
            targets.append(str(url))
            try:
                targets.append(str(urlparse(url).netloc or ""))
            except Exception:
                pass
        for domain in re.findall(r"\b(?:www\.)?(?:[A-Za-z0-9-]+\.)+[a-z]{2,}\b", qtxt):
            targets.append(str(domain))
        # Identity resolution: no alias expansion for query-anchored targets
        return cls._resolve_and_dedupe(targets, lambda x: x)

    @classmethod
    def contextual_targets(
        cls,
        *,
        turn_request: str,
        messages: Sequence[dict],
        whitelist: set[str],
        resolve_aliases: Callable[[object], object],
        summary_fallback_tools: set[str] | None = None,
    ) -> list[str]:
        qtxt = str(turn_request or "")
        targets: list[str] = list(cls.extract_query_targets(qtxt))
        summary_fallback_tools = summary_fallback_tools or set()
        for email in re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", qtxt):
            targets.append(str(email))
        for iban in re.findall(r"\b[A-Z]{2}[0-9]{2}[0-9A-Z]{10,30}\b", qtxt.upper()):
            targets.append(str(iban))
        for url in re.findall(r"(?:https?://)?(?:www\.)?(?:[A-Za-z0-9-]+\.)+[a-z]{2,}(?:/[^\s)>,]*)?", qtxt):
            targets.append(str(url))
            try:
                targets.append(str(urlparse(url).netloc or ""))
            except Exception:
                pass
        for domain in re.findall(r"\b(?:www\.)?(?:[A-Za-z0-9-]+\.)+[a-z]{2,}\b", qtxt):
            targets.append(str(domain))
        for msg in messages:
            if msg.get("role") != "tool":
                continue
            tool_name = cls.tool_name_for_message(msg)
            if tool_name not in whitelist:
                continue
            content = str(msg.get("content") or "")
            targets.extend(cls.extract_safe_targets_from_output_text(content))
            targets.extend(cls.extract_summary_fact_targets_from_output_text(content))
            if tool_name in summary_fallback_tools:
                targets.extend(cls.extract_summary_targets_from_output_text(content))

        return cls._resolve_and_dedupe(targets, resolve_aliases)

    @classmethod
    def capsule_contextual_targets(
        cls,
        *,
        messages: Sequence[dict],
        whitelist: set[str],
        resolve_aliases: Callable[[object], object],
    ) -> list[str]:
        """Targets safe enough to strengthen capsule provenance binding.

        Unlike `contextual_targets`, this intentionally ignores `safe_targets`
        extracted from raw tool outputs because those may include attacker-chosen
        references from untrusted bodies. For capsule authorization, only consume
        targets derived from sanitized summaries / summary facts.
        """
        targets: list[str] = []
        for msg in messages:
            if msg.get("role") != "tool":
                continue
            tool_name = cls.tool_name_for_message(msg)
            if tool_name not in whitelist:
                continue
            content = str(msg.get("content") or "")
            parsed = cls._parse_mapping_payload(content)
            if not isinstance(parsed, dict):
                continue
            targets.extend(
                cls._extract_capsule_targets_from_value(
                    parsed.get("summary"),
                    resolve_aliases=resolve_aliases,
                )
            )
            targets.extend(
                cls._extract_capsule_targets_from_value(
                    parsed.get("summary_facts"),
                    resolve_aliases=resolve_aliases,
                )
            )

        resolved_targets_by_norm: dict[str, str] = {}
        for target in targets:
            resolved = resolve_aliases(str(target or ""))
            normalized = cls.normalize_target(resolved)
            raw = str(resolved or "")
            if normalized and raw.strip() and normalized not in resolved_targets_by_norm:
                resolved_targets_by_norm[normalized] = raw
        out = sorted(str(item) for item in resolved_targets_by_norm.values() if str(item).strip())
        return out[:64]

    @classmethod
    def expand_target_prefixes(
        cls,
        tool_args: dict,
        contextual_targets: list[str],
        *,
        resolve_aliases: Callable[[object], object],
        prefix_expand_keys: set[str] | None = None,
    ) -> dict:
        observed: dict[str, str] = {}
        for raw in contextual_targets:
            text = str(raw or "")
            norm = cls.normalize_target(text)
            if text.strip() and norm and norm not in observed:
                observed[norm] = text
        if not observed:
            return dict(tool_args or {})
        prefix_expand_keys = prefix_expand_keys or cls.DEFAULT_PREFIX_EXPAND_KEYS

        def _candidate_allowed(key_norm: str, candidate: str) -> bool:
            cand = str(candidate or "").strip()
            if not cand:
                return False
            low = cand.lower()
            if key_norm in cls.SLACK_USER_KEYS:
                return "@" not in cand and not low.startswith("http") and "/" not in cand
            if key_norm in cls.SLACK_CHANNEL_KEYS:
                return "@" not in cand and not low.startswith("http") and "/" not in cand
            if key_norm in {"email", "user_email", "contact_email"}:
                return "@" in cand
            return True

        def _expand_scalar(key_norm: str, value: object) -> object:
            if value in (None, ""):
                return value
            sval = str(value).strip()
            norm = cls.normalize_target(resolve_aliases(sval))
            if not norm:
                return value
            exact = observed.get(norm)
            if exact and _candidate_allowed(key_norm, exact):
                return exact
            if "@" in norm or norm.startswith("http") or "/" in norm:
                return value
            longer_prefix_matches = [
                raw
                for onorm, raw in observed.items()
                if onorm != norm and onorm.startswith(norm) and _candidate_allowed(key_norm, raw)
            ]
            longer_prefix_matches = [candidate for candidate in longer_prefix_matches if str(candidate or "").strip()]
            if len(longer_prefix_matches) == 1:
                return longer_prefix_matches[0]
            candidates = [
                raw
                for onorm, raw in observed.items()
                if (onorm.startswith(norm) or norm.startswith(onorm)) and _candidate_allowed(key_norm, raw)
            ]
            candidates = [candidate for candidate in candidates if str(candidate or "").strip()]
            if len(candidates) == 1:
                return candidates[0]
            return value

        out = dict(tool_args or {})
        for key, value in list(out.items()):
            key_norm = str(key or "").strip().lower()
            if key_norm not in prefix_expand_keys:
                continue
            if isinstance(value, list):
                out[key] = [_expand_scalar(key_norm, item) for item in value]
            else:
                out[key] = _expand_scalar(key_norm, value)
        return out

    @staticmethod
    def matches_task_intent(
        *,
        turn_request: str,
        tool_name: str,
        tool_args: dict,
        tool_intent_keywords: dict[str, tuple[str, ...]],
        local_state_effect_tools: set[str],
        policy_targets: Sequence[str],
        recipient: str,
        domain: str,
    ) -> bool:
        req = str(turn_request or "").lower()
        if not req:
            return True
        keywords = tool_intent_keywords.get(str(tool_name), ())
        if keywords and any(keyword in req for keyword in keywords):
            return True
        for value in [*policy_targets, domain]:
            sval = str(value or "").strip().lower()
            if sval and sval in req:
                return True
        if tool_name in local_state_effect_tools and any(word in req for word in ("file", "calendar", "event", "email", "password", "address", "profile", "document", "note")):
            return True
        return False

    @classmethod
    def matches_trusted_follow_on_fetch(
        cls,
        *,
        turn_request: str,
        tool_name: str,
        tool_args: dict,
        contextual_targets: list[str],
        fetch_like_tools: set[str],
        domain: str,
    ) -> bool:
        if str(tool_name) not in fetch_like_tools:
            return False
        req = str(turn_request or "").lower()
        if not req:
            return False
        if not any(
            marker in req
            for marker in (
                "website",
                "webpage",
                "websites",
                "article",
                "blog",
                "link",
                "links",
                "content",
                "posted",
                "shared",
                "channel",
                "message",
                "messages",
                "inbox",
                "site",
                "page",
            )
        ):
            return False
        observed = {cls.normalize_target(item) for item in contextual_targets if str(item or "").strip()}
        if not observed:
            return False
        raw_url = str(tool_args.get("url") or "").strip()
        candidates = [raw_url, domain]
        if raw_url:
            try:
                candidates.append(str(urlparse(raw_url if "://" in raw_url else f"https://{raw_url}").netloc or "").strip())
            except Exception:
                pass
        for candidate in candidates:
            norm = cls.normalize_target(candidate)
            if norm and norm in observed:
                return True
        return False

    @staticmethod
    def tool_name_for_message(msg: dict) -> str:
        tool_call = msg.get("tool_call")
        if isinstance(tool_call, dict):
            return str(tool_call.get("function") or "")
        return str(getattr(tool_call, "function", "") or "")

    @classmethod
    def collect_observed_targets(
        cls,
        query: str,
        messages: Sequence[dict],
        *,
        whitelist: set[str],
        local_recipient: str = "",
        local_domain: str = "",
    ) -> set[str]:
        observed = {cls.normalize_target(item) for item in cls.extract_query_targets(query)}
        for msg in messages:
            if msg.get("role") != "tool":
                continue
            tool_name = cls.tool_name_for_message(msg)
            if tool_name not in whitelist:
                continue
            observed.update(cls.extract_safe_targets_from_output_text(str(msg.get("content") or "")))
        if local_recipient:
            observed.add(cls.normalize_target(local_recipient))
        if local_domain:
            observed.add(cls.normalize_target(local_domain))
        return {item for item in observed if item}

    @staticmethod
    def match_target(target: str, observed: set[str]) -> bool:
        if target in observed:
            return True
        if len(target) < 4:
            return False
        for item in observed:
            if len(item) < 4:
                continue
            if target in item or item in target:
                return True
        return False

    @classmethod
    def tool_likely_aligned(
        cls,
        query: str,
        messages: Sequence[dict],
        tool_name: str,
        tool_args: dict,
        *,
        whitelist: set[str],
        action_hints: dict[str, set[str]],
        local_recipient: str = "",
        local_domain: str = "",
    ) -> bool:
        if tool_name in whitelist:
            return True
        observed = cls.collect_observed_targets(
            query,
            messages,
            whitelist=whitelist,
            local_recipient=local_recipient,
            local_domain=local_domain,
        )
        targets = cls.extract_targets_from_args(tool_name, tool_args)
        if targets:
            return all(cls.match_target(target, observed) for target in targets)
        hints = action_hints.get(tool_name, set())
        query_l = str(query or "").lower()
        if hints and any(hint in query_l for hint in hints):
            return True
        tokens = [
            tok
            for tok in str(tool_name or "").lower().split("_")
            if tok
            not in {
                "get",
                "read",
                "search",
                "send",
                "create",
                "update",
                "delete",
                "cancel",
                "reschedule",
                "add",
                "remove",
                "share",
                "reserve",
                "schedule",
                "post",
            }
        ]
        return bool(tokens) and any(tok in query_l for tok in tokens)
