"""
Sanitization helpers for AI/ML pipeline inputs.

Redacts sensitive values before content is classified, scored, or persisted.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List
import ipaddress
import re

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")
THAI_ID_RE = re.compile(r"(?<!\d)\d{13}(?!\d)")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Z0-9._~+/=-]{10,}")
CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:api[_ -]?key|token|secret|password|passwd|authorization)\b\s*[:=]\s*[^\s,;]+"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _merge_counts(target: Dict[str, int], source: Dict[str, int]) -> Dict[str, int]:
    for key, value in source.items():
        target[key] = target.get(key, 0) + value
    return target


def _replace_private_ips(text: str) -> tuple[str, int]:
    count = 0

    def replacer(match: re.Match[str]) -> str:
        nonlocal count
        candidate = match.group(0)
        try:
            if ipaddress.ip_address(candidate).is_private:
                count += 1
                return "[REDACTED_PRIVATE_IP]"
        except ValueError:
            return candidate
        return candidate

    return IP_RE.sub(replacer, text), count


def sanitize_text(value: str) -> Dict[str, Any]:
    text = str(value or "")
    counts: Dict[str, int] = {}

    for label, pattern, replacement in [
        ("email", EMAIL_RE, "[REDACTED_EMAIL]"),
        ("thai_national_id", THAI_ID_RE, "[REDACTED_ID]"),
        ("bearer_token", BEARER_RE, "Bearer [REDACTED_TOKEN]"),
        ("credential_secret", CREDENTIAL_RE, "[REDACTED_SECRET]"),
    ]:
        text, replaced = pattern.subn(replacement, text)
        if replaced > 0:
            counts[label] = replaced

    text, private_ip_count = _replace_private_ips(text)
    if private_ip_count > 0:
        counts["private_ip"] = private_ip_count

    text, phone_count = PHONE_RE.subn("[REDACTED_PHONE]", text)
    if phone_count > 0:
        counts["phone"] = counts.get("phone", 0) + phone_count

    flags = [f"redacted_{name}" for name in sorted(counts)]
    return {
        "text": text,
        "redaction_counts": counts,
        "sanitized": bool(counts),
        "flags": flags
    }


def sanitize_observation_fields(
    descriptions: Iterable[str],
    references: Iterable[str],
    tags: Iterable[str]
) -> Dict[str, Any]:
    summary_counts: Dict[str, int] = {}
    flags: List[str] = []
    flagged_fields: List[str] = []

    def sanitize_many(values: Iterable[str], field_name: str) -> List[str]:
        sanitized_values: List[str] = []
        field_touched = False
        for value in values:
            result = sanitize_text(value)
            cleaned = result["text"].strip()
            if cleaned:
                sanitized_values.append(cleaned)
            if result["sanitized"]:
                nonlocal_flags.extend(result["flags"])
                _merge_counts(summary_counts, result["redaction_counts"])
                field_touched = True
        if field_touched and field_name not in flagged_fields:
            flagged_fields.append(field_name)
        return sanitized_values

    nonlocal_flags: List[str] = []
    sanitized_descriptions = sanitize_many(descriptions, "description")
    sanitized_references = sanitize_many(references, "reference")
    sanitized_tags = sanitize_many(tags, "tags")

    for flag in nonlocal_flags:
        if flag not in flags:
            flags.append(flag)

    return {
        "descriptions": sanitized_descriptions,
        "references": sanitized_references,
        "tags": sanitized_tags,
        "summary": {
            "sanitized": bool(summary_counts),
            "redaction_counts": summary_counts,
            "flagged_fields": flagged_fields,
            "flags": flags
        }
    }
