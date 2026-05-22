"""Severity normalization + ES filter helpers.

Extracted from dashboard_router.py (Phase A.4). One place to change when we
need to switch dashboard aggregations between the raw ``severity`` field
(Cyberint source-provided) and the AI-computed ``ai_severity`` field.

Public API:
    - SEVERITY_ORDER, CYBERINT_SEVERITY_BANDS  (constants)
    - normalize_severity(value)
    - source_severity(doc), ai_severity(doc), severity_label(value)
    - highest_severity_from_buckets(buckets)
    - severity_filters_config(field="severity")

Underscore-prefixed aliases (`_normalize_severity`, etc.) are kept for the
existing call sites in dashboard_router.py — switch them to the unprefixed
names during Phase B.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Sequence, Tuple


SEVERITY_ORDER: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "clean": 0,
}

# Cyberint emits `severity` as a discrete numeric score in the datalake.
# These bands mirror :func:`normalize_severity`'s numeric branch so that
# querying the datalake with a normalized string label maps to the right
# numeric range.
CYBERINT_SEVERITY_BANDS: Dict[str, Tuple[int, int]] = {
    "critical": (80, 100),
    "high": (60, 79),
    "medium": (40, 59),
    "low": (1, 39),
    "clean": (0, 0),
}


def normalize_severity(value: Optional[str]) -> str:
    """Normalize *value* into one of ``critical/high/medium/low/clean``.

    Accepts text labels (case-insensitive) and numeric Cyberint scores in
    string form. ``None`` / empty / unrecognised inputs return ``"low"``.
    """
    text = str(value or "").strip().lower()
    if text in {"critical", "very high"}:
        return "critical"
    if text == "high":
        return "high"
    if text == "medium":
        return "medium"
    if text in {"clean", "info"}:
        return "clean"
    # Handle numeric severity scores (e.g. cyberint sends "100", "80", "20", "0")
    if text.isdigit():
        score = int(text)
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        if score == 0:
            return "clean"
        return "low"
    return "low"


def source_severity(doc: Dict[str, Any]) -> str:
    """Severity as reported by the upstream source (``severity`` field)."""
    return normalize_severity(doc.get("severity"))


def ai_severity(doc: Dict[str, Any]) -> str:
    """AI-computed severity (``ai_severity``), falling back to source ``severity``."""
    return normalize_severity(doc.get("ai_severity") or doc.get("severity"))


def severity_label(value: str) -> str:
    """Capitalise a normalized severity for UI display (``"high"`` → ``"High"``)."""
    return value.capitalize() if value else "Low"


def highest_severity_from_buckets(buckets: Sequence[Dict[str, Any]]) -> str:
    """Return the highest-ranked severity present across ES term buckets."""
    highest = "clean"
    for bucket in buckets:
        if int(bucket.get("doc_count") or 0) <= 0:
            continue
        severity = normalize_severity(bucket.get("key"))
        if SEVERITY_ORDER[severity] > SEVERITY_ORDER[highest]:
            highest = severity
    return severity_label(highest)


def severity_filters_config(field: str = "severity") -> Dict[str, Dict[str, Any]]:
    """Build the ``filters`` agg dict for splitting docs by severity.

    *field* defaults to ``"severity"`` for backwards compatibility — pass
    ``"ai_severity"`` to switch aggregations onto the AI-computed field.
    """
    return {
        severity: {"term": {field: severity}}
        for severity in ("critical", "high", "medium", "low", "clean")
    }


# Backwards-compatibility aliases (existing dashboard_router code uses these).
_CYBERINT_SEVERITY_BANDS = CYBERINT_SEVERITY_BANDS
_normalize_severity = normalize_severity
_source_severity = source_severity
_ai_severity = ai_severity
_severity_label = severity_label
_highest_severity_from_buckets = highest_severity_from_buckets
_severity_filters_config = severity_filters_config


__all__ = [
    "SEVERITY_ORDER",
    "CYBERINT_SEVERITY_BANDS",
    "normalize_severity",
    "source_severity",
    "ai_severity",
    "severity_label",
    "highest_severity_from_buckets",
    "severity_filters_config",
    # aliases
    "_CYBERINT_SEVERITY_BANDS",
    "_normalize_severity",
    "_source_severity",
    "_ai_severity",
    "_severity_label",
    "_highest_severity_from_buckets",
    "_severity_filters_config",
]
