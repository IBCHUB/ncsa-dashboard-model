"""Time / date helpers used across every dashboard endpoint.

Extracted from dashboard_router.py (Phase A.3).

Includes:
    - Bangkok timezone constant
    - Time-mode constants (observed / processed / published / changed)
    - WAREHOUSE_TIME_FIELDS / DATALAKE_TIME_FIELDS / PYTHON_FILTER_FIELDS
    - parse_dt (ISO 8601 → tz-aware datetime)
    - Bangkok day/hour formatters and floor helpers
    - pick_activity_time / pick_event_time / pick_display_time(_in_range)
    - date_query_range  (build ES `range` clause for a [start,end] window)
    - resolve_anchor_end (used by comparison metrics)
    - resolve_date_bounds (parse window edges to datetime)

Underscore-prefixed aliases are kept so existing call sites in
``dashboard_router.py`` need no changes during this phase.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, Dict, Optional, Sequence, Tuple
from zoneinfo import ZoneInfo


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Timezone + time-mode constants
# ---------------------------------------------------------------------------
BANGKOK_TZ = ZoneInfo("Asia/Bangkok")

TIME_MODE_OBSERVED = "observed"
TIME_MODE_PROCESSED = "processed"
TIME_MODE_PUBLISHED = "published"
TIME_MODE_CHANGED = "changed"

# Field-name maps used to translate the user-facing time mode into the ES
# field(s) that actually carry that timestamp. Lists are tried in order; the
# first field present on the doc wins (semantics preserved verbatim from the
# original router).
WAREHOUSE_TIME_FIELDS: Dict[str, list[str]] = {
    "observed": ["event_time", "first_seen", "last_seen"],
    "processed": ["processed_at", "created_at", "collect_time"],
    "published": ["published_at"],
    # Warehouse mapping has no `revoked_at` or `updated_at` field. The two
    # populated change-timestamps are `last_shared_at` (set on every doc) and
    # `action_updated_at` (set when the action workflow advances).
    "changed": ["last_shared_at", "action_updated_at"],
}

DATALAKE_TIME_FIELDS: Dict[str, list[str]] = {
    "observed": ["observation_date", "first_seen"],
    "processed": ["@timestamp", "processed_at"],
    "published": ["published_at"],
    # Datalake has no native "changed" timestamp; fall back to @timestamp so
    # callers passing time_mode=changed against datalake don't silently bypass
    # the date filter (would return entire index).
    "changed": ["@timestamp"],
}

PYTHON_FILTER_FIELDS: Dict[str, list[str]] = {
    "observed": ["event_time", "first_seen", "last_seen", "observation_date"],
    "processed": ["processed_at", "created_at", "collect_time"],
    "published": ["published_at"],
    "changed": ["last_shared_at", "action_updated_at"],
}


# ---------------------------------------------------------------------------
# Datetime parsing + Bangkok formatting / flooring
# ---------------------------------------------------------------------------
def parse_dt(value: Any) -> Optional[datetime]:
    """Parse *value* into a tz-aware ``datetime`` (UTC if naive). ``None``-safe."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def to_bangkok_date(value: datetime) -> str:
    """Format *value* as ``YYYY-MM-DD`` in the Asia/Bangkok timezone."""
    return value.astimezone(BANGKOK_TZ).strftime("%Y-%m-%d")


def to_bangkok_hour(value: datetime) -> str:
    """Format *value* as ``YYYY-MM-DD HH:00`` in Asia/Bangkok."""
    return value.astimezone(BANGKOK_TZ).strftime("%Y-%m-%d %H:00")


def start_bangkok_day(value: datetime) -> datetime:
    """Return the start (00:00) of *value*'s Bangkok-local day."""
    localized = value.astimezone(BANGKOK_TZ)
    return datetime(localized.year, localized.month, localized.day, tzinfo=BANGKOK_TZ)


def start_bangkok_hour(value: datetime) -> datetime:
    """Return the start of *value*'s Bangkok-local hour."""
    localized = value.astimezone(BANGKOK_TZ)
    return datetime(
        localized.year, localized.month, localized.day, localized.hour, tzinfo=BANGKOK_TZ
    )


# ---------------------------------------------------------------------------
# Document-time pickers
# ---------------------------------------------------------------------------
def pick_activity_time(doc: Dict[str, Any]) -> Optional[datetime]:
    """Last-known activity timestamp for *doc* (broadest fallback chain)."""
    return parse_dt(
        doc.get("last_seen")
        or doc.get("event_time")
        or doc.get("observation_date")
        or doc.get("collect_time")
        or doc.get("processed_at")
        or doc.get("first_seen")
        or doc.get("@timestamp")
        or doc.get("created_at")
    )


def pick_event_time(doc: Dict[str, Any]) -> Optional[datetime]:
    """Best-guess "when did the event happen" timestamp for *doc*."""
    return parse_dt(
        doc.get("event_time")
        or doc.get("observation_date")
        or doc.get("first_seen")
        or doc.get("@timestamp")
        or doc.get("collect_time")
        or doc.get("processed_at")
        or doc.get("created_at")
    )


def pick_display_time(doc: Dict[str, Any], time_mode: str = "processed") -> Optional[datetime]:
    """Mode-aware timestamp for display — matches filter semantics so users see consistent data."""
    fields = PYTHON_FILTER_FIELDS.get(time_mode, PYTHON_FILTER_FIELDS["processed"])
    for field in fields:
        result = parse_dt(doc.get(field))
        if result:
            return result
    return pick_event_time(doc)


def pick_display_time_in_range(
    doc: Dict[str, Any],
    time_mode: str,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Optional[datetime]:
    """Prefer the timestamp that actually made the record match the selected range."""
    start_bound, end_bound = resolve_date_bounds(start_date, end_date)
    fields = PYTHON_FILTER_FIELDS.get(time_mode, PYTHON_FILTER_FIELDS["processed"])
    if start_bound or end_bound:
        for field in fields:
            result = parse_dt(doc.get(field))
            if result is None:
                continue
            if start_bound and result < start_bound:
                continue
            if end_bound and result > end_bound:
                continue
            return result
    return pick_display_time(doc, time_mode)


# ---------------------------------------------------------------------------
# Date range helpers (for ES queries + period anchoring)
# ---------------------------------------------------------------------------
def date_query_range(
    start_date: Optional[str], end_date: Optional[str]
) -> Optional[Dict[str, str]]:
    """Build the ``range`` clause body for an ES date filter.

    Bare ``YYYY-MM-DD`` is widened to a full Bangkok-local day.
    """
    if not start_date and not end_date:
        return None
    range_query: Dict[str, str] = {}
    if start_date:
        range_query["gte"] = (
            start_date if "T" in start_date else f"{start_date}T00:00:00+07:00"
        )
    if end_date:
        range_query["lte"] = (
            end_date if "T" in end_date else f"{end_date}T23:59:59+07:00"
        )
    return range_query


def resolve_anchor_end(end_date: Optional[str]) -> datetime:
    """Resolve the "current period end" anchor used by comparison metrics."""
    if end_date:
        normalized = end_date if "T" in end_date else f"{end_date}T23:59:59+07:00"
        parsed = parse_dt(normalized)
        if parsed:
            return parsed.astimezone(UTC)
        logger.warning(
            "_resolve_anchor_end: malformed end_date %r, falling back to now()",
            end_date,
        )
    return datetime.now(UTC)


def resolve_date_bounds(
    start_date: Optional[str], end_date: Optional[str]
) -> Tuple[Optional[datetime], Optional[datetime]]:
    """Parse a ``[start_date, end_date]`` window into datetime bounds (Bangkok-local)."""

    def _normalize(value: Optional[str], time_suffix: str) -> Optional[datetime]:
        if not value:
            return None
        text = value if "T" in value else f"{value}{time_suffix}"
        return parse_dt(text)

    start_bound = _normalize(start_date, "T00:00:00+07:00")
    end_bound = _normalize(end_date, "T23:59:59+07:00")
    return start_bound, end_bound


# ---------------------------------------------------------------------------
# Backwards-compatibility aliases (underscore names used by dashboard_router)
# ---------------------------------------------------------------------------
_parse_dt = parse_dt
_to_bangkok_date = to_bangkok_date
_to_bangkok_hour = to_bangkok_hour
_start_bangkok_day = start_bangkok_day
_start_bangkok_hour = start_bangkok_hour
_pick_activity_time = pick_activity_time
_pick_event_time = pick_event_time
_pick_display_time = pick_display_time
_pick_display_time_in_range = pick_display_time_in_range
_date_query_range = date_query_range
_resolve_anchor_end = resolve_anchor_end
_resolve_date_bounds = resolve_date_bounds


__all__ = [
    # constants
    "BANGKOK_TZ",
    "TIME_MODE_OBSERVED",
    "TIME_MODE_PROCESSED",
    "TIME_MODE_PUBLISHED",
    "TIME_MODE_CHANGED",
    "WAREHOUSE_TIME_FIELDS",
    "DATALAKE_TIME_FIELDS",
    "PYTHON_FILTER_FIELDS",
    # public names
    "parse_dt",
    "to_bangkok_date",
    "to_bangkok_hour",
    "start_bangkok_day",
    "start_bangkok_hour",
    "pick_activity_time",
    "pick_event_time",
    "pick_display_time",
    "pick_display_time_in_range",
    "date_query_range",
    "resolve_anchor_end",
    "resolve_date_bounds",
    # aliases (existing call sites)
    "_parse_dt",
    "_to_bangkok_date",
    "_to_bangkok_hour",
    "_start_bangkok_day",
    "_start_bangkok_hour",
    "_pick_activity_time",
    "_pick_event_time",
    "_pick_display_time",
    "_pick_display_time_in_range",
    "_date_query_range",
    "_resolve_anchor_end",
    "_resolve_date_bounds",
]

# `Sequence` is intentionally imported above only for forward-compat with
# future helpers — keep the import even if currently unused so callers can
# rely on it being available.
_ = Sequence
