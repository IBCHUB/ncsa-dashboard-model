"""Response envelope builders for dashboard endpoints.

Extracted from dashboard_router.py (Phase A.1). These helpers shape every
JSON response sent by the dashboard API so the frontend gets a consistent
`{ data, meta, error }` envelope.

Public API:
    - meta(**extra)
    - success(data, **meta_extra)
    - paged(data, page, page_size, total, **meta_extra)

Backwards-compatibility aliases (`_meta`, `_success`, `_paged`) are also
exported so existing callers don't need to be rewritten in this phase.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Dict


def meta(**extra: Any) -> Dict[str, Any]:
    """Build the standard meta block (`generated_at`, `timezone`, plus extras)."""
    return {
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "timezone": "Asia/Bangkok",
        **extra,
    }


def success(data: Any, **meta_extra: Any) -> Dict[str, Any]:
    """Wrap *data* in the success envelope used by every dashboard endpoint."""
    return {"data": data, "meta": meta(**meta_extra), "error": None}


def paged(
    data: Any,
    page: int,
    page_size: int,
    total: int,
    **meta_extra: Any,
) -> Dict[str, Any]:
    """Like :func:`success` but includes pagination metadata."""
    total_pages = max(1, (total + page_size - 1) // page_size) if page_size > 0 else 1
    return {
        "data": data,
        "meta": meta(
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
            **meta_extra,
        ),
        "error": None,
    }


# Backwards-compatibility aliases (existing call sites use the leading-underscore
# names). New code should prefer the unprefixed names above.
_meta = meta
_success = success
_paged = paged


__all__ = ["meta", "success", "paged", "_meta", "_success", "_paged"]
