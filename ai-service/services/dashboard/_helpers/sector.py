"""Target-sector display + lookup helpers.

Extracted from dashboard_router.py (Phase A.6). Used by every endpoint
that surfaces a sector chip or chart entry (Operations dashboard,
Target Sectors report, IOC detail panel).

Public API:
    - SECTOR_DISPLAY_NAMES                 (raw label → canonical name)
    - sector_display_name(value)
    - sector_info(doc)

Underscore-prefixed aliases preserved for existing call sites in
dashboard_router.py.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional


# Keep the logger name stable across the refactor so existing tests /
# log searches that filter on "services.dashboard_router" still catch the
# "sector display name unmapped" warnings emitted below.
logger = logging.getLogger("services.dashboard_router")


# Mapping of raw sector labels (Thai + English, mixed casing) to the
# canonical English display name. Keys are matched case-insensitively
# (the helper lowers the lookup before checking).
SECTOR_DISPLAY_NAMES: Dict[str, str] = {
    "national security": "National Security",
    "security": "National Security",
    "ความมั่นคงของรัฐ": "National Security",
    "ด้านความมั่นคงของรัฐ": "National Security",
    "government": "Substantive Public Services",
    "public service": "Substantive Public Services",
    "public services": "Substantive Public Services",
    "essential government services": "Substantive Public Services",
    "substantive public services": "Substantive Public Services",
    "ภาครัฐ": "Substantive Public Services",
    "บริการภาครัฐ": "Substantive Public Services",
    "บริการภาครัฐที่สำคัญ": "Substantive Public Services",
    "ด้านบริการภาครัฐที่สำคัญ": "Substantive Public Services",
    "finance": "Banking and Finance",
    "financial": "Banking and Finance",
    "financial services": "Banking and Finance",
    "banking": "Banking and Finance",
    "banking and finance": "Banking and Finance",
    "finance and banking": "Banking and Finance",
    "ภาคการเงิน": "Banking and Finance",
    "การเงิน": "Banking and Finance",
    "การเงินการธนาคาร": "Banking and Finance",
    "ด้านการเงินการธนาคาร": "Banking and Finance",
    "technology": "Information Technology and Telecommunications",
    "telecom": "Information Technology and Telecommunications",
    "telecommunications": "Information Technology and Telecommunications",
    "information technology": "Information Technology and Telecommunications",
    "information technology and telecommunications": "Information Technology and Telecommunications",
    "เทคโนโลยี": "Information Technology and Telecommunications",
    "โทรคมนาคม": "Information Technology and Telecommunications",
    "เทคโนโลยีสารสนเทศและโทรคมนาคม": "Information Technology and Telecommunications",
    "ด้านเทคโนโลยีสารสนเทศและโทรคมนาคม": "Information Technology and Telecommunications",
    "transportation": "Transportation and Logistics",
    "transport": "Transportation and Logistics",
    "logistics": "Transportation and Logistics",
    "transportation and logistics": "Transportation and Logistics",
    "ขนส่ง": "Transportation and Logistics",
    "คมนาคม": "Transportation and Logistics",
    "การขนส่งและโลจิสติกส์": "Transportation and Logistics",
    "ด้านการขนส่งและโลจิสติกส์": "Transportation and Logistics",
    "energy": "Energy and Public Utilities",
    "utilities": "Energy and Public Utilities",
    "energy and public utilities": "Energy and Public Utilities",
    "พลังงาน": "Energy and Public Utilities",
    "สาธารณูปโภค": "Energy and Public Utilities",
    "พลังงานและสาธารณูปโภค": "Energy and Public Utilities",
    "ด้านพลังงานและสาธารณูปโภค": "Energy and Public Utilities",
    "health": "Public Health",
    "healthcare": "Public Health",
    "public health": "Public Health",
    "สาธารณสุข": "Public Health",
    "ด้านสาธารณสุข": "Public Health",
    "critical infrastructure": "Other",
    "โครงสร้างพื้นฐาน": "Other",
    "โครงสร้างพื้นฐานสำคัญ": "Other",
    "other": "Other",
    "other designated cii": "Other",
    "อื่นๆ": "Other",
    "อื่น ๆ": "Other",
    "general": "Other",
    "general/multiple": "Other",
    "ทั่วไป": "Other",
    "education": "Other",
    "ภาคการศึกษา": "Other",
    "การศึกษา": "Other",
    "manufacturing": "Other",
    "retail": "Other",
    "private sector": "Other",
}


# Once-per-process record of unmapped sector labels, used to keep the
# log noise bounded.
_UNMAPPED_SECTOR_SEEN: set[str] = set()


def sector_display_name(value: Any) -> Optional[str]:
    """Return the canonical sector name for *value*, or ``"Other"`` fallback.

    Empty / unknown inputs collapse to ``"Other"``. Unmapped raw labels
    are logged once at INFO so operators can extend
    :data:`SECTOR_DISPLAY_NAMES` rather than silently grouping new data
    into the catch-all bucket.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    lowered = raw.lower()
    if lowered in {"none", "null", "unknown", "n/a", "-", "ไม่ระบุ"}:
        return "Other"
    mapped = SECTOR_DISPLAY_NAMES.get(lowered) or SECTOR_DISPLAY_NAMES.get(raw)
    if mapped:
        return mapped
    if lowered not in _UNMAPPED_SECTOR_SEEN:
        _UNMAPPED_SECTOR_SEEN.add(lowered)
        logger.info(
            "sector display name unmapped, falling back to 'Other': %r", raw
        )
    return "Other"


def sector_info(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a ``{sector, sector_name, sector_name_th, icon}`` block from *doc*.

    Prefers the top-level ``target_sector*`` fields when present; falls
    back to ``ai_score_breakdown.target_sector`` (computed during scoring)
    otherwise.
    """
    if (
        doc.get("target_sector")
        or doc.get("target_sector_name")
        or doc.get("target_sector_name_th")
    ):
        sector_name = sector_display_name(
            doc.get("target_sector_name")
            or doc.get("target_sector")
            or doc.get("target_sector_name_th")
        )
        return {
            "sector": doc.get("target_sector"),
            "sector_name": sector_name,
            "sector_name_th": doc.get("target_sector_name_th"),
            "icon": doc.get("target_sector_icon"),
        }
    breakdown = doc.get("ai_score_breakdown")
    sector = (
        (((breakdown or {}).get("target_sector") or {}) if isinstance(breakdown, dict) else {})
        or {}
    )
    sector_name = sector_display_name(
        sector.get("sector_name") or sector.get("sector") or sector.get("sector_name_th")
    )
    return {
        "sector": sector.get("sector"),
        "sector_name": sector_name,
        "sector_name_th": sector.get("sector_name_th"),
        "icon": sector.get("icon"),
    }


# Backwards-compatibility aliases.
_sector_display_name = sector_display_name
_sector_info = sector_info


__all__ = [
    "SECTOR_DISPLAY_NAMES",
    "sector_display_name",
    "sector_info",
    "_UNMAPPED_SECTOR_SEEN",
    "_sector_display_name",
    "_sector_info",
]
