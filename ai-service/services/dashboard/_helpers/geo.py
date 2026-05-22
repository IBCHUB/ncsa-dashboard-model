"""Geographic / country normalization helpers.

Extracted from dashboard_router.py (Phase A.5). Drives the "Top Attack
Origins" / Threat Map widgets — every IOC doc is funnelled through
:func:`country_from_doc` so the dashboard can render a consistent country
regardless of which of the ~30 possible source fields populated it.

Public API:
    - COUNTRY_CODE_MAP       (name → ISO-2 code)
    - COUNTRY_NAME_FROM_CODE (ISO-2 code → Title-Cased name)
    - country_from_doc(doc)
    - country_code_from_name(name)
    - country_name_from_code_or_raw(value)

Underscore-prefixed aliases retained for the existing call sites in
dashboard_router.py.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


COUNTRY_CODE_MAP: Dict[str, str] = {
    "afghanistan": "AF", "albania": "AL", "algeria": "DZ", "argentina": "AR",
    "armenia": "AM", "australia": "AU", "austria": "AT", "azerbaijan": "AZ",
    "bahrain": "BH", "bangladesh": "BD", "belarus": "BY", "belgium": "BE",
    "bolivia": "BO", "bosnia and herzegovina": "BA", "brazil": "BR",
    "brunei": "BN", "bulgaria": "BG", "cambodia": "KH", "cameroon": "CM",
    "canada": "CA", "chile": "CL", "china": "CN", "colombia": "CO",
    "costa rica": "CR", "croatia": "HR", "cuba": "CU", "cyprus": "CY",
    "czech republic": "CZ", "czechia": "CZ", "denmark": "DK",
    "dominican republic": "DO", "ecuador": "EC", "egypt": "EG",
    "el salvador": "SV", "estonia": "EE", "ethiopia": "ET", "finland": "FI",
    "france": "FR", "georgia": "GE", "germany": "DE", "ghana": "GH",
    "greece": "GR", "guatemala": "GT", "honduras": "HN", "hong kong": "HK",
    "hungary": "HU", "iceland": "IS", "india": "IN", "indonesia": "ID",
    "iran": "IR", "iraq": "IQ", "ireland": "IE", "israel": "IL",
    "italy": "IT", "jamaica": "JM", "japan": "JP", "jordan": "JO",
    "kazakhstan": "KZ", "kenya": "KE", "kuwait": "KW", "kyrgyzstan": "KG",
    "laos": "LA", "latvia": "LV", "lebanon": "LB", "libya": "LY",
    "lithuania": "LT", "luxembourg": "LU", "macau": "MO", "malaysia": "MY",
    "maldives": "MV", "malta": "MT", "mexico": "MX", "moldova": "MD",
    "mongolia": "MN", "montenegro": "ME", "morocco": "MA", "mozambique": "MZ",
    "myanmar": "MM", "nepal": "NP", "netherlands": "NL", "new zealand": "NZ",
    "nicaragua": "NI", "nigeria": "NG", "north korea": "KP",
    "north macedonia": "MK", "norway": "NO", "oman": "OM", "pakistan": "PK",
    "palestine": "PS", "panama": "PA", "paraguay": "PY", "peru": "PE",
    "philippines": "PH", "poland": "PL", "portugal": "PT", "qatar": "QA",
    "romania": "RO", "russia": "RU", "russian federation": "RU",
    "saudi arabia": "SA", "senegal": "SN", "serbia": "RS", "singapore": "SG",
    "slovakia": "SK", "slovenia": "SI", "south africa": "ZA",
    "south korea": "KR", "spain": "ES", "sri lanka": "LK", "sudan": "SD",
    "sweden": "SE", "switzerland": "CH", "syria": "SY", "taiwan": "TW",
    "tajikistan": "TJ", "tanzania": "TZ", "thailand": "TH", "tunisia": "TN",
    "turkey": "TR", "turkmenistan": "TM", "uganda": "UG", "ukraine": "UA",
    "united arab emirates": "AE", "united kingdom": "GB", "united states": "US",
    "uruguay": "UY", "uzbekistan": "UZ", "venezuela": "VE", "vietnam": "VN",
    "yemen": "YE", "zambia": "ZM", "zimbabwe": "ZW",
}

# Reverse lookup (ISO-2 → Title-Cased name) computed once at import time.
COUNTRY_NAME_FROM_CODE: Dict[str, str] = {
    code: name.title() for name, code in COUNTRY_CODE_MAP.items()
}


def country_code_from_name(country_name: Optional[str]) -> Optional[str]:
    """Look up an ISO-2 code from a free-text country name (case-insensitive)."""
    if not country_name:
        return None
    raw = str(country_name).strip()
    if len(raw) == 2 and raw.isalpha():
        return raw.upper()
    normalized = raw.lower()
    return COUNTRY_CODE_MAP.get(normalized)


def country_name_from_code_or_raw(raw_value: Optional[str]) -> str:
    """Return a human-readable country name.

    If *raw_value* is a 2-letter ISO code that we recognise, return the
    full name (e.g. ``"US"`` → ``"United States"``). Otherwise return
    the original value unchanged.
    """
    if not raw_value:
        return "Unknown"
    trimmed = str(raw_value).strip()
    if len(trimmed) == 2 and trimmed.isalpha():
        return COUNTRY_NAME_FROM_CODE.get(trimmed.upper(), trimmed.upper())
    normalized = trimmed.lower()
    if normalized in COUNTRY_CODE_MAP:
        return COUNTRY_NAME_FROM_CODE.get(
            COUNTRY_CODE_MAP[normalized], trimmed.title()
        )
    return trimmed


def country_from_doc(doc: Dict[str, Any]) -> Optional[str]:
    """Best-effort country extraction across the ~30 possible source fields.

    The Cyberint/warehouse pipeline writes country into different shapes
    depending on the IOC type and enrichment that ran. This function walks
    the union of all known shapes and returns the first non-empty value
    normalized to a human-readable country name, or ``None`` if nothing
    usable was found.
    """
    enrichment = doc.get("enrichment") or {}
    ip_info = (
        enrichment.get("ip_info")
        if isinstance(enrichment, dict) and isinstance(enrichment.get("ip_info"), dict)
        else {}
    )
    asn_data = (doc.get("asn_data") or {}) if isinstance(doc.get("asn_data"), dict) else {}
    geo_info = (doc.get("geo_info") or {}) if isinstance(doc.get("geo_info"), dict) else {}
    direct_ip = (doc.get("ip_info") or {}) if isinstance(doc.get("ip_info"), dict) else {}
    geo_ip = (
        enrichment.get("geo_ip")
        if isinstance(enrichment, dict) and isinstance(enrichment.get("geo_ip"), dict)
        else {}
    )
    source_geo = (
        (((doc.get("source") or {}).get("geo") or {}) if isinstance(doc.get("source"), dict) else {})
        or {}
    )
    destination_geo = (
        (((doc.get("destination") or {}).get("geo") or {}) if isinstance(doc.get("destination"), dict) else {})
        or {}
    )
    victim_geo = (
        (((doc.get("victim") or {}).get("geo") or {}) if isinstance(doc.get("victim"), dict) else {})
        or {}
    )
    target_geo = (
        (((doc.get("target") or {}).get("geo") or {}) if isinstance(doc.get("target"), dict) else {})
        or {}
    )
    country = (
        ip_info.get("country")
        or direct_ip.get("country")
        or geo_ip.get("country_code")
        or geo_ip.get("country")
        or asn_data.get("country_code")
        or asn_data.get("country")
        or geo_info.get("country")
        or geo_info.get("country_code")
        or doc.get("geo_country")
        or doc.get("country")
        or doc.get("country_code")
        or doc.get("victim_country")
        or doc.get("victim_country_name")
        or doc.get("source_country")
        or doc.get("source_country_name")
        or doc.get("target_country")
        or doc.get("target_country_name")
        or doc.get("destination_country")
        or doc.get("destination_country_name")
        or doc.get("dst_country")
        or doc.get("dst_country_name")
        or source_geo.get("country_code")
        or source_geo.get("country_name")
        or source_geo.get("country")
        or destination_geo.get("country_code")
        or destination_geo.get("country_name")
        or destination_geo.get("country")
        or victim_geo.get("country_code")
        or victim_geo.get("country_name")
        or victim_geo.get("country")
        or target_geo.get("country_code")
        or target_geo.get("country_name")
        or target_geo.get("country")
    )
    normalized = str(country or "").strip()
    if not normalized or normalized.lower() in {"none", "null", "unknown", "n/a", "-"}:
        return None
    return country_name_from_code_or_raw(normalized)


# Backwards-compatibility aliases for existing call sites.
_COUNTRY_NAME_FROM_CODE = COUNTRY_NAME_FROM_CODE
_country_from_doc = country_from_doc
_country_code_from_name = country_code_from_name
_country_name_from_code_or_raw = country_name_from_code_or_raw


__all__ = [
    "COUNTRY_CODE_MAP",
    "COUNTRY_NAME_FROM_CODE",
    "country_from_doc",
    "country_code_from_name",
    "country_name_from_code_or_raw",
    # aliases
    "_COUNTRY_NAME_FROM_CODE",
    "_country_from_doc",
    "_country_code_from_name",
    "_country_name_from_code_or_raw",
]
