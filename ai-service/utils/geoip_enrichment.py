"""
GeoIP enrichment using MaxMind GeoLite2-Country database.

Provides country-level geolocation for IP addresses. Uses a singleton
reader for efficient repeated lookups (~50K lookups/sec in-memory).

Setup:
  1. Register at https://www.maxmind.com/en/geolite2/signup
  2. Download GeoLite2-Country.mmdb
  3. Place in ai-service/data/GeoLite2-Country.mmdb
     (or set GEOIP_DB_PATH env variable)
"""

from __future__ import annotations

import ipaddress
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]

# Search paths for the GeoLite2 database (first found wins)
_DEFAULT_DB_PATHS = [
    os.environ.get("GEOIP_DB_PATH", ""),
    str(_AI_SERVICE_ROOT / "data" / "GeoLite2-Country.mmdb"),
    str(_AI_SERVICE_ROOT / "GeoLite2-Country.mmdb"),
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
]

# Singleton reader
_reader: Any = None
_reader_loaded = False


def _find_db_path() -> Optional[str]:
    """Find the first existing GeoLite2-Country.mmdb file."""
    for candidate in _DEFAULT_DB_PATHS:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def _get_reader() -> Any:
    """Get or create the singleton GeoIP reader."""
    global _reader, _reader_loaded
    if _reader_loaded:
        return _reader

    _reader_loaded = True

    db_path = _find_db_path()
    if not db_path:
        logger.warning(
            "GeoLite2-Country.mmdb not found. GeoIP enrichment disabled. "
            "Download from https://www.maxmind.com/en/geolite2/signup and "
            "place in ai-service/data/GeoLite2-Country.mmdb"
        )
        return None

    try:
        import geoip2.database  # type: ignore[import-untyped]

        _reader = geoip2.database.Reader(db_path)
        logger.info("GeoIP database loaded: %s", db_path)
        return _reader
    except ImportError:
        logger.warning(
            "geoip2 package not installed. Run: pip install geoip2. "
            "GeoIP enrichment disabled."
        )
        return None
    except Exception as exc:
        logger.warning("Failed to load GeoIP database %s: %s", db_path, exc)
        return None


def _is_valid_global_ip(ip_str: str) -> bool:
    """Check if the string is a valid, globally routable IP address."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_global
    except (ValueError, TypeError):
        return False


def lookup_country(ip_address: str) -> Optional[str]:
    """
    Look up the ISO country code for an IP address.

    Returns a 2-letter ISO country code (e.g. "TH", "US", "CN")
    or None if lookup fails or IP is private/invalid.
    """
    ip_str = str(ip_address or "").strip()
    if not ip_str or not _is_valid_global_ip(ip_str):
        return None

    reader = _get_reader()
    if not reader:
        return None

    try:
        response = reader.country(ip_str)
        country_code = response.country.iso_code
        return country_code if country_code else None
    except Exception:
        # AddressNotFoundError, InvalidDatabaseError, etc.
        return None


def lookup_country_detail(ip_address: str) -> Optional[Dict[str, str]]:
    """
    Look up country details for an IP address.

    Returns dict with iso_code, country_name, continent_code
    or None if lookup fails.
    """
    ip_str = str(ip_address or "").strip()
    if not ip_str or not _is_valid_global_ip(ip_str):
        return None

    reader = _get_reader()
    if not reader:
        return None

    try:
        response = reader.country(ip_str)
        iso_code = response.country.iso_code
        if not iso_code:
            return None
        return {
            "iso_code": iso_code,
            "country_name": response.country.name or iso_code,
            "continent_code": response.continent.code or "",
        }
    except Exception:
        return None


def enrich_geo_country(
    doc: Dict[str, Any],
    *,
    ip_field: str = "ioc_value",
    type_field: str = "ioc_type",
    country_field: str = "geo_country",
    ip_types: tuple = ("ip", "ipv4", "ipv6", "ip-src", "ip-dst", "ip_address"),
) -> Dict[str, Any]:
    """
    Enrich a document with geo_country from its IP IOC value if missing.

    Returns a NEW dict (no mutation). If the document already has a
    geo_country or is not an IP-type IOC, returns it unchanged.
    """
    existing_country = str(doc.get(country_field) or "").strip()
    if existing_country:
        return doc

    ioc_type = str(doc.get(type_field, "")).strip().lower()
    if ioc_type not in ip_types:
        return doc

    ip_value = str(doc.get(ip_field, "")).strip()
    country_code = lookup_country(ip_value)
    if not country_code:
        return doc

    return {**doc, country_field: country_code}
