"""
WHOIS-based domain age enrichment.
Looks up domain registration date to compute domain_age_days.

Uses python-whois library (add to requirements.txt).
In-memory LRU cache prevents re-querying same domain in a session.
Gracefully returns None on any failure (rate limit, timeout, no data).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# IOC types that can have a registrable domain
_DOMAIN_IOC_TYPES = frozenset({"url", "domain", "hostname", "fqdn", "uri"})

# Private / skip patterns
_SKIP_HOSTS = frozenset({"localhost", "localhost."})
_SKIP_SUFFIXES = (".local", ".internal", ".localdomain", ".corp")

_PRIVATE_IP_RE = re.compile(
    r"^("
    r"10\.\d+\.\d+\.\d+"
    r"|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+"
    r"|127\.\d+\.\d+\.\d+"
    r"|::1"
    r"|fc[0-9a-f]{2}:.+"
    r")$",
    re.IGNORECASE,
)


def _extract_domain(ioc_value: str, ioc_type: str) -> Optional[str]:
    """Extract registrable domain from URL or domain IOC."""
    ioc_type_lower = (ioc_type or "").strip().lower()
    value = (ioc_value or "").strip()

    if not value:
        return None

    # Only process domain-like IOC types
    if ioc_type_lower not in _DOMAIN_IOC_TYPES:
        return None

    # Extract host from URL
    if ioc_type_lower in ("url", "uri") or "://" in value:
        try:
            parsed = urlparse(value if "://" in value else "http://" + value)
            host = parsed.hostname or ""
        except Exception:
            host = ""
    else:
        # domain / hostname / fqdn — strip trailing dot
        host = value.rstrip(".")

    if not host:
        return None

    host_lower = host.lower()

    # Skip localhost and local-only hostnames
    if host_lower in _SKIP_HOSTS:
        return None
    for suffix in _SKIP_SUFFIXES:
        if host_lower.endswith(suffix):
            return None

    # Skip private/loopback IPs
    if _PRIVATE_IP_RE.match(host):
        return None

    # Skip bare IP addresses (any valid IPv4 pattern)
    _ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if _ip_re.match(host):
        return None

    return host


@lru_cache(maxsize=2000)
def _cached_lookup(domain: str) -> Optional[int]:
    """Cached WHOIS lookup — result persists for the process lifetime."""
    try:
        import whois  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("python-whois not installed; WHOIS enrichment disabled")
        return None

    try:
        data = whois.whois(domain)
    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)
        return None

    if data is None:
        return None

    # creation_date can be a datetime or a list of datetimes
    creation_date = getattr(data, "creation_date", None)
    if creation_date is None:
        return None

    if isinstance(creation_date, list):
        # Use the earliest date
        dates = [d for d in creation_date if isinstance(d, datetime)]
        if not dates:
            return None
        creation_date = min(dates)

    if not isinstance(creation_date, datetime):
        return None

    try:
        now = datetime.now(timezone.utc)
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        age_days = (now - creation_date).days
        return max(age_days, 0)
    except Exception as exc:
        logger.debug("Failed to compute domain age for %s: %s", domain, exc)
        return None


def lookup_domain_age(ioc_value: str, ioc_type: str) -> Optional[int]:
    """Return domain age in days, or None if unavailable."""
    try:
        domain = _extract_domain(ioc_value, ioc_type)
        if domain is None:
            return None
        return _cached_lookup(domain)
    except Exception as exc:
        logger.debug("lookup_domain_age error for %s/%s: %s", ioc_value, ioc_type, exc)
        return None
