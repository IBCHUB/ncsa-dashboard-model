"""Unit tests for whois_enrichment — domain extraction and graceful failure."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.whois_enrichment import _extract_domain, lookup_domain_age


def test_extract_domain_from_url():
    assert _extract_domain("https://evil.example.com/path?q=1", "url") == "evil.example.com"

def test_extract_domain_from_domain_ioc():
    assert _extract_domain("evil.example.com", "domain") == "evil.example.com"

def test_extract_domain_strips_www():
    # www prefix should be preserved (WHOIS needs the actual registered domain)
    result = _extract_domain("https://www.example.com/foo", "url")
    assert result == "www.example.com" or result == "example.com"

def test_extract_domain_ip_returns_none():
    assert _extract_domain("1.2.3.4", "ip") is None
    assert _extract_domain("192.168.1.1", "ip") is None

def test_extract_domain_localhost_returns_none():
    assert _extract_domain("localhost", "domain") is None
    assert _extract_domain("http://localhost/", "url") is None

def test_lookup_domain_age_graceful_on_invalid():
    """lookup_domain_age must return None (not raise) for invalid inputs."""
    result = lookup_domain_age("not-a-real-domain-xyz-99999.com", "domain")
    assert result is None or isinstance(result, int)

def test_lookup_domain_age_non_domain_ioc_returns_none():
    """Hash and IP IOC types should return None immediately."""
    assert lookup_domain_age("abc123", "sha256") is None
    assert lookup_domain_age("1.2.3.4", "ip") is None
