"""Tests for build_classifier_context() -- validates that the context builder
synthesises meaningful classifier input from structured IOC data."""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils.pipeline_documents import build_classifier_context


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_doc(enrichment=None):
    """Return a minimal ioc_doc dict with optional enrichment."""
    doc = {"ioc_value": "example.com", "ioc_type": "domain"}
    if enrichment is not None:
        doc["enrichment"] = enrichment
    return doc


def _call(
    ioc_value="example.com",
    ioc_type="domain",
    descriptions=None,
    threat_types_raw=None,
    source_names=None,
    source_types=None,
    ioc_docs=None,
):
    """Convenience wrapper with sensible defaults."""
    return build_classifier_context(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        descriptions=descriptions or [],
        threat_types_raw=threat_types_raw or [],
        source_names=source_names or [],
        source_types=source_types or [],
        ioc_docs=ioc_docs if ioc_docs is not None else [],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestContextAlwaysIncludesIocIdentity:
    """IOC value and type are always present in the output."""

    def test_context_always_includes_ioc_identity(self):
        result = _call(ioc_value="10.0.0.1", ioc_type="ip")

        assert "10.0.0.1" in result
        assert "ip" in result
        assert "IOC: 10.0.0.1 (type: ip)" in result

    def test_identity_present_with_no_other_data(self):
        result = _call(ioc_value="evil.test", ioc_type="domain")

        assert "IOC: evil.test (type: domain)" in result


class TestContextIncludesDescriptionWhenPresent:
    """Existing descriptions appear as a primary signal."""

    def test_context_includes_description_when_present(self):
        result = _call(descriptions=["Phishing domain targeting banks"])

        assert "Phishing domain targeting banks" in result

    def test_multiple_descriptions_joined(self):
        result = _call(descriptions=["Line one", "Line two"])

        assert "Line one" in result
        assert "Line two" in result


class TestContextIncludesSourceThreatTypes:
    """threat_types from source appear in the context."""

    def test_context_includes_source_threat_types(self):
        result = _call(threat_types_raw=["malware", "phishing"])

        assert "Threat types reported by source:" in result
        assert "malware" in result
        assert "phishing" in result

    def test_empty_threat_types_omitted(self):
        result = _call(threat_types_raw=["", ""])

        assert "Threat types reported by source:" not in result


class TestContextIncludesSourceNames:
    """Source names and types appear in the context."""

    def test_context_includes_source_names(self):
        result = _call(
            source_names=["AlienVault"],
            source_types=["osint"],
        )

        assert "Reported by:" in result
        assert "AlienVault" in result
        assert "osint" in result

    def test_source_without_type(self):
        result = _call(
            source_names=["CustomFeed"],
            source_types=[],
        )

        assert "CustomFeed" in result

    def test_multiple_sources(self):
        result = _call(
            source_names=["SourceA", "SourceB"],
            source_types=["osint", "commercial"],
        )

        assert "SourceA (osint)" in result
        assert "SourceB (commercial)" in result


class TestContextExtractsWhoisData:
    """enrichment.whois registrant org, country, creation_date."""

    def test_context_extracts_whois_data(self):
        doc = _make_doc(enrichment={
            "whois": {
                "domain_name": "evil.example",
                "registrant_organization": "ShellCorp LLC",
                "registrant_country": "RU",
                "creation_date": "2024-01-15T00:00:00Z",
                "registrar": "BadRegistrar Inc",
            }
        })
        result = _call(ioc_docs=[doc])

        assert "evil.example" in result
        assert "ShellCorp LLC" in result
        assert "RU" in result
        assert "2024-01-15" in result
        assert "BadRegistrar Inc" in result

    def test_whois_with_list_domain_name(self):
        doc = _make_doc(enrichment={
            "whois": {
                "domain_name": ["EVIL.EXAMPLE", "evil.example"],
                "org": "TestOrg",
                "country": "CN",
            }
        })
        result = _call(ioc_docs=[doc])

        assert "EVIL.EXAMPLE" in result
        assert "TestOrg" in result
        assert "CN" in result


class TestContextExtractsIpInfo:
    """enrichment.ip_info country, ASN, org."""

    def test_context_extracts_ip_info(self):
        doc = _make_doc(enrichment={
            "ip_info": {
                "country": "US",
                "asn": "AS13335",
                "org": "Cloudflare Inc",
            }
        })
        result = _call(ioc_docs=[doc])

        assert "IP located in US" in result
        assert "AS13335" in result
        assert "Cloudflare Inc" in result

    def test_ip_info_country_code_fallback(self):
        doc = _make_doc(enrichment={
            "ip_info": {
                "country_code": "DE",
                "org": "Hetzner",
            }
        })
        result = _call(ioc_docs=[doc])

        assert "IP located in DE" in result
        assert "Hetzner" in result

    def test_ip_info_org_only(self):
        doc = _make_doc(enrichment={
            "ip_info": {
                "org": "SomeISP",
            }
        })
        result = _call(ioc_docs=[doc])

        assert "Organization: SomeISP" in result


class TestContextExtractsCategories:
    """enrichment.categories (list format and dict format)."""

    def test_context_extracts_categories_list(self):
        doc = _make_doc(enrichment={
            "categories": ["malware", "botnet", "c2"],
        })
        result = _call(ioc_docs=[doc])

        assert "Threat categories:" in result
        assert "malware" in result
        assert "botnet" in result
        assert "c2" in result

    def test_context_extracts_categories_dict(self):
        doc = _make_doc(enrichment={
            "categories": {
                "Forcepoint": "malicious",
                "BitDefender": "phishing",
            },
        })
        result = _call(ioc_docs=[doc])

        assert "Threat categories:" in result
        assert "malicious" in result
        assert "phishing" in result


class TestContextHandlesEmptyEnrichment:
    """No enrichment still returns IOC identity + sources."""

    def test_context_handles_empty_enrichment(self):
        doc = _make_doc(enrichment=None)
        result = _call(
            ioc_value="badhost.com",
            ioc_type="domain",
            source_names=["TestSource"],
            source_types=["osint"],
            ioc_docs=[doc],
        )

        assert "IOC: badhost.com (type: domain)" in result
        assert "TestSource" in result

    def test_empty_enrichment_dict(self):
        doc = _make_doc(enrichment={})
        result = _call(ioc_docs=[doc])

        assert "IOC: example.com (type: domain)" in result
        assert "whois" not in result.lower() or "Threat categories" not in result


class TestContextDeduplicatesWhois:
    """Multiple docs with same whois produce only one whois block."""

    def test_context_deduplicates_whois(self):
        whois_data = {
            "domain_name": "evil.test",
            "registrant_organization": "DupeCorp",
            "registrant_country": "KP",
        }
        doc_a = _make_doc(enrichment={"whois": whois_data})
        doc_b = _make_doc(enrichment={"whois": whois_data})

        result = _call(ioc_docs=[doc_a, doc_b])

        assert result.count("DupeCorp") == 1
        assert result.count("evil.test") == 1


class TestContextIsPureFunction:
    """Input dicts are not mutated."""

    def test_context_is_pure_function(self):
        doc = _make_doc(enrichment={
            "whois": {
                "domain_name": "pure.test",
                "registrant_organization": "PureCorp",
            },
            "ip_info": {
                "country": "JP",
                "asn": "AS1234",
                "org": "PureISP",
            },
            "categories": ["trojan"],
        })
        original = copy.deepcopy(doc)
        descriptions = ["Test description"]
        threat_types = ["malware"]
        sources = ["Feed1"]
        source_types = ["osint"]

        original_descriptions = list(descriptions)
        original_threats = list(threat_types)
        original_sources = list(sources)
        original_source_types = list(source_types)

        _call(
            descriptions=descriptions,
            threat_types_raw=threat_types,
            source_names=sources,
            source_types=source_types,
            ioc_docs=[doc],
        )

        assert doc == original, "ioc_doc was mutated"
        assert descriptions == original_descriptions, "descriptions list was mutated"
        assert threat_types == original_threats, "threat_types_raw list was mutated"
        assert sources == original_sources, "source_names list was mutated"
        assert source_types == original_source_types, "source_types list was mutated"
