"""Unit tests for datalake_adapters — covers geo extraction, occurrences_count, and related_entities."""
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Stub heavy optional deps before any import touches them
for _mod in ("geoip2", "geoip2.database", "geoip2.errors"):
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

from datalake_adapters import (  # noqa: E402
    _extract_geo_country,
    extract_cyberint_evidence,
    _extract_related_entities_evidence,
    extract_virustotal_evidence,
)


# ---------------------------------------------------------------------------
# _extract_geo_country — enrichment.geo (new *-enrichment-* format)
# ---------------------------------------------------------------------------

def test_geo_from_enrichment_geo_key():
    """*-enrichment-* format uses enrichment.geo instead of enrichment.geo_ip."""
    raw = {}
    enrichment = {"geo": {"country": "Thailand", "city": "Bangkok"}}
    result = _extract_geo_country(raw, enrichment)
    assert result == "Thailand"


def test_geo_ip_still_works():
    """tcti-feeds-* format enrichment.geo_ip must still be read."""
    raw = {}
    enrichment = {"geo_ip": {"country_code": "US", "country": "United States"}}
    result = _extract_geo_country(raw, enrichment)
    assert result == "US"


def test_geo_ip_takes_priority_over_geo():
    """geo_ip should be preferred when both keys exist."""
    enrichment = {
        "geo_ip": {"country": "Germany"},
        "geo": {"country": "Japan"},
    }
    result = _extract_geo_country({}, enrichment)
    assert result == "Germany"


def test_ip_info_asn_data_country():
    """enrichment.ip_info.asn_data.country should be reachable."""
    enrichment = {
        "ip_info": {
            "ip": "1.2.3.4",
            "asn_data": {"country": "SG", "org": "AS1234 Example ISP"},
        }
    }
    result = _extract_geo_country({}, enrichment)
    assert result == "SG"


def test_ip_info_direct_country_still_works():
    """Existing ip_info.country (legacy format) must still be read."""
    enrichment = {"ip_info": {"country": "FR"}}
    result = _extract_geo_country({}, enrichment)
    assert result == "FR"


# ---------------------------------------------------------------------------
# extract_cyberint_evidence — occurrences_count
# ---------------------------------------------------------------------------

def test_occurrences_count_stored_in_evidence():
    """occurrences_count from Zone-H cyberint.risk should appear in evidence."""
    enrichment = {
        "cyberint": {
            "risk": {
                "malicious_score": 100,
                "occurrences_count": 32,
                "detected_activities": [],
            }
        }
    }
    ev = extract_cyberint_evidence(enrichment)
    assert ev.get("cyberint_occurrence_count") == 32


def test_occurrences_count_high_adds_extra_source():
    """occurrences_count >= 5 means Cyberint confirmed multi-occurrence — add extra source."""
    enrichment = {
        "cyberint": {
            "risk": {"malicious_score": 80, "occurrences_count": 15, "detected_activities": []}
        }
    }
    ev = extract_cyberint_evidence(enrichment)
    sources = ev.get("external_evidence_sources", [])
    assert "Cyberint" in sources
    assert any("multi-occurrence" in s for s in sources)


def test_occurrences_count_low_no_extra_source():
    """occurrences_count < 5 should NOT add the extra corroboration source."""
    enrichment = {
        "cyberint": {
            "risk": {"malicious_score": 80, "occurrences_count": 2, "detected_activities": []}
        }
    }
    ev = extract_cyberint_evidence(enrichment)
    sources = ev.get("external_evidence_sources", [])
    assert sources == ["Cyberint"]


def test_occurrences_count_absent_defaults_to_no_count():
    """When occurrences_count field is absent the count should not appear in evidence."""
    enrichment = {
        "cyberint": {
            "risk": {"malicious_score": 80, "detected_activities": []}
        }
    }
    ev = extract_cyberint_evidence(enrichment)
    assert ev.get("cyberint_occurrence_count") is None


# ---------------------------------------------------------------------------
# _extract_related_entities_evidence — top-level enrichment.related_entities
# ---------------------------------------------------------------------------

def test_related_entities_extracts_threat_actors():
    """enrichment.related_entities Threat-Actor-Group entries should become threat actors."""
    enrichment = {
        "related_entities": [
            {"entity_id": "aaa", "entity_type": "Threat-Actor-Group", "entity_name": "Lazarus Group"},
            {"entity_id": "bbb", "entity_type": "Threat-Actor-Group", "entity_name": "APT33"},
            {"entity_id": "ccc", "entity_type": "Malware", "entity_name": "PlugX"},  # not an actor
        ]
    }
    ev = _extract_related_entities_evidence(enrichment)
    actors = ev.get("source_threat_actors", [])
    assert "Lazarus Group" in actors
    assert "APT33" in actors
    assert "PlugX" not in actors


def test_related_entities_empty_returns_empty():
    """Empty or absent related_entities should return empty dict."""
    assert _extract_related_entities_evidence({}) == {}
    assert _extract_related_entities_evidence({"related_entities": []}) == {}


def test_related_entities_non_actor_types_ignored():
    """Only Threat-Actor-Group entries are extracted — other entity_types are skipped."""
    enrichment = {
        "related_entities": [
            {"entity_type": "Campaign", "entity_name": "Dark Waters"},
            {"entity_type": "Tool", "entity_name": "Cobalt Strike"},
        ]
    }
    ev = _extract_related_entities_evidence(enrichment)
    assert ev.get("source_threat_actors", []) == []
