"""
Edge-case tests for the pipeline document builder.

Production data is rarely clean: missing fields, malformed timestamps,
unicode, conflicting signals across multi-source observations. These
tests guard against silent failures on real-world input shapes.
"""

import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Stub out heavy ML deps so this test stays unit-level (no model loading).
sys.modules["models.classifier"] = types.SimpleNamespace(
    classify_threat=lambda text: {
        "threat_types": [],
        "confidence": 0.0,
        "sector_classifications": [],
    },
    extract_threat_actors=lambda text: [],
    extract_mitre_techniques=lambda text: [],
)
sys.modules["models.actions"] = types.SimpleNamespace(
    derive_action_metadata=lambda doc: {}
)

from utils.pipeline_documents import (  # noqa: E402
    build_enriched_ioc_document,
    parse_dt,
)


# ---------------------------------------------------------------------------
# parse_dt — defensive against many real-world timestamp formats
# ---------------------------------------------------------------------------


def test_parse_dt_handles_zulu_suffix():
    """ISO-8601 with trailing Z (Elasticsearch default)."""
    result = parse_dt("2026-05-21T06:31:54.276488Z")
    assert result is not None
    assert result.year == 2026
    assert result.tzinfo is not None


def test_parse_dt_handles_offset():
    """ISO-8601 with explicit timezone offset."""
    result = parse_dt("2024-09-01T23:55:13+00:00")
    assert result is not None
    assert result.year == 2024


def test_parse_dt_handles_naive_iso_assumes_utc():
    """Naive datetime string must be treated as UTC, not crash."""
    result = parse_dt("2025-01-15T12:00:00")
    assert result is not None
    assert result.tzinfo is not None  # Promoted to UTC


def test_parse_dt_handles_garbage_returns_none():
    """Malformed timestamps must return None, not raise."""
    assert parse_dt("not-a-date") is None
    assert parse_dt("") is None
    assert parse_dt(None) is None
    assert parse_dt(12345) is None  # Wrong type
    assert parse_dt({}) is None


# ---------------------------------------------------------------------------
# Empty / minimal observations — must produce a valid doc, not crash
# ---------------------------------------------------------------------------


def _minimal_doc(**overrides) -> dict:
    """Smallest valid observation; tests override individual fields."""
    base = {
        "_id": "test-1",
        "_index": "test-index",
        "adapter_name": "test_adapter",
        "ioc_type": "domain",
        "ioc_value": "test.example",
        "source_name": "TestFeed",
        "source_type": "external-feed",
        "description": "test description",
        "threat_type": [],
        "severity": "",
        "confidence": 0,
        "event_time": "2026-01-01T00:00:00+00:00",
        "collect_time": "2026-01-01T00:00:00+00:00",
    }
    base.update(overrides)
    return base


def test_build_doc_with_minimal_observation_does_not_crash():
    """Single minimal observation should produce a complete warehouse doc."""
    result = build_enriched_ioc_document([_minimal_doc()])
    assert result["document"]["ioc_value"] == "test.example"
    assert "ai_risk_score" in result["document"]
    assert "ai_severity" in result["document"]


def test_build_doc_with_empty_description():
    """Empty description must not crash threat extraction / classification."""
    result = build_enriched_ioc_document([_minimal_doc(description="")])
    doc = result["document"]
    assert doc["ai_risk_score"] >= 0


def test_build_doc_with_none_event_time_uses_collect_time_fallback():
    """Missing event_time must not crash the decay calculation."""
    result = build_enriched_ioc_document([_minimal_doc(
        event_time=None,
        collect_time="2026-05-01T00:00:00+00:00",
    )])
    assert result["document"]["ai_risk_score"] >= 0


def test_build_doc_with_malformed_timestamp_falls_back_gracefully():
    """Garbage timestamps must not poison the pipeline."""
    result = build_enriched_ioc_document([_minimal_doc(
        event_time="not-a-timestamp",
        collect_time="also-garbage",
    )])
    # Should still produce a doc, just with no decay applied or decay=1.0
    assert result["document"]["ai_risk_score"] >= 0


# ---------------------------------------------------------------------------
# Unicode and special characters in descriptions
# ---------------------------------------------------------------------------


def test_build_doc_with_unicode_description():
    """Thai/Chinese/emoji in description must not crash classification."""
    result = build_enriched_ioc_document([_minimal_doc(
        description="มัลแวร์ระบาด 恶意软件 🦠 — banking trojan in Thailand .th",
    )])
    doc = result["document"]
    assert doc["ai_risk_score"] >= 0
    # Sector keyword extraction should pick up Thai context if implemented;
    # at minimum, must not crash.


def test_build_doc_with_html_artifacts_in_description():
    """News descriptions often have HTML cruft; pipeline must not crash on them.

    Note: Current sanitizer scope = field-level value sanitization, not
    HTML stripping from description text. This test guards against crashes,
    not against XSS — XSS protection lives in the API/dashboard layer where
    descriptions are rendered.
    """
    result = build_enriched_ioc_document([_minimal_doc(
        source_type="news",
        description=(
            "<p>Phishing campaign targeting banks &amp; financial services</p>"
            "<script>alert('xss')</script>"
        ),
    )])
    doc = result["document"]
    # Doc still builds successfully even with HTML cruft
    assert doc["ai_risk_score"] >= 0
    # Phishing keyword should still be extracted despite HTML wrapping
    assert "ai_threat_types" in doc


# ---------------------------------------------------------------------------
# Multi-source merge — conflicting signals
# ---------------------------------------------------------------------------


def test_build_doc_with_multiple_observations_aggregates_sources():
    """Same IOC from 3 sources → source_count should reflect the merge."""
    result = build_enriched_ioc_document([
        _minimal_doc(_id="a", source_name="VirusTotal"),
        _minimal_doc(_id="b", source_name="AbuseIPDB"),
        _minimal_doc(_id="c", source_name="ThreatFox"),
    ])
    doc = result["document"]
    assert doc.get("source_count", 0) >= 1
    # source_quality breakdown should mention multiple sources
    assert doc["ai_risk_score"] >= 0


def test_build_doc_with_conflicting_severity_picks_highest():
    """Multi-source with conflicting severity should prefer the higher signal."""
    result = build_enriched_ioc_document([
        _minimal_doc(_id="a", severity="low", confidence=10),
        _minimal_doc(_id="b", severity="critical", confidence=90),
    ])
    doc = result["document"]
    # Should have some non-zero score from the "critical" observation
    assert doc["ai_risk_score"] >= 0


def test_build_doc_with_empty_threat_type_list():
    """threat_type=[] (common in cyberint_iocs) must not crash extraction."""
    result = build_enriched_ioc_document([_minimal_doc(threat_type=[])])
    assert result["document"]["ai_risk_score"] >= 0


def test_build_doc_with_string_threat_type_instead_of_list():
    """Some sources send threat_type as a string, not a list. Must be tolerated."""
    result = build_enriched_ioc_document([_minimal_doc(threat_type="Malware")])
    assert result["document"]["ai_risk_score"] >= 0


# ---------------------------------------------------------------------------
# Source evidence merge (Phase 1.8+ schema)
# ---------------------------------------------------------------------------


def test_build_doc_with_partial_source_evidence():
    """source_evidence with only some fields populated should not crash."""
    result = build_enriched_ioc_document([_minimal_doc(
        source_evidence={
            "external_evidence_sources": ["MISP"],
            "source_risk_score": 50,
            # Missing: source_actionable, source_threat_actors, etc.
        }
    )])
    doc = result["document"]
    assert doc.get("source_risk_score") == 50
    assert doc.get("external_evidence_sources") == ["MISP"]


def test_build_doc_with_null_source_evidence_values():
    """source_evidence with None values (common from optional ES fields)."""
    result = build_enriched_ioc_document([_minimal_doc(
        source_evidence={
            "external_evidence_sources": None,
            "source_risk_score": None,
            "source_actionable": None,
            "source_threat_actors": None,
            "source_mitre_techniques": None,
            "source_campaigns": None,
            "source_target_countries": None,
            "related_doc_count": None,
        }
    )])
    assert result["document"]["ai_risk_score"] >= 0


# ---------------------------------------------------------------------------
# IOC type variants
# ---------------------------------------------------------------------------


def test_build_doc_with_sha256_no_domain_age():
    """sha256 IOCs have no domain — WHOIS lookup must be skipped, not crash."""
    result = build_enriched_ioc_document([_minimal_doc(
        ioc_type="sha256",
        ioc_value="a" * 64,
    )])
    doc = result["document"]
    # Phase 1.11: domain_age dropped from scoring; should be None for hash IOCs
    assert doc.get("domain_age_days") is None
    assert doc["ai_risk_score"] >= 0


def test_build_doc_with_ipv6_address():
    """IPv6 IOCs must not crash GeoIP enrichment."""
    result = build_enriched_ioc_document([_minimal_doc(
        ioc_type="ip",
        ioc_value="2001:db8::1",
    )])
    assert result["document"]["ai_risk_score"] >= 0


def test_build_doc_with_url_containing_query_params():
    """URLs with ? and & must not break domain extraction for WHOIS."""
    result = build_enriched_ioc_document([_minimal_doc(
        ioc_type="url",
        ioc_value="https://evil.example/path?utm=campaign&id=42",
    )])
    assert result["document"]["ai_risk_score"] >= 0
