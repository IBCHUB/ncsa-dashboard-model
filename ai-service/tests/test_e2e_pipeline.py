"""
E2E Pipeline Tests

Validates the full data flow:
  source JSON -> normalize_ioc() -> datalake doc -> build_enriched_ioc_document() -> warehouse doc

Tests verify that critical data is preserved through each pipeline stage.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.ops.import_to_datalake import normalize_ioc  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_raw_event(**overrides):
    """Build a minimal raw event dict with sensible defaults."""
    base = {
        "ioc": {"value": "evil.example.com", "type": "domain"},
        "source_name": "TestSource",
        "source_type": "feed",
        "description": "Test IOC event",
        "threat_type": ["Phishing"],
        "severity": "medium",
        "tags": ["test"],
        "reference": "https://ref.example.com",
        "collect_time": "2025-01-15T12:00:00Z",
        "event_time": "2025-01-14T08:00:00Z",
        "geo_info": {},
        "confidence": 0,
        "source_url": "",
        "source_id": "",
    }
    for key, value in overrides.items():
        if key == "ioc_extra":
            base["ioc"] = {**base["ioc"], **value}
        else:
            base[key] = value
    return base


MOCK_CLASSIFICATION = {
    "threat_types": ["Ransomware"],
    "confidence": 0.85,
    "labels": ["ransomware"],
    "scores": [0.85],
    "threat_details": [{"type": "Ransomware", "confidence": 0.85}],
}

MOCK_SCORE_RESULT = {
    "risk_score": 65,
    "severity": "high",
    "severity_th": "สูง",
    "breakdown": {},
    "top_factors": [],
    "score_model_version": "test",
    "score_config_version": "test",
    "credibility_score": 50,
    "impact_score": 60,
}

MOCK_VALIDATION = {
    "validation_status": "validated",
    "validation_reasons": [],
    "warehouse_eligible": True,
    "review_required": False,
}

_PIPELINE_MODULE = "utils.pipeline_documents"


# ---------------------------------------------------------------------------
# Test 1 – enrichment blob preserved
# ---------------------------------------------------------------------------

def test_normalize_ioc_preserves_enrichment():
    raw = _make_raw_event(
        enrichment={
            "whois": {"registrar": "Example Registrar"},
            "ip_info": {"asn": "AS1234", "country": "US"},
        },
    )
    result = normalize_ioc(raw)

    assert isinstance(result["enrichment"], dict)
    assert result["enrichment"] is not None
    assert result["enrichment"]["whois"]["registrar"] == "Example Registrar"
    assert result["enrichment"]["ip_info"]["asn"] == "AS1234"


# ---------------------------------------------------------------------------
# Test 2 – confidence preserved
# ---------------------------------------------------------------------------

def test_normalize_ioc_preserves_confidence():
    raw = _make_raw_event(confidence=75)
    result = normalize_ioc(raw)

    assert result["confidence"] == 75


# ---------------------------------------------------------------------------
# Test 3 – source_url preserved
# ---------------------------------------------------------------------------

def test_normalize_ioc_preserves_source_url():
    raw = _make_raw_event(source_url="https://example.com/report")
    result = normalize_ioc(raw)

    assert result["source_url"] == "https://example.com/report"


# ---------------------------------------------------------------------------
# Test 4 – domain age computed from enrichment
# ---------------------------------------------------------------------------

def test_normalize_ioc_computes_domain_age():
    raw = _make_raw_event(
        enrichment={
            "whois": {"creation_date": "2020-01-01T00:00:00Z"},
        },
    )
    result = normalize_ioc(raw)

    assert result["domain_age_days"] is not None
    assert result["domain_age_days"] > 2000


# ---------------------------------------------------------------------------
# Test 5 – missing enrichment handled gracefully
# ---------------------------------------------------------------------------

def test_normalize_ioc_handles_missing_enrichment():
    base = {
        "ioc": {"value": "bare.example.com", "type": "domain"},
        "source_name": "TestSource",
        "source_type": "feed",
        "description": "Bare event",
        "threat_type": [],
        "severity": "low",
        "tags": [],
        "reference": "",
        "collect_time": "2025-01-15T12:00:00Z",
        "event_time": "2025-01-14T08:00:00Z",
        "geo_info": {},
    }
    result = normalize_ioc(base)

    assert result["enrichment"] == {}
    assert result["domain_age_days"] is None
    assert result["confidence"] == 0


# ---------------------------------------------------------------------------
# Test 6 – geo_country falls back to enrichment.ip_info
# ---------------------------------------------------------------------------

def test_normalize_ioc_geo_country_fallback():
    raw = _make_raw_event(
        geo_info={},
        enrichment={
            "ip_info": {"country": "TH"},
        },
    )
    result = normalize_ioc(raw)

    assert result["geo_country"] == "TH"


# ---------------------------------------------------------------------------
# Test 7 – related IOC fields preserved
# ---------------------------------------------------------------------------

def test_normalize_ioc_preserves_related_iocs():
    raw = _make_raw_event(
        ioc_extra={"related_hash": "abc123", "related_domain": "evil.com"},
    )
    result = normalize_ioc(raw)

    assert result["related_hash"] == "abc123"
    assert result["related_domain"] == "evil.com"


# ---------------------------------------------------------------------------
# Test 8 – source_urls collected across observations
# ---------------------------------------------------------------------------

@patch(f"{_PIPELINE_MODULE}.evaluate_validation_status", return_value=MOCK_VALIDATION)
@patch(f"{_PIPELINE_MODULE}.calculate_risk_score", return_value=MOCK_SCORE_RESULT)
@patch(f"{_PIPELINE_MODULE}.extract_mitre_techniques", return_value=[])
@patch(f"{_PIPELINE_MODULE}.extract_threat_actors", return_value=[])
@patch(f"{_PIPELINE_MODULE}.classify_threat", return_value=MOCK_CLASSIFICATION)
def test_pipeline_source_urls_collected(
    _mock_classify,
    _mock_actors,
    _mock_mitre,
    _mock_score,
    _mock_validate,
):
    from utils.pipeline_documents import build_enriched_ioc_document

    doc1 = normalize_ioc(_make_raw_event(source_url="https://feed-a.example.com/1"))
    doc2 = normalize_ioc(_make_raw_event(
        source_url="https://feed-b.example.com/2",
        source_name="AnotherSource",
    ))

    result = build_enriched_ioc_document([doc1, doc2])

    assert "https://feed-a.example.com/1" in result["document"]["source_urls"]
    assert "https://feed-b.example.com/2" in result["document"]["source_urls"]


# ---------------------------------------------------------------------------
# Test 9 – domain_age_days forwarded to scorer
# ---------------------------------------------------------------------------

@patch(f"{_PIPELINE_MODULE}.evaluate_validation_status", return_value=MOCK_VALIDATION)
@patch(f"{_PIPELINE_MODULE}.calculate_risk_score", return_value=MOCK_SCORE_RESULT)
@patch(f"{_PIPELINE_MODULE}.extract_mitre_techniques", return_value=[])
@patch(f"{_PIPELINE_MODULE}.extract_threat_actors", return_value=[])
@patch(f"{_PIPELINE_MODULE}.classify_threat", return_value=MOCK_CLASSIFICATION)
def test_pipeline_domain_age_passed_to_scorer(
    _mock_classify,
    _mock_actors,
    _mock_mitre,
    mock_score,
    _mock_validate,
):
    from utils.pipeline_documents import build_enriched_ioc_document

    doc = normalize_ioc(_make_raw_event(
        enrichment={"whois": {"creation_date": "2025-11-24T00:00:00Z"}},
    ))
    doc["domain_age_days"] = 30

    build_enriched_ioc_document([doc])

    mock_score.assert_called_once()
    call_kwargs = mock_score.call_args
    assert call_kwargs.kwargs.get("domain_age_days") == 30 or (
        len(call_kwargs.args) > 4 and call_kwargs.args[4] == 30
    )
