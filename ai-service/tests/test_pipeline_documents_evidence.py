import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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

from utils.pipeline_documents import build_enriched_ioc_document  # noqa: E402


def test_source_evidence_is_merged_into_warehouse_doc_and_scoring_inputs():
    result = build_enriched_ioc_document([
        {
            "_id": "uuid-1",
            "_index": "misp_attributes-11052026",
            "adapter_name": "misp_attribute",
            "ioc_type": "domain",
            "ioc_value": "evil.example",
            "source_name": "Cyble Threat Intelligence Feed",
            "source_type": "misp",
            "description": "Cyble Threat Intelligence Feed - 2024-09-01",
            "threat_type": ["Phishing"],
            "severity": "low",
            "confidence": 80,
            "event_time": "2024-09-01T23:55:13.000000+00:00",
            "collect_time": "2026-05-11T06:31:54.276488+00:00",
            "source_evidence": {
                "external_evidence_sources": ["MISP"],
                "source_risk_score": 100,
                "source_actionable": True,
                "source_threat_actors": ["TeamTNT"],
                "source_mitre_techniques": ["T1587.001 Malware"],
                "source_campaigns": ["Campaign A"],
                "source_target_countries": ["DE"],
                "related_doc_count": 2,
            },
        }
    ])

    doc = result["document"]
    assert doc["source_risk_score"] == 100
    assert doc["source_actionable"] is True
    assert doc["external_evidence_sources"] == ["MISP"]
    assert doc["related_doc_count"] == 2
    assert doc["source_campaigns"] == ["Campaign A"]
    assert doc["source_target_countries"] == ["DE"]
    assert doc["ai_threat_types"] == ["Phishing"]
    assert doc["ai_threat_actors"] == ["TeamTNT"]
    assert doc["ai_mitre_techniques"] == ["T1587.001 Malware"]
    assert doc["source_count"] == 2


def test_vulnerability_news_uses_context_rule_without_ml():
    result = build_enriched_ioc_document([
        {
            "_id": "news-1",
            "_index": "tcti-feeds-thehackernews-16032026",
            "adapter_name": "legacy_external",
            "ioc_type": "ip",
            "ioc_value": "20.12.5.3",
            "source_name": "The Hacker News",
            "source_type": "news",
            "description": (
                "Cisco confirms active exploitation of CVE-2026-20122. "
                "The vulnerability can allow remote code execution and arbitrary commands."
            ),
            "threat_type": [],
            "severity": "high",
            "confidence": 0,
            "event_time": "2026-03-05T00:00:00+00:00",
            "collect_time": "2026-03-05T00:00:00+00:00",
        }
    ])

    doc = result["document"]
    assert doc["classification_mode"] == "source_rule"
    assert doc["classification_reason"] == "context_rule_threat_metadata"
    assert doc["ai_threat_types"] == ["Remote Code Execution", "Exploited Vulnerability"]


def test_raw_source_threat_types_are_mapped_before_ai_threat_types():
    result = build_enriched_ioc_document([
        {
            "_id": "hash-1",
            "_index": "tcti-feeds",
            "adapter_name": "existing_canonical",
            "ioc_type": "sha256",
            "ioc_value": "a" * 64,
            "source_name": "tcti-feeds",
            "source_type": "customer-datalake",
            "description": "Recognized as Malicious.",
            "threat_type": ["malware_payload"],
            "severity": "critical",
            "confidence": 80,
            "event_time": "2025-03-10T22:33:39+00:00",
            "collect_time": "2025-11-11T10:27:31+00:00",
        }
    ])

    doc = result["document"]
    assert doc["classification_mode"] == "source_rule"
    assert doc["ai_threat_types"] == ["Malware"]
    assert "malware_payload" not in doc["ai_threat_types"]


def test_enrichment_souce_is_added_as_cross_source():
    """enrichment.souce ('Virustotal'/'Cyberint') should appear as an extra scoring source."""
    result = build_enriched_ioc_document([
        {
            "_id": "cyb-1",
            "_index": "cyberint_iocs-20260520",
            "adapter_name": "cyberint_iocs",
            "ioc_type": "domain",
            "ioc_value": "evil-bank.com",
            "source_name": "cyberint_iocs",
            "source_type": "customer-datalake",
            "description": "Phishing domain targeting banking customers",
            "threat_type": ["phishing"],
            "severity": "",
            "confidence": 60,
            "event_time": "2026-05-19T00:00:00+00:00",
            "collect_time": "2026-05-20T00:00:00+00:00",
            "enrichment": {
                "souce": "Virustotal",
                "whois": {
                    "creation_date": "2026-05-10T00:00:00Z",
                    "registrar": "Namecheap",
                },
            },
        }
    ])

    doc = result["document"]
    # Virustotal should appear as an additional source from enrichment
    assert "Virustotal" in doc["sources"]
    assert doc["source_count"] >= 2
    # Score breakdown should reflect the cross-source enrichment
    breakdown = doc.get("ai_score_breakdown", {})
    cross_source = breakdown.get("cross_source", {})
    assert cross_source.get("count", 0) >= 2
    assert "Virustotal" in cross_source.get("sources_found", [])


def test_enrichment_whois_domain_age_feeds_scorer():
    """When domain_age_days is None, WHOIS creation_date should be used for scoring."""
    result = build_enriched_ioc_document([
        {
            "_id": "zh-1",
            "_index": "tcti-feeds-zone-h",
            "adapter_name": "legacy_external",
            "ioc_type": "domain",
            "ioc_value": "defaced-site.th",
            "source_name": "Zone-H",
            "source_type": "news",
            "description": "Zone-H mirror shows a defaced website",
            "threat_type": [],
            "severity": "low",
            "confidence": 0,
            "event_time": "2026-01-01T00:00:00+00:00",
            "collect_time": "2026-01-01T00:00:00+00:00",
            "enrichment": {
                "souce": "Virustotal",
                "whois": {
                    "creation_date": "2020-06-15T00:00:00Z",
                },
            },
        }
    ])

    doc = result["document"]
    # Domain age should flow into the score breakdown even though weight is 0%
    breakdown = doc.get("ai_score_breakdown", {})
    domain_age = breakdown.get("domain_age", {})
    # The scorer received a real domain_age_days value from WHOIS
    assert domain_age.get("days") is not None
    assert domain_age["days"] > 1800


def _make_domain_doc_with_whois_field(field_name: str, date_value: str) -> dict:
    return {
        "_id": "w-1",
        "_index": "enrichment-idx",
        "adapter_name": "legacy_external",
        "ioc_type": "domain",
        "ioc_value": "test.example.com",
        "source_name": "TestFeed",
        "source_type": "external-feed",
        "description": "test",
        "threat_type": [],
        "severity": "",
        "confidence": 0,
        "event_time": "2026-01-01T00:00:00+00:00",
        "collect_time": "2026-01-01T00:00:00+00:00",
        "enrichment": {"whois": {field_name: date_value}},
    }


def test_whois_create_date_variant_feeds_domain_age():
    """create_date (WHOIS/ARIN format) should be used when creation_date is absent."""
    result = build_enriched_ioc_document([
        _make_domain_doc_with_whois_field("create_date", "2019-03-10T00:00:00Z"),
    ])
    days = result["document"].get("ai_score_breakdown", {}).get("domain_age", {}).get("days")
    assert days is not None and days > 2000


def test_whois_created_variant_feeds_domain_age():
    """created (RIPE/ARIN text format) should be used when other date fields are absent."""
    result = build_enriched_ioc_document([
        _make_domain_doc_with_whois_field("created", "2021-07-01T00:00:00Z"),
    ])
    days = result["document"].get("ai_score_breakdown", {}).get("domain_age", {}).get("days")
    assert days is not None and days > 500


def test_whois_regdate_variant_feeds_domain_age():
    """regdate (ARIN format) should be parsed for domain age."""
    result = build_enriched_ioc_document([
        _make_domain_doc_with_whois_field("regdate", "2023-01-15"),
    ])
    days = result["document"].get("ai_score_breakdown", {}).get("domain_age", {}).get("days")
    assert days is not None and days > 100


def test_whois_registered_on_variant_feeds_domain_age():
    """registered_on format should also be parsed."""
    result = build_enriched_ioc_document([
        _make_domain_doc_with_whois_field("registered_on", "2022-11-20T00:00:00Z"),
    ])
    days = result["document"].get("ai_score_breakdown", {}).get("domain_age", {}).get("days")
    assert days is not None and days > 100
