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
