import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import elastic_client  # noqa: E402
from elastic_client import ElasticClient  # noqa: E402


def _client_without_init():
    client = ElasticClient.__new__(ElasticClient)
    client.datalake_index = "tcti-feeds"
    client.warehouse_index = "cyber-logs-datawarehouse"
    return client


def test_processed_state_id_uses_source_record_identity():
    first = ElasticClient._build_processed_state_id({
        "_index": "tcti-feeds",
        "_id": "abc-123",
        "ioc_type": "ip",
        "ioc_value": "1.2.3[.]4",
    })
    second = ElasticClient._build_processed_state_id({
        "_index": "other-feed",
        "_id": "different-source-doc",
        "ioc_type": "ip_addresses",
        "ioc_value": "1.2.3.4",
    })
    same_source_doc = ElasticClient._build_processed_state_id({
        "_index": "tcti-feeds",
        "_id": "abc-123",
        "ioc_type": "ip",
        "ioc_value": "9.9.9.9",
    })
    other_source_doc = ElasticClient._build_processed_state_id({
        "_index": "tcti-feeds",
        "_id": "xyz-789",
        "ioc_type": "ip",
        "ioc_value": "1.2.3.4",
    })

    assert first != second
    assert first == same_source_doc
    assert first != other_source_doc
    assert first.startswith("src:")


def test_canonical_ioc_normalization():
    assert ElasticClient.normalize_ioc_type("ip_addresses") == "ip"
    assert ElasticClient.normalize_ioc_type("SHA-256") == "sha256"
    assert ElasticClient.normalize_ioc_value("hxxps://evil[.]example/a b") == "https://evil.example/ab"
    assert ElasticClient.canonical_ioc_key({
        "ioc_type": "ip_addresses",
        "ioc_value": "12.2.1[.]4",
    }) == "ip:12.2.1.4"


def test_normalize_external_hit_adds_canonical_fields():
    doc = ElasticClient._normalize_datalake_hit({
        "_index": "tcti-feeds",
        "_id": "doc-1",
        "_source": {
            "ioc": {"type": "ip_addresses", "value": "12.2.1[.]4"},
            "source": [{"name": "DarkReading", "description": "test"}],
        },
    })

    assert doc["ioc_type"] == "ip"
    assert doc["ioc_value"] == "12.2.1.4"
    assert doc["original_ioc_type"] == "ip_addresses"
    assert doc["original_ioc_value"] == "12.2.1[.]4"
    assert doc["canonical_ioc_key"] == "ip:12.2.1.4"
    assert doc["adapter_name"] == "legacy_external"
    assert doc["adapter_status"] == "normalized"


def test_normalize_cyberint_iocs_hit():
    doc = ElasticClient._normalize_datalake_hit({
        "_index": "cyberint_iocs-2025.09.01",
        "_id": "hash-1",
        "_source": {
            "id": "hash-1",
            "detected_activity": "malware_payload",
            "ioc_type": "file/sha256",
            "ioc_value": "ABCDEF",
            "observation_date": "2025-03-10T22:33:39+00:00",
            "severity_score": "100",
            "confidence": "80",
            "description": "Recognized as Malicious.",
            "@timestamp": "2025-11-11T10:27:31.738512+00:00",
        },
    })

    assert doc["adapter_name"] == "cyberint_iocs"
    assert doc["adapter_status"] == "normalized"
    assert doc["ioc_type"] == "sha256"
    assert doc["ioc_value"] == "abcdef"
    assert doc["severity"] == "critical"
    assert doc["confidence"] == 80
    assert doc["event_time"] == "2025-03-10T22:33:39+00:00"
    assert "malware payload" in doc["description"]


def test_normalize_misp_attribute_hit():
    doc = ElasticClient._normalize_datalake_hit({
        "_index": "misp_attributes-11052026",
        "_id": "uuid-1",
        "_source": {
            "uuid": "uuid-1",
            "type": "domain",
            "value": "Example[.]Com",
            "first_seen": "2024-09-01T23:55:13.000000+00:00",
            "Event": {
                "info": "Cyble Threat Intelligence Feed - 2024-09-01",
                "Orgc": {"name": "Cyble Threat Intelligence Feed"},
                "ThreatLevel": {"name": "Low"},
            },
            "Tag": [
                {"name": "behaviour-tag=\"Phishing\""},
                {"name": "confidence:high"},
                {"name": "risk-score:100"},
                {"name": "misp-galaxy:threat-actor=\"TeamTNT\""},
                {"name": "misp-galaxy:sector=\"Aerospace & Defense\""},
                {"name": "misp-galaxy:target-information=\"DE\""},
            ],
            "to_ids": True,
            "@timestamp": "2026-05-11T06:31:54.276488+00:00",
        },
    })

    assert doc["adapter_name"] == "misp_attribute"
    assert doc["adapter_status"] == "normalized"
    assert doc["ioc_type"] == "domain"
    assert doc["ioc_value"] == "example.com"
    assert doc["source_name"] == "Cyble Threat Intelligence Feed"
    assert doc["severity"] == "low"
    assert doc["confidence"] == 80
    assert doc["threat_type"] == ["Phishing"]
    assert doc["source_risk_score"] == 100
    assert doc["source_actionable"] is True
    assert doc["source_evidence"]["source_threat_actors"] == ["TeamTNT"]
    assert doc["source_evidence"]["source_target_countries"] == ["DE"]


def test_legacy_external_extracts_virustotal_and_correlation_evidence():
    doc = ElasticClient._normalize_datalake_hit({
        "_index": "tcti-feeds-bleeping-12032026",
        "_id": "doc-1",
        "_source": {
            "doc_hash": "doc-1",
            "ioc": {"type": "domain", "value": "evil[.]example"},
            "source": [{"name": "BleepingComputer News", "description": "Long report text"}],
            "confidence": 0,
            "enrichment": {
                "virustotal": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 3,
                            "suspicious": 1,
                            "harmless": 55,
                            "undetected": 33,
                        },
                        "reputation": -5,
                        "meaningful_name": "evil.example",
                    }
                },
                "mitre": {
                    "external_id": "T1587.001",
                    "name": "Malware",
                    "tactics": ["resource-development"],
                },
                "summary": {
                    "actor_groups": ["FIN7"],
                    "campaign_names": ["Test Campaign"],
                    "countries": ["US"],
                },
            },
            "correlations": {
                "related_docs": [
                    {"original_ioc": "cve-2026-0001", "type": "cve"},
                    {"original_ioc": "other.example", "type": "domain"},
                ]
            },
        },
    })

    assert doc["adapter_name"] == "legacy_external"
    assert doc["external_evidence_sources"] == ["VirusTotal"]
    assert doc["virustotal_malicious"] == 3
    assert doc["virustotal_suspicious"] == 1
    assert doc["related_doc_count"] == 2
    assert doc["source_evidence"]["source_threat_actors"] == ["FIN7"]
    assert doc["source_evidence"]["source_campaigns"] == ["Test Campaign"]
    assert doc["source_evidence"]["source_target_countries"] == ["US"]
    assert doc["source_evidence"]["source_mitre_techniques"] == ["T1587.001 Malware"]


def test_legacy_external_extracts_sandbox_evidence():
    doc = ElasticClient._normalize_datalake_hit({
        "_index": "tcti-feeds-sandbox-26032026",
        "_id": "sandbox-1",
        "_source": {
            "ioc": {"type": "sha256", "value": "ABCDEF"},
            "source": [{"name": "Sandbox", "description": "Sandbox detonated sample"}],
            "confidence": 70,
            "malware_family": "AgentTesla",
            "verdict": "malicious",
            "suspicious_activities": ["Creates autorun key"],
        },
    })

    assert doc["source_malware_family"] == "AgentTesla"
    assert doc["external_evidence_sources"] == ["Sandbox"]
    assert doc["threat_type"] == ["AgentTesla"]
    assert doc["source_evidence"]["sandbox_verdict"] == "malicious"


def test_unknown_datalake_hit_is_quarantined():
    doc = ElasticClient._normalize_datalake_hit({
        "_index": "unknown-source",
        "_id": "doc-1",
        "_source": {"unexpected": "shape"},
    })

    assert doc["adapter_status"] == "quarantined"
    assert doc["quarantine_reason"] == "unsupported_datalake_schema"
    assert doc["raw_keys"] == ["unexpected"]


def test_readonly_feed_filters_docs_already_marked_processed(monkeypatch):
    client = _client_without_init()
    monkeypatch.setattr(elastic_client, "DATALAKE_SCAN_BATCH_SIZE", 2)
    monkeypatch.setattr(elastic_client, "DATALAKE_SCAN_MAX_PAGES", 2)

    pages = [
        {
            "hits": {
                "hits": [
                    {"_index": "tcti-feeds", "_id": "done", "_source": {"ioc": {"type": "domain", "value": "done.example"}}},
                    {"_index": "tcti-feeds", "_id": "new", "_source": {"ioc": {"type": "domain", "value": "new.example"}}},
                ]
            }
        }
    ]

    def fake_search(index, body):
        assert index == "tcti-feeds"
        return pages.pop(0) if pages else {"hits": {"hits": []}}

    monkeypatch.setattr(client, "_search_index", fake_search)
    monkeypatch.setattr(client, "is_source_processed", lambda doc: doc["_id"] == "done")

    result = client._get_unprocessed_iocs_from_readonly_feed(limit=1)

    assert [doc["_id"] for doc in result] == ["new"]


def test_processed_status_only_skips_finished_docs(monkeypatch):
    client = _client_without_init()

    monkeypatch.setattr(client, "_get_processed_state", lambda doc: {"status": "processed"})
    assert client.is_source_processed({"_id": "done"})

    monkeypatch.setattr(client, "_get_processed_state", lambda doc: {"status": "rejected"})
    assert client.is_source_processed({"_id": "rejected"})

    monkeypatch.setattr(client, "_get_processed_state", lambda doc: {"status": "failed"})
    assert not client.is_source_processed({"_id": "failed"})
