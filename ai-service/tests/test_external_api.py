import json
import os
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import services.dashboard_router as dashboard_router  # noqa: E402
import services.external_sharing_router as external_sharing_router  # noqa: E402
from services.external_sharing_bootstrap import reset_external_state  # noqa: E402
from test_support.dashboard_fake_backend import FakeElasticClient  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    fake_client = FakeElasticClient()
    partner_registry = [
        {
            "api_key": "reader-key",
            "partner_id": "partner-reader",
            "partner_name": "Reader Partner",
            "permissions": ["read_feed"],
            "max_tlp": "amber",
            "allowed_ioc_types": ["domain", "ip", "url", "hash", "cve"],
            "allowed_formats": ["json"],
            "rate_limit": 60,
        },
        {
            "api_key": "writer-key",
            "partner_id": "partner-writer",
            "partner_name": "Writer Partner",
            "permissions": ["read_feed", "submit_data", "export_feed"],
            "max_tlp": "amber",
            "allowed_ioc_types": ["domain", "ip", "url", "hash", "cve"],
            "allowed_formats": ["json", "csv", "plain_text", "suricata", "snort"],
            "rate_limit": 120,
        },
    ]
    monkeypatch.setenv("EXTERNAL_PARTNER_REGISTRY_JSON", json.dumps(partner_registry))
    reset_external_state()
    monkeypatch.setattr(dashboard_router, "get_elastic_client", lambda: fake_client)
    monkeypatch.setattr(external_sharing_router, "get_elastic_client", lambda: fake_client)
    app = FastAPI()
    app.include_router(external_sharing_router.router)
    with TestClient(app) as test_client:
        yield test_client, fake_client
    reset_external_state()


def _reader_headers():
    return {"X-API-Key": "reader-key"}


def _writer_headers():
    return {"X-API-Key": "writer-key"}


def _assert_success_envelope(response):
    assert response.headers["content-type"].startswith("application/json")
    payload = response.json()
    assert "data" in payload
    assert "meta" in payload
    assert "error" in payload
    assert payload["error"] is None
    return payload


def test_external_authentication_and_partner_permissions(client):
    test_client, _ = client

    missing = test_client.get("/api/v1/external/profile")
    assert missing.status_code == 401
    assert missing.json()["detail"] == "Missing API Key. Include 'X-API-Key' header."

    invalid = test_client.get("/api/v1/external/profile", headers={"X-API-Key": "nope"})
    assert invalid.status_code == 403
    assert invalid.json()["detail"] == "Invalid API Key."

    profile = test_client.get("/api/v1/external/profile", headers=_reader_headers())
    assert profile.status_code == 200
    profile_payload = _assert_success_envelope(profile)["data"]
    assert profile_payload["partner_id"] == "partner-reader"
    assert "api_key" not in profile_payload

    reader_export_formats = test_client.get("/api/v1/external/lookups/export-formats", headers=_reader_headers())
    assert reader_export_formats.status_code == 403
    assert "export_feed" in reader_export_formats.json()["detail"]

    reader_submit = test_client.post(
        "/api/v1/external/indicators",
        headers=_reader_headers(),
        json={"ioc_value": "blocked.example", "ioc_type": "domain", "title": "Should fail"},
    )
    assert reader_submit.status_code == 403
    assert "submit_data" in reader_submit.json()["detail"]


@pytest.mark.parametrize(
    ("path", "headers", "expected_values"),
    [
        ("/api/v1/external/lookups/ioc-types", _reader_headers(), {"domain", "ip", "url"}),
        ("/api/v1/external/lookups/threat-types", _reader_headers(), {"Phishing", "Malware"}),
        ("/api/v1/external/lookups/severities", _reader_headers(), {"critical", "high", "medium", "low", "clean"}),
        ("/api/v1/external/lookups/tlp-levels", _reader_headers(), {"clear", "green", "amber", "red"}),
        ("/api/v1/external/lookups/export-formats", _writer_headers(), {"json", "csv", "plain_text", "suricata", "snort"}),
    ],
)
def test_external_lookup_endpoints(client, path, headers, expected_values):
    test_client, _ = client

    response = test_client.get(path, headers=headers)
    assert response.status_code == 200
    items = _assert_success_envelope(response)["data"]["items"]
    assert {item["value"] for item in items} >= expected_values


def test_external_changes_endpoint_filters_and_cursor_variants(client):
    test_client, _ = client

    changes = test_client.get("/api/v1/external/changes?page_size=10", headers=_reader_headers())
    assert changes.status_code == 200
    payload = _assert_success_envelope(changes)
    created_ids = {item["indicator"]["indicator_id"] for item in payload["data"]["created"]}
    updated_ids = {item["indicator"]["indicator_id"] for item in payload["data"]["updated"]}
    all_ids = created_ids | updated_ids
    assert "domain::malicious.example" in all_ids
    assert "ip::185.10.10.10" in all_ids
    assert "domain::top-secret.example" not in all_ids
    assert "domain::suspicious-review.example" not in all_ids
    assert payload["meta"]["next_cursor"]

    tlp_filtered = test_client.get("/api/v1/external/changes?tlp=green", headers=_reader_headers())
    assert tlp_filtered.status_code == 200
    tlp_ids = {
        item["indicator"]["indicator_id"]
        for bucket in ("created", "updated", "revoked")
        for item in tlp_filtered.json()["data"][bucket]
    }
    assert tlp_ids == {"ip::185.10.10.10"}

    threat_filtered = test_client.get("/api/v1/external/changes?threat_types=Malware", headers=_reader_headers())
    assert threat_filtered.status_code == 200
    threat_ids = {
        item["indicator"]["indicator_id"]
        for bucket in ("created", "updated", "revoked")
        for item in threat_filtered.json()["data"][bucket]
    }
    assert threat_ids == {"ip::185.10.10.10"}

    severity_filtered = test_client.get("/api/v1/external/changes?severities=critical", headers=_reader_headers())
    assert severity_filtered.status_code == 200
    severity_ids = {
        item["indicator"]["indicator_id"]
        for bucket in ("created", "updated", "revoked")
        for item in severity_filtered.json()["data"][bucket]
    }
    assert severity_ids == {"domain::malicious.example"}

    ioc_type_filtered = test_client.get("/api/v1/external/changes?ioc_types=domain", headers=_reader_headers())
    assert ioc_type_filtered.status_code == 200
    type_ids = {
        item["indicator"]["indicator_id"]
        for bucket in ("created", "updated", "revoked")
        for item in ioc_type_filtered.json()["data"][bucket]
    }
    assert type_ids == {"domain::malicious.example"}

    future_since = test_client.get("/api/v1/external/changes?since=2099-01-01T00:00:00Z", headers=_reader_headers())
    assert future_since.status_code == 200
    assert future_since.json()["data"] == {"created": [], "updated": [], "revoked": []}
    assert future_since.json()["meta"]["next_cursor"] == "2099-01-01T00:00:00Z"

    future_updated = test_client.get(
        "/api/v1/external/changes?updated_after=2099-01-01T00:00:00Z",
        headers=_reader_headers(),
    )
    assert future_updated.status_code == 200
    assert future_updated.json()["data"] == {"created": [], "updated": [], "revoked": []}

    invalid_page_size = test_client.get("/api/v1/external/changes?page_size=0", headers=_reader_headers())
    assert invalid_page_size.status_code == 422


def test_external_indicators_list_detail_observations_and_relationships(client):
    test_client, _ = client

    indicators = test_client.get("/api/v1/external/indicators?page=1&page_size=10", headers=_reader_headers())
    assert indicators.status_code == 200
    indicator_payload = _assert_success_envelope(indicators)
    items = indicator_payload["data"]["items"]
    assert len(items) >= 2
    assert all(item["tlp"] in {"green", "amber"} for item in items)
    assert indicator_payload["meta"]["page"] == 1
    assert indicator_payload["meta"]["page_size"] == 10

    search_filtered = test_client.get(
        "/api/v1/external/indicators?query=malicious&page=1&page_size=10",
        headers=_reader_headers(),
    )
    assert search_filtered.status_code == 200
    search_items = search_filtered.json()["data"]["items"]
    assert [item["indicator_id"] for item in search_items] == ["domain::malicious.example"]

    tlp_filtered = test_client.get("/api/v1/external/indicators?tlp=green", headers=_reader_headers())
    assert tlp_filtered.status_code == 200
    assert [item["indicator_id"] for item in tlp_filtered.json()["data"]["items"]] == ["ip::185.10.10.10"]

    risk_filtered = test_client.get("/api/v1/external/indicators?min_risk_score=90", headers=_reader_headers())
    assert risk_filtered.status_code == 200
    assert [item["indicator_id"] for item in risk_filtered.json()["data"]["items"]] == ["domain::malicious.example"]

    type_filtered = test_client.get("/api/v1/external/indicators?ioc_types=ip", headers=_reader_headers())
    assert type_filtered.status_code == 200
    assert [item["indicator_id"] for item in type_filtered.json()["data"]["items"]] == ["ip::185.10.10.10"]

    threat_filtered = test_client.get("/api/v1/external/indicators?threat_types=Malware", headers=_reader_headers())
    assert threat_filtered.status_code == 200
    assert [item["indicator_id"] for item in threat_filtered.json()["data"]["items"]] == ["ip::185.10.10.10"]

    severity_filtered = test_client.get("/api/v1/external/indicators?severities=critical", headers=_reader_headers())
    assert severity_filtered.status_code == 200
    assert [item["indicator_id"] for item in severity_filtered.json()["data"]["items"]] == ["domain::malicious.example"]

    paged = test_client.get("/api/v1/external/indicators?page=2&page_size=1", headers=_reader_headers())
    assert paged.status_code == 200
    assert paged.json()["meta"]["page"] == 2
    assert len(paged.json()["data"]["items"]) == 1

    detail = test_client.get("/api/v1/external/indicators/domain::malicious.example", headers=_reader_headers())
    assert detail.status_code == 200
    detail_payload = _assert_success_envelope(detail)["data"]
    assert detail_payload["indicator_id"] == "domain::malicious.example"
    assert detail_payload["sharing_status"] == "active"

    observations = test_client.get(
        "/api/v1/external/indicators/domain::malicious.example/observations?page=1&page_size=1",
        headers=_reader_headers(),
    )
    assert observations.status_code == 200
    observation_payload = _assert_success_envelope(observations)
    assert observation_payload["meta"]["page"] == 1
    assert observation_payload["meta"]["page_size"] == 1
    observation = observation_payload["data"]["items"][0]
    assert observation["source_name"] == "AbuseIPDB"
    assert "registrant_email" not in json.dumps(observations.json())
    assert "target_ip" not in json.dumps(observations.json())

    relationships = test_client.get(
        "/api/v1/external/indicators/domain::malicious.example/relationships",
        headers=_reader_headers(),
    )
    assert relationships.status_code == 200
    relationships_payload = _assert_success_envelope(relationships)["data"]
    assert "graph_summary" in relationships_payload
    assert "related_indicators" in relationships_payload

    invalid_indicator = test_client.get("/api/v1/external/indicators/not-a-valid-id", headers=_reader_headers())
    assert invalid_indicator.status_code == 400

    invalid_observations = test_client.get(
        "/api/v1/external/indicators/not-a-valid-id/observations",
        headers=_reader_headers(),
    )
    assert invalid_observations.status_code == 400

    invalid_relationships = test_client.get(
        "/api/v1/external/indicators/not-a-valid-id/relationships",
        headers=_reader_headers(),
    )
    assert invalid_relationships.status_code == 400

    hidden_indicator = test_client.get("/api/v1/external/indicators/domain::top-secret.example", headers=_reader_headers())
    assert hidden_indicator.status_code == 404

    missing_indicator = test_client.get("/api/v1/external/indicators/domain::missing.example", headers=_reader_headers())
    assert missing_indicator.status_code == 404

    invalid_page = test_client.get("/api/v1/external/indicators?page=0", headers=_reader_headers())
    assert invalid_page.status_code == 422


def test_external_submission_indicator_event_bulk_and_status_flows(client):
    test_client, fake_client = client

    indicator_submission = test_client.post(
        "/api/v1/external/indicators",
        headers=_writer_headers(),
        json={
            "ioc_value": "new-submit.example",
            "ioc_type": "domain",
            "title": "Partner phishing domain",
            "description": "Phishing infrastructure shared by partner",
            "threat_types": ["Phishing"],
            "severity": "high",
            "confidence": 85,
            "tlp": "green",
            "references": ["https://partner.example/report/1"],
            "observed_at": "2026-03-12T01:00:00Z",
        },
    )
    assert indicator_submission.status_code == 200
    indicator_payload = _assert_success_envelope(indicator_submission)["data"]
    assert indicator_payload["status"] == "accepted"
    assert indicator_payload["normalized_indicator_ids"] == ["domain::new-submit.example"]

    event_submission = test_client.post(
        "/api/v1/external/events",
        headers=_writer_headers(),
        json={
            "event_type": "incident_report",
            "title": "Partner observed multiple indicators",
            "description": "Callback and phishing indicators observed in same case",
            "severity": "critical",
            "confidence": 90,
            "tlp": "amber",
            "observed_at": "2026-03-12T02:00:00Z",
            "indicators": [
                {"ioc_value": "203.0.113.200", "ioc_type": "ip"},
                {"ioc_value": "https://evil.example/login", "ioc_type": "url"},
            ],
            "references": ["https://partner.example/report/2"],
        },
    )
    assert event_submission.status_code == 200
    event_payload = _assert_success_envelope(event_submission)["data"]
    assert event_payload["accepted_count"] == 2
    assert event_payload["status"] == "accepted"

    bulk_submission = test_client.post(
        "/api/v1/external/bulk",
        headers=_writer_headers(),
        json={
            "default_tlp": "amber",
            "dedupe_strategy": "indicator_id",
            "items": [
                {
                    "kind": "indicator",
                    "ioc_value": "bulk-ip.example",
                    "ioc_type": "domain",
                    "description": "Bulk IOC",
                    "severity": "medium",
                    "confidence": 70,
                },
                {
                    "kind": "indicator",
                    "ioc_value": "bulk-ip.example",
                    "ioc_type": "domain",
                    "description": "Bulk IOC duplicate",
                    "severity": "medium",
                    "confidence": 70,
                },
                {
                    "kind": "event",
                    "event_type": "bulk_event",
                    "description": "Bulk event IOC",
                    "severity": "high",
                    "confidence": 80,
                    "indicators": [
                        {"ioc_value": "198.51.100.11", "ioc_type": "ip"},
                    ],
                },
            ],
        },
    )
    assert bulk_submission.status_code == 200
    bulk_payload = _assert_success_envelope(bulk_submission)["data"]
    assert bulk_payload["accepted_count"] == 2
    assert sorted(bulk_payload["normalized_indicator_ids"]) == ["domain::bulk-ip.example", "ip::198.51.100.11"]

    submission_id = indicator_payload["submission_id"]
    submission_status = test_client.get(f"/api/v1/external/submissions/{submission_id}", headers=_writer_headers())
    assert submission_status.status_code == 200
    status_payload = _assert_success_envelope(submission_status)["data"]
    assert status_payload["submission_id"] == submission_id
    assert status_payload["submission_type"] == "indicator"

    submitted_indicator = test_client.get(
        "/api/v1/external/indicators/domain::new-submit.example",
        headers=_writer_headers(),
    )
    assert submitted_indicator.status_code == 200
    assert submitted_indicator.json()["data"]["submission_source"] == "Writer Partner"

    wrong_partner_status = test_client.get(
        f"/api/v1/external/submissions/{submission_id}",
        headers=_reader_headers(),
    )
    assert wrong_partner_status.status_code == 403

    assert len(fake_client.index_docs[fake_client.datalake_index]) >= 8


def test_external_submission_validation_and_error_cases(client):
    test_client, _ = client

    rejected_indicator = test_client.post(
        "/api/v1/external/indicators",
        headers=_writer_headers(),
        json={
            "ioc_value": "",
            "ioc_type": "email",
            "title": "Bad indicator",
        },
    )
    assert rejected_indicator.status_code == 200
    rejected_payload = _assert_success_envelope(rejected_indicator)["data"]
    assert rejected_payload["status"] == "rejected"
    assert rejected_payload["accepted_count"] == 0
    assert rejected_payload["rejected_count"] == 2

    rejected_event = test_client.post(
        "/api/v1/external/events",
        headers=_writer_headers(),
        json={
            "event_type": "incident_report",
            "severity": "high",
            "confidence": 60,
            "tlp": "amber",
            "indicators": [],
        },
    )
    assert rejected_event.status_code == 200
    event_payload = _assert_success_envelope(rejected_event)["data"]
    assert event_payload["status"] == "rejected"
    assert event_payload["validation_errors"][0]["field"] == "indicators"

    rejected_bulk = test_client.post(
        "/api/v1/external/bulk",
        headers=_writer_headers(),
        json={
            "default_tlp": "amber",
            "dedupe_strategy": "indicator_id",
            "items": [
                {
                    "kind": "indicator",
                    "ioc_value": "",
                    "ioc_type": "domain",
                },
                {
                    "kind": "event",
                    "event_type": "bulk_event",
                    "indicators": [],
                },
            ],
        },
    )
    assert rejected_bulk.status_code == 200
    bulk_payload = _assert_success_envelope(rejected_bulk)["data"]
    assert bulk_payload["status"] == "rejected"
    assert bulk_payload["accepted_count"] == 0
    assert bulk_payload["rejected_count"] == 2

    validation_error = test_client.post(
        "/api/v1/external/indicators",
        headers=_writer_headers(),
        json={
            "ioc_value": "bad-confidence.example",
            "ioc_type": "domain",
            "confidence": 101,
        },
    )
    assert validation_error.status_code == 422

    missing_submission = test_client.get("/api/v1/external/submissions/sub-missing", headers=_writer_headers())
    assert missing_submission.status_code == 404

    missing_revoke = test_client.post("/api/v1/external/submissions/sub-missing/revoke", headers=_writer_headers())
    assert missing_revoke.status_code == 404


def test_external_revoke_flow_and_changes_stream(client):
    test_client, _ = client

    before = test_client.get("/api/v1/external/changes", headers=_writer_headers())
    assert before.status_code == 200
    cursor = before.json()["meta"]["next_cursor"]

    indicator_submission = test_client.post(
        "/api/v1/external/indicators",
        headers=_writer_headers(),
        json={
            "ioc_value": "revoke-me.example",
            "ioc_type": "domain",
            "title": "Partner phishing domain",
            "description": "Will be revoked",
            "threat_types": ["Phishing"],
            "severity": "high",
            "confidence": 85,
            "tlp": "green",
        },
    )
    submission_id = indicator_submission.json()["data"]["submission_id"]

    revoke = test_client.post(f"/api/v1/external/submissions/{submission_id}/revoke", headers=_writer_headers())
    assert revoke.status_code == 200
    revoke_payload = _assert_success_envelope(revoke)["data"]
    assert revoke_payload["status"] == "revoked"
    assert revoke_payload["updated_count"] >= 1
    assert revoke_payload["revoked_at"]

    second_revoke = test_client.post(f"/api/v1/external/submissions/{submission_id}/revoke", headers=_writer_headers())
    assert second_revoke.status_code == 200
    second_payload = _assert_success_envelope(second_revoke)["data"]
    assert second_payload["status"] == "revoked"
    assert second_payload["updated_count"] == 0

    after = test_client.get(f"/api/v1/external/changes?cursor={cursor}", headers=_writer_headers())
    assert after.status_code == 200
    revoked_ids = {item["indicator"]["indicator_id"] for item in after.json()["data"]["revoked"]}
    assert "domain::revoke-me.example" in revoked_ids


def test_external_export_endpoints_filters_permissions_and_error_cases(client):
    test_client, _ = client

    for export_format in ["json", "csv", "plain_text", "suricata", "snort"]:
        export = test_client.post(
            "/api/v1/external/exports",
            headers=_writer_headers(),
            json={
                "query": None,
                "ioc_types": ["domain", "ip"],
                "threat_types": [],
                "severities": [],
                "min_risk_score": 70,
                "tlp": "amber",
                "start_date": "2026-03-10",
                "end_date": "2026-03-12",
                "format": export_format,
            },
        )
        assert export.status_code == 200
        payload = _assert_success_envelope(export)["data"]
        assert payload["format"] == export_format
        assert payload["record_count"] >= 1
        assert payload["download_url"]

        status = test_client.get(f"/api/v1/external/exports/{payload['export_id']}", headers=_writer_headers())
        assert status.status_code == 200
        assert status.json()["data"]["download_url"]

        download = test_client.get(f"/api/v1/external/exports/{payload['export_id']}/download", headers=_writer_headers())
        assert download.status_code == 200
        assert len(download.content) > 0

        wrong_partner_status = test_client.get(
            f"/api/v1/external/exports/{payload['export_id']}",
            headers=_reader_headers(),
        )
        assert wrong_partner_status.status_code == 403

    disallowed_format = test_client.post(
        "/api/v1/external/exports",
        headers=_writer_headers(),
        json={"format": "xml"},
    )
    assert disallowed_format.status_code == 400

    reader_export = test_client.post(
        "/api/v1/external/exports",
        headers=_reader_headers(),
        json={"format": "json"},
    )
    assert reader_export.status_code == 403

    missing_export_status = test_client.get("/api/v1/external/exports/exp-missing", headers=_writer_headers())
    assert missing_export_status.status_code == 404

    missing_export_download = test_client.get(
        "/api/v1/external/exports/exp-missing/download",
        headers=_writer_headers(),
    )
    assert missing_export_download.status_code == 404
