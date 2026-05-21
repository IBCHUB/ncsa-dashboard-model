import os
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import services.dashboard_bootstrap as dashboard_bootstrap  # noqa: E402
import services.dashboard_compat_router as dashboard_compat_router  # noqa: E402
import services.dashboard_router as dashboard_router  # noqa: E402
from test_support.dashboard_fake_backend import FakeElasticClient  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    dashboard_bootstrap._state = None
    monkeypatch.setenv("DASHBOARD_BOOTSTRAP_PASSWORD", "admin123!")
    monkeypatch.setenv("DASHBOARD_SUPERADMIN_PASSWORD", "superadmin123!")
    monkeypatch.setenv("DASHBOARD_ANALYST_PASSWORD", "analyst123!")
    monkeypatch.setenv("AI_SERVICE_API_KEYS", "test-internal-key")
    fake_client = FakeElasticClient()
    monkeypatch.setattr(dashboard_router, "get_elastic_client", lambda: fake_client)
    app = FastAPI()
    app.include_router(dashboard_compat_router.router)
    app.include_router(dashboard_router.router)
    with TestClient(app) as test_client:
        yield test_client, fake_client
    dashboard_bootstrap._state = None


def _login(test_client):
    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin123!"},
    )
    assert response.status_code == 200
    token = response.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_attack_origin_trend_filters_missing_and_non_country_series():
    groups_bucket = {
        "buckets": [
            {
                "key": "None",
                "doc_count": 20,
                "timeline": {"buckets": [{"key": 1778198400000, "key_as_string": "2026-05-08T00:00:00Z", "doc_count": 20}]},
            },
            {
                "key": "US",
                "doc_count": 2,
                "timeline": {"buckets": [{"key": 1778198400000, "key_as_string": "2026-05-08T00:00:00Z", "doc_count": 2}]},
            },
            {
                "key": "not-a-country",
                "doc_count": 10,
                "timeline": {"buckets": [{"key": 1778198400000, "key_as_string": "2026-05-08T00:00:00Z", "doc_count": 10}]},
            },
            {
                "key": "CA",
                "doc_count": 1,
                "timeline": {"buckets": [{"key": 1778198400000, "key_as_string": "2026-05-08T00:00:00Z", "doc_count": 1}]},
            },
        ]
    }

    trend = dashboard_router._build_aggregated_trend(groups_bucket, "attack-origins", "day")

    labels = [item["label"] for item in trend["series"]]
    assert labels == ["United States", "Canada"]
    assert "None" not in labels
    assert "not-a-country" not in labels


def test_attack_time_heatmap_shape_changes_by_date_range():
    docs = [
        {
            "ioc_value": "one.example",
            "ai_threat_types": ["Phishing"],
            "last_seen": "2026-03-11T02:00:00Z",
            "warehouse_eligible": True,
        },
        {
            "ioc_value": "two.example",
            "ai_threat_types": ["Malware"],
            "last_seen": "2026-03-11T05:00:00Z",
            "warehouse_eligible": True,
        },
    ]

    today = dashboard_router._build_heatmap(docs, start_date="2026-03-11", end_date="2026-03-11")
    assert today["mode"] == "time-threat-type"
    assert today["y_axis"] == [
        "00:00 - 03:00",
        "03:00 - 06:00",
        "06:00 - 09:00",
        "09:00 - 12:00",
        "12:00 - 15:00",
        "15:00 - 18:00",
        "18:00 - 21:00",
        "21:00 - 00:00",
    ]
    assert today["x_axis"] == ["Phishing", "Malware"]

    last_week = dashboard_router._build_heatmap(docs, start_date="2026-03-09", end_date="2026-03-15")
    assert last_week["mode"] == "time-date"
    assert "11-03-26" in last_week["x_axis"]

    last_month = dashboard_router._build_heatmap(docs, start_date="2026-03-01", end_date="2026-03-31")
    assert last_month["mode"] == "time-day"
    assert last_month["x_axis"][0] == "1"
    assert "11" in last_month["x_axis"]

    last_six_months = dashboard_router._build_heatmap(docs, start_date="2026-01-01", end_date="2026-06-30")
    assert last_six_months["mode"] == "time-month"
    assert last_six_months["x_axis"][:2] == ["Jan 2026", "Feb 2026"]


def test_attack_time_event_row_does_not_invent_target_victim():
    row_without_target = dashboard_router._attack_time_event_row(
        {
            "_id": "domain:no-target.example",
            "ioc_value": "no-target.example",
            "severity": "low",
            "ai_threat_types": ["Malware"],
            "source_name": "Cyble Threat Intelligence Feed",
            "last_seen": "2026-05-11T06:31:54Z",
        },
        time_mode=dashboard_router.TIME_MODE_OBSERVED,
        start_date="2026-05-09",
        end_date="2026-05-15",
    )
    assert row_without_target["target_victim"] is None

    row_with_target = dashboard_router._attack_time_event_row(
        {
            "_id": "domain:target.example",
            "ioc_value": "target.example",
            "severity": "low",
            "ai_threat_types": ["Malware"],
            "source_name": "Cyble Threat Intelligence Feed",
            "last_seen": "2026-05-11T06:31:54Z",
            "target_country": "Thailand",
        },
        time_mode=dashboard_router.TIME_MODE_OBSERVED,
        start_date="2026-05-09",
        end_date="2026-05-15",
    )
    assert row_with_target["target_victim"] == "Thailand"


def test_trend_event_rows_are_hourly_volume_logs():
    docs = [
        {
            "_id": "critical-1",
            "severity": "critical",
            "last_seen": "2026-01-05T09:12:00+07:00",
            "target_sector_name": "National Security",
            "ai_threat_types": ["Web Defacement"],
        },
        {
            "_id": "high-1",
            "severity": "high",
            "last_seen": "2026-01-05T09:42:00+07:00",
            "target_sector_name": "National Security",
            "ai_threat_types": ["Web Defacement"],
        },
        {
            "_id": "medium-1",
            "severity": "medium",
            "last_seen": "2026-01-05T10:01:00+07:00",
            "target_sector_name": "Banking & Finance",
            "ai_threat_types": ["Malware"],
        },
        {
            "_id": "clean-1",
            "severity": "clean",
            "last_seen": "2026-01-05T09:30:00+07:00",
            "target_sector_name": "National Security",
            "ai_threat_types": ["Web Defacement"],
        },
    ]

    rows = dashboard_router._build_trend_event_rows(
        docs,
        start_date="2026-01-05",
        end_date="2026-01-05",
        time_mode=dashboard_router.TIME_MODE_OBSERVED,
    )

    assert len(rows) == 2
    national_security = next(row for row in rows if row["sector"] == "National Security")
    assert national_security["timestamp"] == "2026-01-05T09:00:00+07:00"
    assert national_security["threat_types"] == ["Web Defacement"]
    assert national_security["critical"] == 1
    assert national_security["high"] == 1
    assert national_security["medium"] == 0
    assert national_security["low"] == 0
    assert national_security["total"] == 2


def test_auth_and_lookup_contracts(client):
    test_client, _ = client
    headers = _login(test_client)

    me = test_client.get("/api/v1/auth/me", headers=headers)
    assert me.status_code == 200
    assert me.json()["data"]["username"] == "admin"

    threat_types = test_client.get("/api/v1/lookups/threat-types", headers=headers)
    assert threat_types.status_code == 200
    values = [item["value"] for item in threat_types.json()["data"]["items"]]
    assert "Phishing" in values
    assert "Malware" in values

    sources = test_client.get("/api/v1/lookups/sources", headers=headers)
    assert sources.status_code == 200
    source_values = [item["value"] for item in sources.json()["data"]["items"]]
    assert "AbuseIPDB" in source_values
    assert "TheHackerNews" in source_values


def test_sso_exchange_creates_dashboard_session(client):
    test_client, _ = client

    direct_sso_token = test_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.fake.sig"},
    )
    assert direct_sso_token.status_code == 401

    response = test_client.post(
        "/api/v1/auth/sso/session",
        headers={"X-API-Key": "test-internal-key"},
        json={
            "sso_id": "sso-123",
            "email": "sso.user@example.com",
            "name": "SSO User",
            "pid": "1234567890123",
            "phone": "0812345678",
            "role_name": "Admin",
        },
    )

    assert response.status_code == 200
    payload = response.json()["data"]
    assert payload["access_token"]
    assert payload["token_type"] == "Bearer"
    assert payload["user"]["username"] == "sso.user"
    assert payload["user"]["name"] == "SSO User"
    assert payload["user"]["role_name"] == "Admin"

    me = test_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["data"]["name"] == "SSO User"


def test_sso_exchange_requires_internal_api_key(client):
    test_client, _ = client

    missing_key = test_client.post(
        "/api/v1/auth/sso/session",
        json={"sso_id": "sso-123", "email": "sso.user@example.com"},
    )
    assert missing_key.status_code == 401

    invalid_key = test_client.post(
        "/api/v1/auth/sso/session",
        headers={"X-API-Key": "wrong-key"},
        json={"sso_id": "sso-123", "email": "sso.user@example.com"},
    )
    assert invalid_key.status_code == 403


def test_ioc_date_range_keeps_recently_processed_old_iocs():
    doc = {
        "first_seen": "2024-05-12T21:52:54Z",
        "last_seen": "2025-11-10T09:11:11Z",
        "processed_at": "2026-05-13T23:09:58Z",
        "published_at": "2026-05-13T23:09:58Z",
    }

    assert dashboard_router._ioc_doc_matches_date_range(
        doc,
        start_date="2026-05-08",
        end_date="2026-05-14",
    )


def test_executive_and_operations_dashboards(client):
    test_client, _ = client
    headers = _login(test_client)

    executive = test_client.get(
        "/api/v1/executive/dashboard?start_date=2026-03-11&end_date=2026-03-11",
        headers=headers,
    )
    assert executive.status_code == 200
    executive_payload = executive.json()["data"]
    assert executive_payload["threat_level"]["score"] >= 0
    assert executive_payload["attack_volume_trend"]["forecast_start_index"] == 24
    assert len(executive_payload["attack_origin_map"]["origins"]) >= 1
    assert "threat_volume_severity" in executive_payload
    assert executive_payload["exposure_today"] == {
        "total_threats": 3,
        "ioc_active": 3,
        "critical_active": 2,
        "high_active": 1,
        "comparison": {
            "total_threats": {"previous_value": 1, "delta_percent": 200.0, "direction": "up"},
            "ioc_active": {"previous_value": 1, "delta_percent": 200.0, "direction": "up"},
            "critical_active": {"previous_value": 1, "delta_percent": 100.0, "direction": "up"},
            "high_active": {"previous_value": 0, "delta_percent": 100.0, "direction": "up"},
        },
    }
    assert sum(item["value"] for item in executive_payload["threat_volume_severity"]["nodes"]) == executive_payload["exposure_today"]["total_threats"]

    empty_executive = test_client.get(
        "/api/v1/executive/dashboard?start_date=2026-03-01&end_date=2026-03-02",
        headers=headers,
    )
    assert empty_executive.status_code == 200
    assert empty_executive.json()["data"]["exposure_today"] == {
        "total_threats": 0,
        "ioc_active": 0,
        "critical_active": 0,
        "high_active": 0,
        "comparison": {
            "total_threats": {"previous_value": 0, "delta_percent": 0.0, "direction": "flat"},
            "ioc_active": {"previous_value": 0, "delta_percent": 0.0, "direction": "flat"},
            "critical_active": {"previous_value": 0, "delta_percent": 0.0, "direction": "flat"},
            "high_active": {"previous_value": 0, "delta_percent": 0.0, "direction": "flat"},
        },
    }
    assert sum(item["value"] for item in empty_executive.json()["data"]["threat_volume_severity"]["nodes"]) == 0

    executive_preview = test_client.post(
        "/api/v1/reports/executive/preview",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "sources": [],
            "severities": [],
        },
    )
    assert executive_preview.status_code == 200
    assert executive_preview.json()["data"]["filters"]["start_date"] == "2026-03-10"
    assert executive_preview.json()["data"]["threat_level"]["date"] == "2026-03-11"

    executive_export = test_client.post(
        "/api/v1/reports/executive/export",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "sources": [],
            "ioc_types": [],
            "severities": [],
            "export_format": "pdf",
        },
    )
    assert executive_export.status_code == 202
    assert executive_export.json()["data"]["report_type"] == "executive-dashboard"

    operations = test_client.get("/api/v1/operations/dashboard", headers=headers)
    assert operations.status_code == 200
    operations_payload = operations.json()["data"]
    assert operations_payload["overview"]["active_ioc"] == 3
    assert operations_payload["attack_time_heatmap"]["mode"] == "day-hour"
    assert sum(cell["value"] for cell in operations_payload["attack_time_heatmap"]["cells"]) == operations_payload["overview"]["active_ioc"]

    operations_report = test_client.get(
        "/api/v1/operations/reports/attack-origin?start_date=2026-03-10&end_date=2026-03-11",
        headers=headers,
    )
    assert operations_report.status_code == 200
    report_payload = operations_report.json()["data"]
    assert report_payload["report_key"] == "attack-origins"
    assert report_payload["ranking"]["items"] == []
    assert report_payload["meta"]["aggregation_mode"] == "elasticsearch"
    assert report_payload["meta"]["reason"] == "aggregation_unavailable"

    operations_preview = test_client.post(
        "/api/v1/reports/operations/attack-origin/preview",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "query": None,
            "threat_types": [],
            "sources": [],
            "severities": [],
            "page": 1,
            "page_size": 10,
        },
    )
    assert operations_preview.status_code == 200
    assert operations_preview.json()["data"]["ranking"]["page_size"] == 10

    operations_export = test_client.post(
        "/api/v1/reports/operations/attack-origin/export",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "sources": [],
            "ioc_types": [],
            "severities": [],
            "export_format": "xlsx",
        },
    )
    assert operations_export.status_code == 202
    assert operations_export.json()["data"]["report_type"] == "operations-attack-origins"

    attack_time_report = test_client.get(
        "/api/v1/operations/attack-time-report?start_date=2026-03-10&end_date=2026-03-11",
        headers=headers,
    )
    assert attack_time_report.status_code == 200
    assert attack_time_report.json()["data"]["summary"]["total_events"] >= 1
    assert attack_time_report.json()["data"]["filters"]["start_date"] == "2026-03-10"

    attack_time_export = test_client.post(
        "/api/v1/reports/operations/attack-time/export",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "query": None,
            "threat_types": [],
            "sources": [],
            "severities": [],
            "page": 1,
            "page_size": 20,
            "export_format": "csv",
        },
    )
    assert attack_time_export.status_code == 202
    assert attack_time_export.json()["data"]["report_type"] == "operations-attack-time"

    threat_intelligence_export = test_client.post(
        "/api/v1/reports/threat-intelligence/export",
        headers=headers,
        json={
            "section": "overview",
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "export_format": "pdf",
        },
    )
    assert threat_intelligence_export.status_code == 202
    assert threat_intelligence_export.json()["data"]["report_type"] == "threat-intelligence-overview"

    event = test_client.get("/api/v1/operations/events/dl-1", headers=headers)
    assert event.status_code == 200
    assert event.json()["data"]["formatted"]["ioc_value"] == "malicious.example"


def test_action_center_flows(client):
    test_client, fake_client = client
    headers = _login(test_client)

    actions = test_client.get("/api/v1/actions", headers=headers)
    assert actions.status_code == 200
    actions_payload = actions.json()["data"]
    action_ids = {item["action_id"] for item in actions_payload["items"]}
    assert actions_payload["summary"]["total"] == 3
    assert "wh-1" in action_ids
    assert "wh-2" in action_ids
    assert "wh-review-1" in action_ids

    detail = test_client.get("/api/v1/actions/wh-1", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["data"]["action"]["severity"] == "Critical"
    assert detail.json()["data"]["evidence_graph"]["nodes"][0]["type"] == "ioc"
    assert detail.json()["data"]["context"]["source_name"] == "AbuseIPDB"

    note = test_client.post(
        "/api/v1/actions/wh-1/notes",
        headers=headers,
        json={"content": "Reviewed evidence and confirmed escalation path."},
    )
    assert note.status_code == 201
    assert note.json()["data"]["note"]["content"] == "Reviewed evidence and confirmed escalation path."
    detail_with_note = test_client.get("/api/v1/actions/wh-1", headers=headers)
    assert any(item["content"] == "Reviewed evidence and confirmed escalation path." for item in detail_with_note.json()["data"]["notes"])

    assign = test_client.post(
        "/api/v1/actions/wh-1/assign",
        headers=headers,
        json={"assignee_id": "usr-general", "handover_note": "Take first review"},
    )
    assert assign.status_code == 200
    assert assign.json()["data"]["status"] == "in_progress"
    assert fake_client.index_docs[fake_client.warehouse_index]["wh-1"]["action_status"] == "in_progress"

    false_positive = test_client.post(
        "/api/v1/actions/wh-1/false-positive",
        headers=headers,
        data={"reason_category": "benign", "justification": "Internal sinkhole domain"},
    )
    assert false_positive.status_code == 200
    assert fake_client.index_docs[fake_client.warehouse_index]["wh-1"]["action_status"] == "closed"
    assert fake_client.index_docs[fake_client.warehouse_index]["wh-1"]["action_closed_reason"] == "false_positive"

    action_preview = test_client.post(
        "/api/v1/reports/actions/preview",
        headers=headers,
        json={
            "query": None,
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "sources": [],
            "severities": [],
            "statuses": [],
        },
    )
    assert action_preview.status_code == 200
    assert action_preview.json()["data"]["summary"]["total"] == 3

    action_export = test_client.post(
        "/api/v1/reports/actions/export",
        headers=headers,
        json={
            "query": None,
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "sources": [],
            "severities": [],
            "statuses": [],
            "export_format": "csv",
        },
    )
    assert action_export.status_code == 202
    assert action_export.json()["data"]["report_type"] == "actions"

    block_ip = test_client.post(
        "/api/v1/actions/wh-2/block-ip",
        headers=headers,
        json={
            "target_ioc": "185.10.10.10",
            "enforcement_point_ids": ["fw-bkk-01"],
            "duration_mode": "temporary",
            "duration_days": 7,
            "reason": "Containment",
        },
    )
    assert block_ip.status_code == 200
    assert block_ip.json()["data"]["execution"]["enforcement_point_ids"] == ["fw-bkk-01"]
    assert fake_client.index_docs[fake_client.warehouse_index]["wh-2"]["action_status"] == "in_progress"


def test_ioc_listing_detail_and_events(client):
    test_client, _ = client
    headers = _login(test_client)

    listing = test_client.get("/api/v1/iocs?high_risk_only=true", headers=headers)
    assert listing.status_code == 200
    listing_payload = listing.json()["data"]
    assert listing_payload["summary"]["total_indicators"] == 3
    assert listing_payload["items"][0]["risk_score"] >= 80

    detail = test_client.get("/api/v1/iocs/domain::malicious.example", headers=headers)
    assert detail.status_code == 200
    detail_payload = detail.json()["data"]
    assert detail_payload["risk_assessment"]["risk_score"] == 92
    assert detail_payload["relationship"]["capabilities"]["campaigns"] is True
    assert detail_payload["enrichment_context"]["references"][0] == "https://intel.example/phishing-1"
    assert detail_payload["history_preview"][0]["source"] == "AbuseIPDB"

    events = test_client.get("/api/v1/iocs/domain::malicious.example/events", headers=headers)
    assert events.status_code == 200
    assert events.json()["data"]["items"][0]["source"] == "AbuseIPDB"

    relationships = test_client.get(
        "/api/v1/iocs/relationships?ioc_type=domain&ioc_value=malicious.example",
        headers=headers,
    )
    assert relationships.status_code == 200
    relationship_payload = relationships.json()["data"]
    assert relationship_payload["matched_ioc"]["ioc_value"] == "malicious.example"
    assert {node["type"] for node in relationship_payload["relationship"]["nodes"]} >= {"ioc", "threat_type", "threat_actor"}
    assert any(item["relationship"] == "classified_as" for item in relationship_payload["relationship_log"])

    summary_tab = test_client.get("/api/v1/ioc-analytics?tab=ioc-summary", headers=headers)
    assert summary_tab.status_code == 200
    assert summary_tab.json()["data"]["cards"]["total_ioc"] == 3
    assert summary_tab.json()["data"]["cards"]["active_ioc"] == 3
    assert summary_tab.json()["data"]["charts"]["severity_by_type"][0]["critical"] >= 0

    import_tab = test_client.get("/api/v1/ioc-analytics?tab=statistics-import", headers=headers)
    assert import_tab.status_code == 200
    assert import_tab.json()["data"]["charts"]["import_by_source"][0]["value"] >= 1


def test_ioc_detail_uses_enrichment_from_any_datalake_doc():
    detail_payload = dashboard_router._build_ioc_detail(
        {
            "ioc_value": "9.0.2.0",
            "ioc_type": "ip",
            "severity": "low",
            "source_name": "BleepingComputer News",
            "ai_risk_score": 22,
            "ai_threat_types": ["Exploited Vulnerability"],
            "first_seen": "2026-04-22T12:00:00Z",
        },
        [
            {
                "ioc_value": "9.0.2.0",
                "ioc_type": "ip",
                "event_time": "2026-04-22T12:00:00Z",
                "source_name": "BleepingComputer News",
            },
            {
                "ioc_value": "9.0.2.0",
                "ioc_type": "ip",
                "event_time": "2026-04-22T12:05:00Z",
                "enrichment": {
                    "geo_ip": {
                        "country": "United States",
                        "city": "Durham",
                        "org": "IBM",
                        "isp": "IBM",
                    }
                },
            },
        ],
    )

    assert detail_payload["geo_location_owner"]["country"] == "United States"
    assert detail_payload["geo_location_owner"]["city"] == "Durham"
    assert detail_payload["geo_location_owner"]["asn_org"] == "IBM"
    assert detail_payload["network_ownership"]["organization"] == "IBM"
    assert detail_payload["asn_infrastructure"]["asn_name"] == "IBM"


def test_ioc_relationships_missing_query_does_not_collect_all_docs(client, monkeypatch):
    test_client, _ = client
    headers = _login(test_client)

    def fail_if_called(*args, **kwargs):
        raise AssertionError("_collect_ioc_docs must not be used by /iocs/relationships fallback")

    monkeypatch.setattr(dashboard_router, "_collect_ioc_docs", fail_if_called)

    response = test_client.get("/api/v1/iocs/relationships?query=missing.example", headers=headers)

    assert response.status_code == 404
    assert response.json()["detail"] == "IOC not found"


def test_ioc_relationship_log_deduplicates_edges_and_keeps_evidence_based_two_hop_rows():
    warehouse_doc = {
        "ioc_type": "domain",
        "ioc_value": "vitosc.xyz",
        "ai_threat_types": ["Exploited Vulnerability"],
        "ai_threat_actors": ["Conti"],
        "first_seen": "2026-04-21T10:45:00Z",
        "last_seen": "2026-04-29T10:41:00Z",
    }
    related_doc = {
        "ioc_type": "domain",
        "ioc_value": "kali.org",
        "ai_threat_types": ["APT"],
        "ai_threat_actors": ["Conti"],
        "first_seen": "2026-04-21T10:45:00Z",
        "last_seen": "2026-04-29T10:41:00Z",
    }
    evidence_entries = [
        {
            "ioc_type": "domain",
            "ioc_value": "kali.org",
            "indicator": dashboard_router._indicator_id("domain", "kali.org"),
            "relation": "correlated_with",
            "first_seen": "2026-04-21T10:45:00Z",
            "last_seen": "2026-04-29T10:41:00Z",
        },
        {
            "ioc_type": "domain",
            "ioc_value": "kali.org",
            "indicator": dashboard_router._indicator_id("domain", "kali.org"),
            "relation": "correlated_with",
            "first_seen": "2026-04-21T10:45:00Z",
            "last_seen": "2026-04-29T10:41:00Z",
        },
    ]

    payload = dashboard_router._build_ioc_relationship_graph(
        warehouse_doc,
        [],
        [related_doc],
        evidence_entries,
    )

    relationship_tuples = [
        (item["source"], item["relationship"], item["target"])
        for item in payload["relationship_log"]
    ]
    assert len(relationship_tuples) == len(set(relationship_tuples))
    assert ("Conti", "uses", "vitosc.xyz") in relationship_tuples
    assert ("vitosc.xyz", "classified_as", "Exploited Vulnerability") in relationship_tuples
    assert ("vitosc.xyz", "correlated_with", "kali.org") in relationship_tuples
    assert ("Conti", "uses", "kali.org") in relationship_tuples
    assert ("kali.org", "classified_as", "APT") in relationship_tuples


def test_threat_type_detail_report(client):
    test_client, _ = client
    headers = _login(test_client)

    detail = test_client.get(
        "/api/v1/operations/reports/threat-types/Phishing?start_date=2026-03-10&end_date=2026-03-11",
        headers=headers,
    )
    assert detail.status_code == 200
    payload = detail.json()["data"]
    assert payload["threat_type"] == "Phishing"
    assert payload["summary"]["total_iocs"] >= 1
    assert payload["ioc_type_distribution"][0]["ioc_type"] == "domain"
    assert payload["targeted_sectors"]
    assert payload["related_attackers"][0]["actor"] in {"Lazarus", "APT29"}
    assert payload["related_iocs"][0]["ioc_value"]


def test_missing_page_api_contracts(client):
    test_client, _ = client
    headers = _login(test_client)

    sectors = test_client.get("/api/v1/lookups/sectors", headers=headers)
    assert sectors.status_code == 200
    sector_values = {item["value"] for item in sectors.json()["data"]["items"]}
    assert {"government", "financial"}.issubset(sector_values)

    trend_events = test_client.get(
        "/api/v1/threat-intelligence/trend/events?start_date=2026-03-10&end_date=2026-03-11",
        headers=headers,
    )
    assert trend_events.status_code == 200
    trend_payload = trend_events.json()["data"]
    assert trend_payload["summary"]["total_events"] >= 1
    assert trend_payload["items"][0]["timestamp"]
    assert trend_payload["items"][0]["ioc_value"]

    cve_list = test_client.get("/api/v1/cve-intelligence", headers=headers)
    assert cve_list.status_code == 200
    cve_payload = cve_list.json()["data"]
    assert cve_payload["summary"]["total_cves"] >= 1
    assert cve_payload["items"][0]["cve_id"] == "CVE-2026-12345"
    assert cve_payload["items"][0]["exploited_in_the_wild"] is True

    cve_detail = test_client.get("/api/v1/cve-intelligence/CVE-2026-12345", headers=headers)
    assert cve_detail.status_code == 200
    assert cve_detail.json()["data"]["cve_id"] == "CVE-2026-12345"

    landscape = test_client.get(
        "/api/v1/threat-landscape?start_date=2026-03-10&end_date=2026-03-11",
        headers=headers,
    )
    assert landscape.status_code == 200
    landscape_payload = landscape.json()["data"]
    assert landscape_payload["summary"]["total_iocs"] == 3
    assert landscape_payload["threat_types"]
    assert landscape_payload["target_sectors"]


def test_collect_ioc_docs_post_filters_query(client, monkeypatch):
    _, fake_client = client

    def _return_all_docs(**_kwargs):
        return {
            "hits": {
                "total": {"value": len(fake_client.index_docs[fake_client.warehouse_index])},
                "hits": [
                    {"_id": doc_id, "_source": payload}
                    for doc_id, payload in fake_client.index_docs[fake_client.warehouse_index].items()
                ],
            }
        }

    monkeypatch.setattr(dashboard_router, "_search_warehouse_docs", _return_all_docs)

    docs = dashboard_router._collect_ioc_docs(
        query="malicious.example",
        start_date="2026-03-10",
        end_date="2026-03-11",
    )

    assert [doc["ioc_value"] for doc in docs] == ["malicious.example"]


def test_build_exposure_summary_uses_latest_active_indicator_state():
    visible_docs = [
        {
            "_id": "visible-1",
            "ioc_type": "domain",
            "ioc_value": "alpha.example",
            "ai_severity": "low",
            "last_seen": "2026-04-07T09:00:00Z",
        },
        {
            "_id": "visible-2",
            "ioc_type": "ip",
            "ioc_value": "198.51.100.10",
            "ai_severity": "medium",
            "last_seen": "2026-04-07T10:00:00Z",
        },
    ]
    active_docs = visible_docs + [
        {
            "_id": "historic-alpha",
            "ioc_type": "domain",
            "ioc_value": "alpha.example",
            "ai_severity": "critical",
            "last_seen": "2026-03-01T00:00:00Z",
        },
        {
            "_id": "active-1",
            "ioc_type": "url",
            "ioc_value": "https://beta.example",
            "ai_severity": "critical",
            "last_seen": "2026-04-02T00:00:00Z",
        },
        {
            "_id": "active-2",
            "ioc_type": "domain",
            "ioc_value": "gamma.example",
            "ai_severity": "high",
            "last_seen": "2026-04-03T00:00:00Z",
        },
    ]

    summary = dashboard_router._build_exposure_summary(visible_docs, active_docs)

    assert summary == {
        "total_threats": 2,
        "ioc_active": 4,
        "critical_active": 1,
        "high_active": 1,
        "comparison": {
            "total_threats": {"previous_value": 0, "delta_percent": 100.0, "direction": "up"},
            "ioc_active": {"previous_value": 0, "delta_percent": 100.0, "direction": "up"},
            "critical_active": {"previous_value": 0, "delta_percent": 100.0, "direction": "up"},
            "high_active": {"previous_value": 0, "delta_percent": 100.0, "direction": "up"},
        },
    }


def test_build_threat_volume_nodes_counts_each_doc_once():
    docs = [
        {
            "_id": "wh-1",
            "ioc_type": "domain",
            "ioc_value": "alpha.example",
            "ai_threat_types": ["Phishing", "APT"],
            "ai_severity": "low",
        },
        {
            "_id": "wh-2",
            "ioc_type": "ip",
            "ioc_value": "198.51.100.10",
            "ai_threat_types": ["Phishing", "Malware"],
            "ai_severity": "medium",
        },
        {
            "_id": "wh-3",
            "ioc_type": "url",
            "ioc_value": "https://beta.example",
            "ai_threat_types": ["Malware"],
            "ai_severity": "high",
        },
    ]

    nodes = dashboard_router._build_threat_volume_nodes(docs)
    by_label = {node["label"]: node for node in nodes}

    assert sum(node["value"] for node in nodes) == len(docs)
    assert by_label["Phishing"]["value"] == 2
    assert by_label["Phishing"]["severity"] == "Medium"
    assert by_label["Malware"]["value"] == 1
    assert by_label["Malware"]["severity"] == "High"


def test_reports_news_and_admin_domains(client):
    test_client, _ = client
    headers = _login(test_client)

    preview = test_client.post(
        "/api/v1/reports/ioc/preview",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "sources": [],
            "ioc_types": [],
            "severities": [],
            "limit": 1,
            "offset": 1,
        },
    )
    assert preview.status_code == 200
    assert preview.json()["data"]["summary"]["total_rows"] >= 2
    assert preview.json()["data"]["filters"]["limit"] == 1
    assert preview.json()["data"]["filters"]["offset"] == 1
    assert len(preview.json()["data"]["items"]) == 1
    assert preview.json()["data"]["items"][0]["rank"] == 2

    preview_paged = test_client.post(
        "/api/v1/reports/ioc/preview",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "sources": [],
            "ioc_types": [],
            "severities": [],
            "page": 2,
            "page_size": 1,
        },
    )
    assert preview_paged.status_code == 200
    assert preview_paged.json()["data"]["filters"]["page"] == 2
    assert preview_paged.json()["data"]["filters"]["page_size"] == 1
    assert len(preview_paged.json()["data"]["items"]) == 1
    assert preview_paged.json()["data"]["items"][0]["rank"] == 2

    export = test_client.post(
        "/api/v1/reports/ioc/export",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "query": "malicious.example",
            "threat_types": ["Phishing"],
            "sources": ["AbuseIPDB"],
            "risk_levels": ["critical"],
            "ioc_types": ["domain"],
            "severities": [],
            "high_risk_only": True,
            "export_format": "csv",
        },
    )
    assert export.status_code == 202
    export_payload = export.json()["data"]
    assert export_payload["filters"]["start_date"] == "2026-03-10"
    assert export_payload["filters"]["end_date"] == "2026-03-11"
    assert export_payload["filters"]["query"] == "malicious.example"
    assert export_payload["filters"]["risk_levels"] == ["critical"]
    assert export_payload["filters"]["high_risk_only"] is True
    assert export_payload["download_url"].endswith(f"/api/v1/exports/{export_payload['export_id']}/download")
    assert "T" in export_payload["created_at"]
    assert "T" in export_payload["completed_at"]
    export_id = export.json()["data"]["export_id"]

    export_status = test_client.get(f"/api/v1/exports/{export_id}", headers=headers)
    assert export_status.status_code == 200
    assert export_status.json()["data"]["status"] == "completed"
    assert export_status.json()["data"]["report_type"] == "ioc-report"
    assert export_status.json()["data"]["download_url"].endswith(f"/api/v1/exports/{export_id}/download")

    export_download = test_client.get(f"/api/v1/exports/{export_id}/download", headers=headers)
    assert export_download.status_code == 200
    assert export_download.headers["content-type"].startswith("text/csv")
    assert "malicious.example" in export_download.text

    xlsx_export = test_client.post(
        "/api/v1/reports/ioc/export",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "query": "malicious.example",
            "threat_types": ["Phishing"],
            "sources": ["AbuseIPDB"],
            "risk_levels": ["critical"],
            "ioc_types": ["domain"],
            "severities": [],
            "high_risk_only": True,
            "export_format": "xlsx",
        },
    )
    assert xlsx_export.status_code == 202
    xlsx_payload = xlsx_export.json()["data"]
    assert xlsx_payload["export_format"] == "xlsx"
    assert xlsx_payload["file_name"].endswith(".xlsx")
    xlsx_download = test_client.get(f"/api/v1/exports/{xlsx_payload['export_id']}/download", headers=headers)
    assert xlsx_download.status_code == 200
    assert xlsx_download.headers["content-type"].startswith("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    assert xlsx_download.content[:4] == b"PK\x03\x04"

    pdf_export = test_client.post(
        "/api/v1/reports/ioc/export",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "query": "malicious.example",
            "threat_types": ["Phishing"],
            "sources": ["AbuseIPDB"],
            "risk_levels": ["critical"],
            "ioc_types": ["domain"],
            "severities": [],
            "high_risk_only": True,
            "export_format": "pdf",
        },
    )
    assert pdf_export.status_code == 202
    pdf_payload = pdf_export.json()["data"]
    assert pdf_payload["export_format"] == "pdf"
    assert pdf_payload["file_name"].endswith(".pdf")
    pdf_download = test_client.get(f"/api/v1/exports/{pdf_payload['export_id']}/download", headers=headers)
    assert pdf_download.status_code == 200
    assert pdf_download.headers["content-type"].startswith("application/pdf")
    assert pdf_download.content[:8] == b"%PDF-1.4"

    most_frequent = test_client.post(
        "/api/v1/reports/most-frequent-threats/preview",
        headers=headers,
        json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "severities": [],
            "risk_levels": [],
        },
    )
    assert most_frequent.status_code == 200
    assert most_frequent.json()["data"]["summary"]["total_rows"] >= 1

    news = test_client.get("/api/v1/news", headers=headers)
    assert news.status_code == 200
    news_item = news.json()["data"]["items"][0]
    assert news_item["source"] == "TheHackerNews"

    news_detail = test_client.get(f"/api/v1/news/{news_item['article_id']}", headers=headers)
    assert news_detail.status_code == 200
    assert news_detail.json()["data"]["title"] == news_item["title"]

    profile = test_client.get("/api/v1/account/profile", headers=headers)
    assert profile.status_code == 200
    assert profile.json()["data"]["email"] == "natakarn@example.com"

    profile_update = test_client.patch(
        "/api/v1/account/profile",
        headers=headers,
        json={"phone_number": "089-999-9999"},
    )
    assert profile_update.status_code == 200
    assert profile_update.json()["data"]["phone_number"] == "089-999-9999"

    create_user = test_client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "name": "Spec User",
            "email": "spec@example.com",
            "password": "Password123!",
            "group_id": "grp-general",
            "status": "active",
        },
    )
    assert create_user.status_code == 201
    created_user_id = create_user.json()["data"]["user_id"]

    users = test_client.get("/api/v1/users", headers=headers)
    assert users.status_code == 200
    assert any(item["user_id"] == created_user_id for item in users.json()["data"]["items"])

    active_users = test_client.get("/api/v1/users?status=active", headers=headers)
    assert active_users.status_code == 200
    assert all(item["status"] == "active" for item in active_users.json()["data"]["items"])

    create_group = test_client.post(
        "/api/v1/user-groups",
        headers=headers,
        json={
            "name": "Tier 2 Analysts",
            "permissions": [{"module": "IOC Data Lake", "read": True, "edit": False}],
        },
    )
    assert create_group.status_code == 201
    group_id = create_group.json()["data"]["group_id"]

    groups = test_client.get("/api/v1/user-groups", headers=headers)
    assert groups.status_code == 200
    assert "member_count" in groups.json()["data"]["items"][0]

    notifications = test_client.get("/api/v1/notifications?unread_only=true", headers=headers)
    assert notifications.status_code == 200
    assert notifications.json()["data"]["unread_count"] >= 1

    read_one = test_client.post("/api/v1/notifications/ntf-001/read", headers=headers)
    assert read_one.status_code == 200
    assert read_one.json()["data"]["unread"] is False

    read_all = test_client.post("/api/v1/notifications/read-all", headers=headers, json={"type": "action_update"})
    assert read_all.status_code == 200
    assert read_all.json()["data"]["marked_count"] >= 0

    read_notifications = test_client.get("/api/v1/notifications?status=read", headers=headers)
    assert read_notifications.status_code == 200
    assert all(item["unread"] is False for item in read_notifications.json()["data"]["items"])

    delete_group = test_client.delete(f"/api/v1/user-groups/{group_id}", headers=headers)
    assert delete_group.status_code == 200


def test_remaining_dashboard_routes(client):
    test_client, _ = client
    headers = _login(test_client)

    severities = test_client.get("/api/v1/lookups/severities", headers=headers)
    assert severities.status_code == 200
    assert severities.json()["data"]["items"][0]["value"] == "critical"

    risk_levels = test_client.get("/api/v1/lookups/risk-levels", headers=headers)
    assert risk_levels.status_code == 200
    assert risk_levels.json()["data"]["items"][-1]["value"] == "clean"

    export_formats = test_client.get("/api/v1/lookups/export-formats", headers=headers)
    assert export_formats.status_code == 200
    assert export_formats.json()["data"]["items"][0]["value"] == "csv"

    assignees = test_client.get("/api/v1/lookups/assignees?status=active&query=nat", headers=headers)
    assert assignees.status_code == 200
    assert assignees.json()["data"]["items"][0]["user_id"] == "usr-admin"

    enforcement_points = test_client.get("/api/v1/lookups/enforcement-points?type=firewall", headers=headers)
    assert enforcement_points.status_code == 200
    assert enforcement_points.json()["data"]["items"][0]["type"] == "firewall"

    related_iocs = test_client.get("/api/v1/actions/wh-1/related-iocs", headers=headers)
    assert related_iocs.status_code == 200
    related_values = {item["ioc_value"] for item in related_iocs.json()["data"]["items"]}
    assert "malicious.example" not in related_values
    assert related_values

    reset = test_client.post(
        "/api/v1/account/password/reset",
        headers=headers,
        json={
            "reset_mode": "change",
            "current_password": "admin123!",
            "new_password": "Admin123!updated",
        },
    )
    assert reset.status_code == 200
    assert reset.json()["data"]["success"] is True

    created_user = test_client.post(
        "/api/v1/users",
        headers=headers,
        json={
            "name": "Temp User",
            "email": "temp@example.com",
            "password": "Password123!",
            "group_id": "grp-general",
            "status": "inactive",
        },
    )
    assert created_user.status_code == 201
    user_id = created_user.json()["data"]["user_id"]

    updated_user = test_client.patch(
        f"/api/v1/users/{user_id}",
        headers=headers,
        json={"status": "active", "phone_number": "081-234-5678"},
    )
    assert updated_user.status_code == 200
    assert updated_user.json()["data"]["status"] == "active"

    deleted_user = test_client.delete(f"/api/v1/users/{user_id}", headers=headers)
    assert deleted_user.status_code == 200
    assert deleted_user.json()["data"]["success"] is True

    created_group = test_client.post(
        "/api/v1/user-groups",
        headers=headers,
        json={
            "name": "Patchable Group",
            "permissions": [{"module": "Reports", "read": True, "edit": True}],
        },
    )
    assert created_group.status_code == 201
    group_id = created_group.json()["data"]["group_id"]

    updated_group = test_client.patch(
        f"/api/v1/user-groups/{group_id}",
        headers=headers,
        json={
            "name": "Patched Group",
            "permissions": [{"module": "Reports", "read": True, "edit": False}],
        },
    )
    assert updated_group.status_code == 200
    assert updated_group.json()["data"]["name"] == "Patched Group"

    deleted_group = test_client.delete(f"/api/v1/user-groups/{group_id}", headers=headers)
    assert deleted_group.status_code == 200
    assert deleted_group.json()["data"]["success"] is True

    logout = test_client.post("/api/v1/auth/logout", headers=headers)
    assert logout.status_code == 200
    assert logout.json()["data"]["logged_out"] is True

    repeated_logout = test_client.post("/api/v1/auth/logout")
    assert repeated_logout.status_code == 200
    assert repeated_logout.json()["data"]["logged_out"] is True

    me_after_logout = test_client.get("/api/v1/auth/me", headers=headers)
    assert me_after_logout.status_code == 401

    relogin = test_client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "Admin123!updated"},
    )
    assert relogin.status_code == 200
    fresh_headers = {"Authorization": f"Bearer {relogin.json()['data']['access_token']}"}

    delete_account = test_client.request(
        "DELETE",
        "/api/v1/account",
        headers=fresh_headers,
        json={"confirmation_text": "delete my user account", "reason": "contract smoke"},
    )
    assert delete_account.status_code == 200
    assert delete_account.json()["data"]["success"] is True


def test_compat_transformers_preserve_frontend_shape():
    lookup_items = dashboard_compat_router._compat_lookup_items(
        [
            {"value": "critical", "label": "Critical"},
            {"value": "high", "label": "High"},
        ]
    )
    assert lookup_items == [
        {"Id": 1, "Name": "Critical", "Value": "critical"},
        {"Id": 2, "Name": "High", "Value": "high"},
    ]

    heatmap = dashboard_compat_router._compat_heatmap(
        {
            "mode": "day-hour",
            "x_axis": ["00:00", "01:00"],
            "y_axis": ["Mon", "Tue"],
            "cells": [
                {"x": "00:00", "y": "Mon", "value": 5},
                {"x": "01:00", "y": "Sun", "value": 2},
            ],
        }
    )
    assert heatmap["xAxis"] == ["00", "01"]
    assert heatmap["yAxis"][0] == "Sun"
    assert [0, 1, 5] in heatmap["data"]
    assert [1, 0, 2] in heatmap["data"]


def test_compat_login_and_lookup_shapes(client):
    test_client, _ = client

    login = test_client.post(
        "/login",
        json={"username": "admin", "password": "admin123!"},
    )
    assert login.status_code == 200
    login_payload = login.json()
    assert "token" in login_payload
    assert login_payload["token_type"] == "Bearer"

    threat_type_lookup = test_client.get("/threat-type")
    assert threat_type_lookup.status_code == 200
    assert threat_type_lookup.json()["res_result"][0] == {
        "Id": 1,
        "Name": "Malware",
        "Value": "malware",
    }

    source_lookup = test_client.get("/source")
    assert source_lookup.status_code == 200
    source_item = source_lookup.json()["res_result"][0]
    assert set(source_item.keys()) == {"Id", "Name", "Value"}
    assert isinstance(source_item["Id"], int)

    severity_lookup = test_client.get("/severity")
    assert severity_lookup.status_code == 200
    assert severity_lookup.json()["res_result"][0]["Name"] == "Critical"

    risk_level_lookup = test_client.get("/rick-level")
    assert risk_level_lookup.status_code == 200
    assert risk_level_lookup.json()["res_result"][-1]["Value"] == "clean"

    export_type_lookup = test_client.get("/export-type")
    assert export_type_lookup.status_code == 200
    assert export_type_lookup.json()["res_result"][0]["Name"] == "CSV"


def test_compat_operations_shapes(client):
    test_client, _ = client

    dashboard = test_client.get("/dashboard?start_date=2026-03-10&end_date=2026-03-11")
    assert dashboard.status_code == 200
    dashboard_payload = dashboard.json()["res_result"]
    assert dashboard_payload == {
        "ActiveIOC": 3,
        "CriticalIOCActive": 2,
        "NewIOC": 3,
        "SourcesActive": 2,
    }

    incident = test_client.get("/incidentbyseverity?start_date=2026-03-10&end_date=2026-03-11")
    assert incident.status_code == 200
    incident_item = incident.json()["res_result"][0]
    assert set(incident_item.keys()) == {"Color", "Name", "Value", "Percentage"}

    attack_time = test_client.get("/attacktime?start_date=2026-03-10&end_date=2026-03-11")
    assert attack_time.status_code == 200
    attack_payload = attack_time.json()["res_result"]
    assert attack_payload["xAxis"][0] == "00"
    assert attack_payload["yAxis"][0] == "Sun"
    assert len(attack_payload["data"][0]) == 3

    intelligence_sources = test_client.get("/intelligencesources?start_date=2026-03-10&end_date=2026-03-11")
    assert intelligence_sources.status_code == 200
    intelligence_payload = intelligence_sources.json()["res_result"]
    assert intelligence_payload[0]["Value"] == 2
    assert {item["Name"] for item in intelligence_payload[:2]} == {"AbuseIPDB", "ThreatFox"}

    threat_type_chart = test_client.get("/threattype?start_date=2026-03-10&end_date=2026-03-11")
    assert threat_type_chart.status_code == 200
    assert threat_type_chart.json()["res_result"][0]["Name"] == "Phishing"

    countries = test_client.get("/countriesbythreatassociation?start_date=2026-03-10&end_date=2026-03-11")
    assert countries.status_code == 200
    assert countries.json()["res_result"][0]["Name"] == "Russia"

    sectors = test_client.get("/targetsectors?start_date=2026-03-10&end_date=2026-03-11")
    assert sectors.status_code == 200
    assert sectors.json()["res_result"][0]["Name"] == "ภาครัฐ"


# ---------------------------------------------------------------------------
# Phase 2.2 — Authorization regression tests
# ---------------------------------------------------------------------------


def _login_as_analyst(test_client):
    response = test_client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "analyst123!"},
    )
    assert response.status_code == 200
    token = response.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_user_admin_endpoints_require_admin_role(client):
    """Phase 2.2-9/10 regression: user/group CRUD must reject non-admins.

    Previously every authenticated user (including "General" analysts)
    could list, create, edit, and delete users and groups.
    """
    test_client, _ = client
    analyst_headers = _login_as_analyst(test_client)

    for path in ("/api/v1/users", "/api/v1/user-groups"):
        response = test_client.get(path, headers=analyst_headers)
        assert response.status_code == 403, f"{path} should be admin-only"

    create_user = test_client.post(
        "/api/v1/users",
        json={"name": "Hacker", "email": "h@example.com", "password": "x"},
        headers=analyst_headers,
    )
    assert create_user.status_code == 403

    delete_user = test_client.delete("/api/v1/users/usr-admin", headers=analyst_headers)
    assert delete_user.status_code == 403


def test_admin_cannot_self_delete_via_user_endpoint(client):
    """Phase 2.2-11 regression: deleting yourself from /users/{id} would
    let an admin lock themselves out — must use DELETE /account instead.
    """
    test_client, _ = client
    admin_headers = _login(test_client)
    response = test_client.delete("/api/v1/users/usr-admin", headers=admin_headers)
    assert response.status_code == 400
    assert "own account" in response.json()["detail"].lower()


def test_block_ip_requires_admin(client):
    """Phase 2.5-1 regression: block-ip queues a real firewall rule push.
    General-role analysts must not reach it.
    """
    test_client, _ = client
    analyst_headers = _login_as_analyst(test_client)
    response = test_client.post(
        "/api/v1/actions/wh-1/block-ip",
        headers=analyst_headers,
        json={
            "target_ioc": "evil.example",
            "enforcement_point_ids": ["fw-bkk-01"],
            "duration_mode": "permanent",
            "duration_days": None,
            "reason": "obvious",
        },
    )
    assert response.status_code == 403


def test_block_ip_rejects_unknown_enforcement_point(client):
    """Phase 2.5-12 regression: bogus enforcement_point_ids used to be
    silently appended to the note. Reject with 400 instead.
    """
    test_client, _ = client
    admin_headers = _login(test_client)
    response = test_client.post(
        "/api/v1/actions/wh-1/block-ip",
        headers=admin_headers,
        json={
            "target_ioc": "evil.example",
            "enforcement_point_ids": ["does-not-exist"],
            "duration_mode": "permanent",
            "duration_days": None,
            "reason": "obvious",
        },
    )
    assert response.status_code == 400
    assert "Unknown enforcement_point_ids" in response.json()["detail"]


def test_assign_action_rejects_inactive_assignee(client):
    """Phase 2.5-9: must not assign work to a user marked inactive."""
    test_client, _ = client
    admin_headers = _login(test_client)
    state = dashboard_bootstrap.get_dashboard_state()
    # Mark the analyst user inactive on the fly.
    state.update_user("usr-general", {"status": "inactive"})
    response = test_client.post(
        "/api/v1/actions/wh-1/assign",
        headers=admin_headers,
        json={"assignee_id": "usr-general", "handover_note": "please look"},
    )
    assert response.status_code == 404
    assert "inactive" in response.json()["detail"].lower()


def test_action_note_blocked_when_action_doc_is_tlp_red(client):
    """Phase 2.5-4: action mutations must respect doc-level TLP, not just
    require an authenticated user.
    """
    test_client, _ = client
    analyst_headers = _login_as_analyst(test_client)
    response = test_client.post(
        "/api/v1/actions/wh-red-1/notes",
        headers=analyst_headers,
        json={"content": "secret note"},
    )
    # 404, not 403, so we don't confirm wh-red-1 exists.
    assert response.status_code == 404


def test_ioc_events_hides_tlp_red_from_analyst(client, monkeypatch):
    """Phase 2.4-1 regression: /iocs/{id}/events used to return RED-tagged
    events for any authenticated user. Analysts must see the doc filtered
    out; admins still see it.
    """
    test_client, fake_client = client
    # Seed a RED-tagged datalake event for a known IOC.
    fake_client.index_docs[fake_client.datalake_index]["dl-red-1"] = {
        "ioc_value": "malicious.example",
        "ioc_type": "domain",
        "description": "Red-tagged sensitive observation",
        "severity": 80,
        "source_name": "Cyberint",
        "tlp": "red",
        "event_time": "2026-03-11T08:30:00Z",
        "@timestamp": "2026-03-11T08:30:00Z",
    }

    analyst_headers = _login_as_analyst(test_client)
    admin_headers = _login(test_client)

    analyst_resp = test_client.get(
        "/api/v1/iocs/domain::malicious.example/events",
        headers=analyst_headers,
    )
    assert analyst_resp.status_code == 200
    descriptions = [item.get("description", "") for item in analyst_resp.json()["data"]["items"]]
    assert "Red-tagged sensitive observation" not in descriptions

    admin_resp = test_client.get(
        "/api/v1/iocs/domain::malicious.example/events",
        headers=admin_headers,
    )
    assert admin_resp.status_code == 200
    admin_descriptions = [item.get("description", "") for item in admin_resp.json()["data"]["items"]]
    assert "Red-tagged sensitive observation" in admin_descriptions


def test_ioc_analytics_rejects_unknown_tab(client):
    """Phase 2.4-5 regression: unknown tab silently went to default branch
    and cached a confusing empty payload. Must return 400 instead.
    """
    test_client, _ = client
    headers = _login(test_client)
    response = test_client.get("/api/v1/ioc-analytics?tab=not-a-tab", headers=headers)
    assert response.status_code == 400
    assert "unknown tab" in response.json()["detail"].lower()


def test_ioc_list_rejects_inverted_date_range(client):
    """Phase 2.4-4: date validation must extend to the IOC list endpoint."""
    test_client, _ = client
    headers = _login(test_client)
    response = test_client.get(
        "/api/v1/iocs?start_date=2026-05-21&end_date=2026-05-20",
        headers=headers,
    )
    assert response.status_code == 400


def test_operation_event_detail_hides_tlp_red_from_analyst(client):
    """Phase 2.3-2 regression: TLP:red docs were exposed via the event-detail
    endpoint to any authenticated user. Analysts must see a 404 (not 403, to
    avoid leaking the document's existence); admins still see it.
    """
    test_client, _ = client
    analyst_headers = _login_as_analyst(test_client)
    admin_headers = _login(test_client)

    analyst_resp = test_client.get("/api/v1/operations/events/wh-red-1", headers=analyst_headers)
    assert analyst_resp.status_code == 404

    admin_resp = test_client.get("/api/v1/operations/events/wh-red-1", headers=admin_headers)
    assert admin_resp.status_code == 200
    assert admin_resp.json()["data"]["event_id"] == "wh-red-1"


def test_executive_dashboard_rejects_inverted_date_range(client):
    """Phase 2.3-3 regression: inverted ranges used to silently return an
    empty payload; surface 400 instead so the caller can fix the query.
    """
    test_client, _ = client
    headers = _login(test_client)
    response = test_client.get(
        "/api/v1/executive/dashboard?start_date=2026-05-21&end_date=2026-05-20",
        headers=headers,
    )
    assert response.status_code == 400
    assert "on or before" in response.json()["detail"].lower()


def test_operations_dashboard_accepts_filter_params(client):
    """Phase 2.3-1 regression: the dashboard endpoints used to drop
    severity/source/threat-type filters on the floor — the signature
    didn't declare them. Now they should at least be accepted (200).
    """
    test_client, _ = client
    headers = _login(test_client)
    response = test_client.get(
        "/api/v1/operations/dashboard?severities=critical&threat_types=Phishing",
        headers=headers,
    )
    assert response.status_code == 200


def test_diagnostics_data_sources_requires_admin(client):
    test_client, _ = client
    analyst_headers = _login_as_analyst(test_client)
    response = test_client.get("/api/v1/diagnostics/data-sources", headers=analyst_headers)
    assert response.status_code == 403


def test_notifications_scope_excludes_other_users_targeted_items(client):
    """Phase 2.2-16/17/18 regression: notifications with an explicit
    recipient must not be visible to other users, and read-state mutations
    from one user must not affect another user's targeted notifications.
    """
    test_client, fake_client = client
    # Inject one broadcast and two user-targeted notifications directly into
    # the bootstrap state. Use the internal state so the fixture stays small.
    state = dashboard_bootstrap.get_dashboard_state()
    state.notifications.append({
        "notification_id": "ntf-private-admin",
        "title": "Admin only",
        "message": "Admin private",
        "created_at": "2026-03-12T08:00:00Z",
        "type": "system",
        "unread": True,
        "recipient_user_id": "usr-admin",
    })
    state.notifications.append({
        "notification_id": "ntf-private-analyst",
        "title": "Analyst only",
        "message": "Analyst private",
        "created_at": "2026-03-12T08:01:00Z",
        "type": "system",
        "unread": True,
        "recipient_user_id": "usr-general",
    })

    analyst_headers = _login_as_analyst(test_client)
    listing = test_client.get("/api/v1/notifications", headers=analyst_headers)
    assert listing.status_code == 200
    ids = {item["notification_id"] for item in listing.json()["data"]["items"]}
    assert "ntf-private-admin" not in ids, "analyst must not see admin-only notification"
    assert "ntf-private-analyst" in ids
    # Broadcast notifications (no recipient_user_id) stay visible to everyone.
    assert "ntf-001" in ids

    # Trying to mark the admin-only notification as read should 404.
    blocked = test_client.post(
        "/api/v1/notifications/ntf-private-admin/read",
        headers=analyst_headers,
    )
    assert blocked.status_code == 404

    # Read-all must only mark the analyst's own + broadcast notifications.
    test_client.post("/api/v1/notifications/read-all", headers=analyst_headers, json={})
    admin_state_check = next(
        n for n in state.notifications if n["notification_id"] == "ntf-private-admin"
    )
    assert admin_state_check["unread"] is True, "admin notification must remain unread"


# ---------------------------------------------------------------------------
# Phase 2.6 — Reports / Exports regression tests
# ---------------------------------------------------------------------------


def test_export_download_analyst_cannot_access_other_users_export(client):
    # BUG-2.6-1: export_download had no ownership check — any logged-in user
    # could download any export job.  Now analysts get 404 for exports they
    # don't own.
    test_client, _ = client
    admin_headers = _login(test_client)
    analyst_headers = _login_as_analyst(test_client)

    # Admin creates an export via the executive report endpoint.
    resp = test_client.post(
        "/api/v1/reports/executive/export",
        headers=admin_headers,
        json={
            "export_format": "csv",
            "start_date": "2026-05-01",
            "end_date": "2026-05-21",
        },
    )
    assert resp.status_code in (200, 202), resp.text
    export_id = resp.json()["data"]["export_id"]

    # Admin can download their own export.
    dl_admin = test_client.get(f"/api/v1/exports/{export_id}/download", headers=admin_headers)
    # 200 if file is attached; 404 if no file was generated — both are valid
    # as long as the analyst is blocked below.
    assert dl_admin.status_code in (200, 404)

    # Analyst must NOT be able to download admin's export (404, not 200/403).
    dl_analyst = test_client.get(f"/api/v1/exports/{export_id}/download", headers=analyst_headers)
    assert dl_analyst.status_code == 404, (
        "analyst must get 404 for another user's export, got "
        f"{dl_analyst.status_code}: {dl_analyst.text}"
    )


def test_export_job_stores_owner_user_id(client):
    # BUG-2.6-2: export jobs previously didn't record owner_user_id, so the
    # ownership check in export_download had nothing to enforce.
    test_client, _ = client
    admin_headers = _login(test_client)

    resp = test_client.post(
        "/api/v1/reports/executive/export",
        headers=admin_headers,
        json={
            "export_format": "csv",
            "start_date": "2026-05-01",
            "end_date": "2026-05-21",
        },
    )
    assert resp.status_code in (200, 202), resp.text
    export_id = resp.json()["data"]["export_id"]

    import services.dashboard_bootstrap as _bs
    state = _bs.get_dashboard_state()
    job = state.get_export_job(export_id)
    assert job is not None
    assert job.get("owner_user_id") == "usr-admin", (
        f"export job should record owner_user_id='usr-admin', got {job.get('owner_user_id')!r}"
    )


def test_export_download_admin_can_access_any_export(client):
    # Admin role must bypass ownership check and download any export.
    test_client, _ = client
    analyst_headers = _login_as_analyst(test_client)
    admin_headers = _login(test_client)

    # Analyst creates an export.
    resp = test_client.post(
        "/api/v1/reports/executive/export",
        headers=analyst_headers,
        json={
            "export_format": "csv",
            "start_date": "2026-05-01",
            "end_date": "2026-05-21",
        },
    )
    assert resp.status_code in (200, 202), resp.text
    export_id = resp.json()["data"]["export_id"]

    # Admin can download analyst's export.
    dl = test_client.get(f"/api/v1/exports/{export_id}/download", headers=admin_headers)
    # 200 with file or 404 because no file artifact — either is fine, not 403.
    assert dl.status_code != 403, f"admin must not be blocked with 403, got {dl.status_code}"


def test_export_delete_job_removes_both_job_and_file(client):
    # BUG-2.6-3: TTL cleanup — verify delete_export_job removes job + file.
    test_client, _ = client
    import services.dashboard_bootstrap as _bs
    state = _bs.get_dashboard_state()

    # Directly create a job with a file via bootstrap.
    job = state.create_export_job(
        "csv",
        "test-report",
        report_type="test",
        file_content=b"col1,col2\n1,2\n",
        media_type="text/csv",
        owner_user_id="usr-admin",
    )
    export_id = job["export_id"]

    assert state.get_export_job(export_id) is not None
    assert state.get_export_file(export_id) is not None

    state.delete_export_job(export_id)

    assert state.get_export_job(export_id) is None
    assert state.get_export_file(export_id) is None


def test_export_download_expired_job_returns_404(client, monkeypatch):
    # BUG-2.6-3: expired exports must be cleaned up lazily and return 404.
    test_client, _ = client
    admin_headers = _login(test_client)

    # Freeze time so the export appears far in the past.
    from datetime import timezone as _tz
    import datetime as _dt
    import services.dashboard_router as _dr

    resp = test_client.post(
        "/api/v1/reports/executive/export",
        headers=admin_headers,
        json={
            "export_format": "csv",
            "start_date": "2026-05-01",
            "end_date": "2026-05-21",
        },
    )
    assert resp.status_code in (200, 202), resp.text
    export_id = resp.json()["data"]["export_id"]

    # Monkeypatch EXPORT_TTL_SECONDS to 0 so any export is immediately expired.
    monkeypatch.setattr(_dr, "EXPORT_TTL_SECONDS", 0)

    dl = test_client.get(f"/api/v1/exports/{export_id}/download", headers=admin_headers)
    assert dl.status_code == 404, f"expired export must 404, got {dl.status_code}"


def test_export_size_limit_rejected(client, monkeypatch):
    # BUG-2.6-4: exports larger than EXPORT_MAX_BYTES must be rejected 413.
    import services.dashboard_router as _dr
    monkeypatch.setattr(_dr, "EXPORT_MAX_BYTES", 5)  # 5-byte limit for the test

    test_client, _ = client
    admin_headers = _login(test_client)

    # Patch _build_ioc_export_artifact to return oversized content.
    def _big_artifact(items, fmt):
        return "csv", b"A" * 100, "text/csv"

    monkeypatch.setattr(_dr, "_build_ioc_export_artifact", _big_artifact)

    resp = test_client.post(
        "/api/v1/reports/ioc/export",
        headers=admin_headers,
        json={
            "export_format": "csv",
            "start_date": "2026-05-01",
            "end_date": "2026-05-21",
        },
    )
    assert resp.status_code == 413, f"oversized export must return 413, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# Phase 2.8 — Compat Router regression tests
# ---------------------------------------------------------------------------


def test_phase_2_8_login_cookie_is_httponly(client):
    """BUG-2.8-1 regression: compat /login must set httponly=True on the token cookie."""
    test_client, _ = client
    resp = test_client.post("/login", json={"username": "admin", "password": "admin123!"})
    assert resp.status_code == 200

    # TestClient exposes Set-Cookie via the response headers.
    set_cookie = resp.headers.get("set-cookie", "")
    assert "httponly" in set_cookie.lower(), (
        f"token cookie must carry HttpOnly flag but got: {set_cookie!r}"
    )


def test_phase_2_8_compat_overview_transformer_returns_int():
    """BUG-2.8-2 regression: _compat_overview must return SourcesActive as int, not str."""
    result = dashboard_compat_router._compat_overview({"sources_active": 5})
    assert isinstance(result["SourcesActive"], int)
    assert result["SourcesActive"] == 5

    result_str_input = dashboard_compat_router._compat_overview({"sources_active": "3"})
    assert isinstance(result_str_input["SourcesActive"], int)
    assert result_str_input["SourcesActive"] == 3

    result_none = dashboard_compat_router._compat_overview({"sources_active": None})
    assert isinstance(result_none["SourcesActive"], int)
    assert result_none["SourcesActive"] == 0

    # All other fields must remain int too — full shape check.
    full = dashboard_compat_router._compat_overview(
        {"active_ioc": 10, "critical_ioc_active": 4, "new_ioc": 7, "sources_active": 2}
    )
    assert full == {"ActiveIOC": 10, "CriticalIOCActive": 4, "NewIOC": 7, "SourcesActive": 2}
    assert all(isinstance(v, int) for v in full.values())
