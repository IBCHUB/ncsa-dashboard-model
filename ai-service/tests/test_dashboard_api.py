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
    assert report_payload["ranking"]["items"][0]["severity_distribution"]["critical"] >= 0

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

    summary_tab = test_client.get("/api/v1/ioc-analytics?tab=ioc-summary", headers=headers)
    assert summary_tab.status_code == 200
    assert summary_tab.json()["data"]["cards"]["total_ioc"] == 3
    assert summary_tab.json()["data"]["cards"]["active_ioc"] == 3
    assert summary_tab.json()["data"]["charts"]["severity_by_type"][0]["critical"] >= 0

    import_tab = test_client.get("/api/v1/ioc-analytics?tab=statistics-import", headers=headers)
    assert import_tab.status_code == 200
    assert import_tab.json()["data"]["charts"]["import_by_source"][0]["value"] >= 1


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
        "SourcesActive": "2",
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
