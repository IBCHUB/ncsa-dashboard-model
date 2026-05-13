#!/usr/bin/env python
"""Run a full contract smoke test for every dashboard API route."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

REPO_ROOT = Path(__file__).resolve().parents[3]
AI_SERVICE_ROOT = REPO_ROOT / "ai-service"
for candidate in (AI_SERVICE_ROOT / "venv" / "lib").glob("python*/site-packages"):
    if candidate.exists() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from fastapi import FastAPI
from fastapi.testclient import TestClient

import services.dashboard_bootstrap as dashboard_bootstrap  # noqa: E402
import services.dashboard_compat_router as dashboard_compat_router  # noqa: E402
import services.dashboard_router as dashboard_router  # noqa: E402
from test_support.dashboard_fake_backend import FakeElasticClient  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke test all dashboard API routes with a fake backend")
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "tmp" / "full-contract-smoke-results.json"),
        help="Path to JSON artifact output",
    )
    return parser.parse_args()


def _build_app() -> tuple[FastAPI, FakeElasticClient]:
    dashboard_bootstrap._state = None
    fake_client = FakeElasticClient()
    dashboard_router.get_elastic_client = lambda: fake_client
    app = FastAPI()
    app.include_router(dashboard_compat_router.router)
    app.include_router(dashboard_router.router)
    return app, fake_client


def _sample_keys(payload: Any) -> List[str]:
    if isinstance(payload, dict):
        return sorted(payload.keys())[:20]
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return sorted(payload[0].keys())[:20]
    return []


def _capture_response(response) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
    }
    if response.headers.get("content-type", "").startswith("application/json"):
        payload = response.json()
        entry["top_level_keys"] = sorted(payload.keys())
        if "data" in payload:
            entry["sample_keys"] = _sample_keys(payload["data"])
        if "res_result" in payload:
            entry["sample_keys"] = _sample_keys(payload["res_result"])
        if "meta" in payload:
            entry["meta_keys"] = sorted(payload["meta"].keys()) if isinstance(payload["meta"], dict) else []
        if "error" in payload:
            entry["error"] = payload["error"]
    else:
        entry["body"] = response.text[:500]
    return entry


def _call(
    client: TestClient,
    results: List[Dict[str, Any]],
    name: str,
    method: str,
    path: str,
    expected_statuses: Iterable[int] = (200,),
    headers: Dict[str, str] | None = None,
    **kwargs: Any,
):
    response = client.request(method, path, headers=headers, **kwargs)
    entry = {
        "name": name,
        "method": method,
        "path": path,
        **_capture_response(response),
    }
    entry["ok"] = response.status_code in set(expected_statuses)
    results.append(entry)
    if not entry["ok"]:
        raise RuntimeError(f"{name} failed with {response.status_code}: {response.text[:500]}")
    return response


def main() -> None:
    args = _parse_args()
    results: List[Dict[str, Any]] = []
    admin_password = "admin123!"
    export_id = ""

    app, _ = _build_app()
    with TestClient(app) as client:
        login = _call(
            client,
            results,
            "canonical_login",
            "POST",
            "/api/v1/auth/login",
            json={"username": "admin", "password": admin_password},
        )
        token = login.json()["data"]["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        _call(client, results, "canonical_me", "GET", "/api/v1/auth/me", headers=headers)
        _call(client, results, "lookup_threat_types", "GET", "/api/v1/lookups/threat-types?query=phish", headers=headers)
        _call(client, results, "lookup_severities", "GET", "/api/v1/lookups/severities", headers=headers)
        _call(client, results, "lookup_risk_levels", "GET", "/api/v1/lookups/risk-levels", headers=headers)
        _call(client, results, "lookup_sources", "GET", "/api/v1/lookups/sources?query=abuse", headers=headers)
        _call(client, results, "lookup_export_formats", "GET", "/api/v1/lookups/export-formats", headers=headers)
        _call(client, results, "lookup_assignees", "GET", "/api/v1/lookups/assignees?status=active&query=nat", headers=headers)
        _call(client, results, "lookup_enforcement_points", "GET", "/api/v1/lookups/enforcement-points?type=firewall", headers=headers)

        _call(client, results, "executive_dashboard", "GET", "/api/v1/executive/dashboard?start_date=2026-03-10&end_date=2026-03-11", headers=headers)
        _call(
            client,
            results,
            "executive_preview",
            "POST",
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
        _call(
            client,
            results,
            "executive_export",
            "POST",
            "/api/v1/reports/executive/export",
            expected_statuses=(202,),
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

        _call(client, results, "operations_dashboard", "GET", "/api/v1/operations/dashboard?start_date=2026-03-10&end_date=2026-03-11", headers=headers)
        _call(client, results, "operations_report", "GET", "/api/v1/operations/reports/attack-origin?start_date=2026-03-10&end_date=2026-03-11", headers=headers)
        _call(
            client,
            results,
            "operations_preview",
            "POST",
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
        _call(
            client,
            results,
            "operations_export",
            "POST",
            "/api/v1/reports/operations/attack-origin/export",
            expected_statuses=(202,),
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
        _call(client, results, "attack_time_report", "GET", "/api/v1/operations/attack-time-report?start_date=2026-03-10&end_date=2026-03-11", headers=headers)
        _call(client, results, "operations_event_detail", "GET", "/api/v1/operations/events/dl-1", headers=headers)

        _call(client, results, "actions_list", "GET", "/api/v1/actions?start_date=2026-03-10&end_date=2026-03-11", headers=headers)
        _call(client, results, "actions_detail", "GET", "/api/v1/actions/wh-1", headers=headers)
        _call(client, results, "actions_related_iocs", "GET", "/api/v1/actions/wh-1/related-iocs", headers=headers)
        _call(
            client,
            results,
            "actions_assign",
            "POST",
            "/api/v1/actions/wh-1/assign",
            headers=headers,
            json={"assignee_id": "usr-general", "handover_note": "Take first review"},
        )
        _call(
            client,
            results,
            "actions_false_positive",
            "POST",
            "/api/v1/actions/wh-1/false-positive",
            headers=headers,
            data={"reason_category": "benign", "justification": "Internal sinkhole domain"},
        )
        _call(
            client,
            results,
            "actions_block_ip",
            "POST",
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
        _call(
            client,
            results,
            "actions_preview",
            "POST",
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
        _call(
            client,
            results,
            "actions_export",
            "POST",
            "/api/v1/reports/actions/export",
            expected_statuses=(202,),
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

        _call(client, results, "iocs_list", "GET", "/api/v1/iocs?high_risk_only=true", headers=headers)
        _call(client, results, "iocs_detail", "GET", "/api/v1/iocs/domain::malicious.example", headers=headers)
        _call(client, results, "iocs_events", "GET", "/api/v1/iocs/domain::malicious.example/events", headers=headers)
        _call(client, results, "ioc_analytics_summary", "GET", "/api/v1/ioc-analytics?tab=ioc-summary", headers=headers)
        _call(client, results, "ioc_analytics_import", "GET", "/api/v1/ioc-analytics?tab=statistics-import", headers=headers)

        _call(
            client,
            results,
            "report_ioc_preview",
            "POST",
            "/api/v1/reports/ioc/preview",
            headers=headers,
            json={
                "start_date": "2026-03-10",
                "end_date": "2026-03-11",
                "threat_types": [],
                "sources": [],
                "ioc_types": [],
                "severities": [],
            },
        )
        report_ioc_export = _call(
            client,
            results,
            "report_ioc_export",
            "POST",
            "/api/v1/reports/ioc/export",
            expected_statuses=(202,),
            headers=headers,
            json={
                "start_date": "2026-03-10",
                "end_date": "2026-03-11",
                "threat_types": [],
                "sources": [],
                "ioc_types": [],
                "severities": [],
                "export_format": "csv",
            },
        )
        export_id = report_ioc_export.json()["data"]["export_id"]
        _call(client, results, "report_most_frequent_preview", "POST", "/api/v1/reports/most-frequent-threats/preview", headers=headers, json={
            "start_date": "2026-03-10",
            "end_date": "2026-03-11",
            "threat_types": [],
            "severities": [],
            "risk_levels": [],
        })
        _call(client, results, "export_status", "GET", f"/api/v1/exports/{export_id}", headers=headers)

        news_list = _call(client, results, "news_list", "GET", "/api/v1/news", headers=headers)
        article_id = news_list.json()["data"]["items"][0]["article_id"]
        _call(client, results, "news_detail", "GET", f"/api/v1/news/{article_id}", headers=headers)

        _call(client, results, "account_profile", "GET", "/api/v1/account/profile", headers=headers)
        _call(
            client,
            results,
            "account_profile_update",
            "PATCH",
            "/api/v1/account/profile",
            headers=headers,
            json={"phone_number": "089-999-9999"},
        )
        _call(
            client,
            results,
            "account_password_reset",
            "POST",
            "/api/v1/account/password/reset",
            headers=headers,
            json={
                "reset_mode": "change",
                "current_password": admin_password,
                "new_password": "Admin123!updated",
            },
        )
        admin_password = "Admin123!updated"

        create_user = _call(
            client,
            results,
            "users_create",
            "POST",
            "/api/v1/users",
            expected_statuses=(201,),
            headers=headers,
            json={
                "name": "Spec User",
                "email": "spec@example.com",
                "password": "Password123!",
                "group_id": "grp-general",
                "status": "active",
            },
        )
        user_id = create_user.json()["data"]["user_id"]
        _call(client, results, "users_list", "GET", "/api/v1/users?status=active", headers=headers)
        _call(
            client,
            results,
            "users_update",
            "PATCH",
            f"/api/v1/users/{user_id}",
            headers=headers,
            json={"status": "inactive", "phone_number": "081-234-5678"},
        )
        _call(client, results, "users_delete", "DELETE", f"/api/v1/users/{user_id}", headers=headers)

        create_group = _call(
            client,
            results,
            "groups_create",
            "POST",
            "/api/v1/user-groups",
            expected_statuses=(201,),
            headers=headers,
            json={
                "name": "Tier 2 Analysts",
                "permissions": [{"module": "IOC Data Lake", "read": True, "edit": False}],
            },
        )
        group_id = create_group.json()["data"]["group_id"]
        _call(client, results, "groups_list", "GET", "/api/v1/user-groups", headers=headers)
        _call(
            client,
            results,
            "groups_update",
            "PATCH",
            f"/api/v1/user-groups/{group_id}",
            headers=headers,
            json={
                "name": "Tier 2 Analysts Updated",
                "permissions": [{"module": "IOC Data Lake", "read": True, "edit": True}],
            },
        )
        _call(client, results, "groups_delete", "DELETE", f"/api/v1/user-groups/{group_id}", headers=headers)

        _call(client, results, "notifications_list", "GET", "/api/v1/notifications?unread_only=true", headers=headers)
        _call(client, results, "notifications_read_one", "POST", "/api/v1/notifications/ntf-001/read", headers=headers)
        _call(
            client,
            results,
            "notifications_read_all",
            "POST",
            "/api/v1/notifications/read-all",
            headers=headers,
            json={"type": "action_update"},
        )

        _call(client, results, "compat_login", "POST", "/login", json={"username": "admin", "password": admin_password})
        _call(client, results, "compat_dashboard", "GET", "/dashboard?start_date=2026-03-10&end_date=2026-03-11")
        _call(client, results, "compat_incident_by_severity", "GET", "/incidentbyseverity?start_date=2026-03-10&end_date=2026-03-11")
        _call(client, results, "compat_attack_time", "GET", "/attacktime?start_date=2026-03-10&end_date=2026-03-11")
        _call(client, results, "compat_intelligence_sources", "GET", "/intelligencesources?start_date=2026-03-10&end_date=2026-03-11")
        _call(client, results, "compat_threat_type_chart", "GET", "/threattype?start_date=2026-03-10&end_date=2026-03-11")
        _call(client, results, "compat_countries_by_threat_association", "GET", "/countriesbythreatassociation?start_date=2026-03-10&end_date=2026-03-11")
        _call(client, results, "compat_target_sectors", "GET", "/targetsectors?start_date=2026-03-10&end_date=2026-03-11")
        _call(client, results, "compat_lookup_threat_type", "GET", "/threat-type")
        _call(client, results, "compat_lookup_source", "GET", "/source")
        _call(client, results, "compat_lookup_severity", "GET", "/severity")
        _call(client, results, "compat_lookup_risk_level", "GET", "/rick-level")
        _call(client, results, "compat_lookup_export_type", "GET", "/export-type")

        _call(client, results, "canonical_logout", "POST", "/api/v1/auth/logout", headers=headers)
        relogin = _call(
            client,
            results,
            "canonical_relogin",
            "POST",
            "/api/v1/auth/login",
            json={"username": "admin", "password": admin_password},
        )
        delete_headers = {"Authorization": f"Bearer {relogin.json()['data']['access_token']}"}
        _call(
            client,
            results,
            "account_delete",
            "DELETE",
            "/api/v1/account",
            headers=delete_headers,
            json={"confirmation_text": "delete my user account", "reason": "contract smoke"},
        )

    summary = {
        "total_routes": len(results),
        "passed": sum(1 for item in results if item["ok"]),
        "failed": sum(1 for item in results if not item["ok"]),
    }
    payload = {"summary": summary, "results": results}
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2))
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
