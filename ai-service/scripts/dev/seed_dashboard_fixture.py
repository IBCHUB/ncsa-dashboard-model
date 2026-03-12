#!/usr/bin/env python
"""Seed or clean synthetic dashboard fixtures in remote ELK indices."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

import requests


ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "https://pluto-elk.ibusiness.co.th").rstrip("/")
DATALAKE_INDEX = os.getenv("DATALAKE_INDEX", "cyber-logs-datalake")
WAREHOUSE_INDEX = os.getenv("WAREHOUSE_INDEX", "cyber-logs-datawarehouse")
DATALAKE_API_KEY = os.getenv("DATALAKE_API_KEY", "")
WAREHOUSE_API_KEY = os.getenv("WAREHOUSE_API_KEY", "")

FIXTURE_IOC_TYPE = "domain"
FIXTURE_IOC_VALUE = "review-fixture-20260205.example"
FIXTURE_ACTION_ID = "fixture-action-review-20260205"
FIXTURE_EVENT_ID = "fixture-dl-action-review-20260205"
FIXTURE_EVENT_TIME = "2026-02-05T07:30:00Z"
FIXTURE_COLLECT_TIME = "2026-02-05T07:32:00Z"
FIXTURE_CREATED_AT = "2026-03-11T00:00:00Z"


def _headers(api_key: str) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    return headers


def _put(index: str, doc_id: str, payload: Dict[str, Any], api_key: str) -> Tuple[int, Dict[str, Any]]:
    response = requests.put(
        f"{ELASTICSEARCH_URL}/{index}/_doc/{doc_id}",
        headers=_headers(api_key),
        json=payload,
        timeout=60,
    )
    body = response.json() if response.content else {}
    return response.status_code, body


def _delete(index: str, doc_id: str, api_key: str) -> Tuple[int, Dict[str, Any]]:
    response = requests.delete(
        f"{ELASTICSEARCH_URL}/{index}/_doc/{doc_id}",
        headers=_headers(api_key),
        timeout=60,
    )
    body = response.json() if response.content else {}
    return response.status_code, body


def _get(index: str, doc_id: str, api_key: str) -> Tuple[int, Dict[str, Any]]:
    response = requests.get(
        f"{ELASTICSEARCH_URL}/{index}/_doc/{doc_id}",
        headers=_headers(api_key),
        timeout=60,
    )
    body = response.json() if response.content else {}
    return response.status_code, body


def _warehouse_fixture() -> Dict[str, Any]:
    return {
        "ioc_value": FIXTURE_IOC_VALUE,
        "ioc_type": FIXTURE_IOC_TYPE,
        "source_name": "SyntheticDashboardTest",
        "source_type": "manual_seed",
        "description": "Synthetic review item for Action Center integration testing",
        "threat_type": ["Phishing"],
        "severity": "critical",
        "tags": ["synthetic", "dashboard-fixture", "codex"],
        "reference": "https://example.invalid/synthetic/dashboard-action",
        "collect_time": FIXTURE_COLLECT_TIME,
        "event_time": FIXTURE_EVENT_TIME,
        "first_seen": FIXTURE_EVENT_TIME,
        "last_seen": FIXTURE_COLLECT_TIME,
        "ioc_age_days": 0,
        "geo_country": "TH",
        "ai_risk_score": 91,
        "ai_severity": "critical",
        "ai_severity_th": "วิกฤต",
        "ai_threat_types": ["Phishing"],
        "ai_threat_actors": ["Synthetic Actor"],
        "ai_mitre_techniques": ["T1566"],
        "ai_classification_confidence": 0.98,
        "ai_score_breakdown": {
            "target_sector": {
                "sector": "government",
                "sector_name": "Government",
                "sector_name_th": "ภาครัฐ",
                "icon": "🏛️",
            }
        },
        "ai_top_factors": [
            {"factor": "cross_source", "score": 25, "weighted_score": 25, "label": "Cross Source"},
            {"factor": "threat_type_severity", "score": 20, "weighted_score": 20, "label": "Threat Type Severity"},
        ],
        "score_model_version": "fixture-v1",
        "score_config_version": "fixture-v1",
        "credibility_score": 80,
        "impact_score": 90,
        "validation_status": "needs_review",
        "validation_reasons": ["synthetic_fixture_for_action_center"],
        "warehouse_eligible": False,
        "review_required": True,
        "review_state": "pending",
        "reviewed_by": None,
        "reviewed_at": None,
        "review_notes": None,
        "cleaning_flags": [],
        "sanitization_summary": {"sanitized": False, "flags": []},
        "processed_at": FIXTURE_COLLECT_TIME,
        "created_at": FIXTURE_CREATED_AT,
    }


def _datalake_fixture() -> Dict[str, Any]:
    return {
        "ioc_value": FIXTURE_IOC_VALUE,
        "ioc_type": FIXTURE_IOC_TYPE,
        "source_name": "SyntheticDashboardTest",
        "source_type": "manual_seed",
        "source_url": "https://example.invalid/synthetic/dashboard-action",
        "collect_time": FIXTURE_COLLECT_TIME,
        "event_time": FIXTURE_EVENT_TIME,
        "threat_type": ["Phishing"],
        "severity": "critical",
        "confidence": 10,
        "description": "Synthetic phishing observation for Action Center detail testing",
        "reference": "https://example.invalid/synthetic/dashboard-action",
        "tags": ["synthetic", "dashboard-fixture", "codex"],
        "geo_country": "TH",
        "geo_info": {"city": "Bangkok"},
        "source_ip": "203.0.113.10",
        "target_ip": "10.10.99.10",
        "enrichment": {
            "ip_info": {"country": "Thailand"},
            "related_entities": {"malware_family": ["SyntheticStealer"]},
        },
        "whois": {"org": "Synthetic Org", "registrant_email": "synthetic@example.invalid"},
        "asn_data": {"asn": "AS64555", "org": "Synthetic ASN"},
        "cluster_label": 20260205,
        "ai_processed": True,
        "created_at": FIXTURE_CREATED_AT,
    }


def seed() -> None:
    warehouse_status, warehouse_body = _put(WAREHOUSE_INDEX, FIXTURE_ACTION_ID, _warehouse_fixture(), WAREHOUSE_API_KEY)
    datalake_status, datalake_body = _put(DATALAKE_INDEX, FIXTURE_EVENT_ID, _datalake_fixture(), DATALAKE_API_KEY)
    print(
        json.dumps(
            {
                "action": "seed",
                "warehouse": {"status_code": warehouse_status, "body": warehouse_body},
                "datalake": {"status_code": datalake_status, "body": datalake_body},
                "fixture": {
                    "action_id": FIXTURE_ACTION_ID,
                    "event_id": FIXTURE_EVENT_ID,
                    "ioc_id": f"{FIXTURE_IOC_TYPE}::{FIXTURE_IOC_VALUE}",
                    "start_date": "2026-02-04",
                    "end_date": "2026-02-05",
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def cleanup() -> None:
    warehouse_status, warehouse_body = _delete(WAREHOUSE_INDEX, FIXTURE_ACTION_ID, WAREHOUSE_API_KEY)
    datalake_status, datalake_body = _delete(DATALAKE_INDEX, FIXTURE_EVENT_ID, DATALAKE_API_KEY)
    print(
        json.dumps(
            {
                "action": "cleanup",
                "warehouse": {"status_code": warehouse_status, "body": warehouse_body},
                "datalake": {"status_code": datalake_status, "body": datalake_body},
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def status() -> None:
    warehouse_status, warehouse_body = _get(WAREHOUSE_INDEX, FIXTURE_ACTION_ID, WAREHOUSE_API_KEY)
    datalake_status, datalake_body = _get(DATALAKE_INDEX, FIXTURE_EVENT_ID, DATALAKE_API_KEY)
    print(
        json.dumps(
            {
                "action": "status",
                "checked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "warehouse": {"status_code": warehouse_status, "found": warehouse_body.get("found", warehouse_status == 200)},
                "datalake": {"status_code": datalake_status, "found": datalake_body.get("found", datalake_status == 200)},
                "fixture": {
                    "action_id": FIXTURE_ACTION_ID,
                    "event_id": FIXTURE_EVENT_ID,
                    "ioc_id": f"{FIXTURE_IOC_TYPE}::{FIXTURE_IOC_VALUE}",
                },
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed or clean synthetic dashboard fixtures.")
    parser.add_argument("command", choices=["seed", "cleanup", "status"])
    args = parser.parse_args()

    if args.command == "seed":
        seed()
    elif args.command == "cleanup":
        cleanup()
    else:
        status()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
