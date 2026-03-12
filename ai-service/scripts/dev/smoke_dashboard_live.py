#!/usr/bin/env python
"""Run a live smoke test of dashboard APIs against configured ELK indices."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from fastapi.testclient import TestClient


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke test dashboard APIs with live ELK data")
    parser.add_argument("--start-date", default="2026-02-04")
    parser.add_argument("--end-date", default="2026-02-05")
    parser.add_argument("--action-id", default="")
    parser.add_argument("--output", default="")
    return parser.parse_args()


def _write_output(path: str, payload: Dict[str, Any]) -> None:
    if not path:
        return
    output_path = Path(path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2))


def main() -> None:
    args = _parse_args()
    os.environ.setdefault("AI_SERVICE_SKIP_STARTUP_PRELOAD", "true")
    os.environ.setdefault("AI_SERVICE_REQUIRE_AUTH", "false")

    from main import app  # noqa: WPS433

    smoke_requests: List[Dict[str, Any]] = [
        {"name": "executive_dashboard", "method": "GET", "path": f"/api/v1/executive/dashboard?start_date={args.start_date}&end_date={args.end_date}"},
        {"name": "operations_dashboard", "method": "GET", "path": f"/api/v1/operations/dashboard?start_date={args.start_date}&end_date={args.end_date}"},
        {"name": "operations_report", "method": "GET", "path": f"/api/v1/operations/reports/attack-origin?start_date={args.start_date}&end_date={args.end_date}"},
        {"name": "attack_time_report", "method": "GET", "path": f"/api/v1/operations/attack-time-report?start_date={args.start_date}&end_date={args.end_date}"},
        {"name": "actions", "method": "GET", "path": f"/api/v1/actions?start_date={args.start_date}&end_date={args.end_date}"},
        {"name": "iocs", "method": "GET", "path": f"/api/v1/iocs?start_date={args.start_date}&end_date={args.end_date}"},
        {"name": "ioc_analytics", "method": "GET", "path": f"/api/v1/ioc-analytics?tab=ioc-summary&start_date={args.start_date}&end_date={args.end_date}"},
        {"name": "news", "method": "GET", "path": f"/api/v1/news?start_date={args.start_date}&end_date={args.end_date}"},
    ]
    if args.action_id:
        smoke_requests.append({"name": "action_detail", "method": "GET", "path": f"/api/v1/actions/{args.action_id}"})

    results: List[Dict[str, Any]] = []
    with TestClient(app) as client:
        login = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123!"})
        login.raise_for_status()
        token = login.json()["data"]["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        for request in smoke_requests:
            response = client.request(request["method"], request["path"], headers=headers)
            entry: Dict[str, Any] = {
                "name": request["name"],
                "method": request["method"],
                "path": request["path"],
                "status_code": response.status_code,
            }
            if response.headers.get("content-type", "").startswith("application/json"):
                payload = response.json()
                entry["meta"] = payload.get("meta")
                entry["error"] = payload.get("error")
                data = payload.get("data")
                if isinstance(data, dict):
                    entry["sample_keys"] = sorted(list(data.keys()))[:20]
                    if "items" in data and isinstance(data["items"], list):
                        entry["sample_item_count"] = len(data["items"])
                results.append(entry)
            else:
                entry["body"] = response.text[:500]
                results.append(entry)

    output = {
        "start_date": args.start_date,
        "end_date": args.end_date,
        "elasticsearch_url": os.getenv("ELASTICSEARCH_URL"),
        "datalake_index": os.getenv("DATALAKE_INDEX"),
        "warehouse_index": os.getenv("WAREHOUSE_INDEX"),
        "results": results,
    }
    _write_output(args.output, output)
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
