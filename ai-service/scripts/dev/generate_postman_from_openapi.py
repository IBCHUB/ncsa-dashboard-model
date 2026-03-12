#!/usr/bin/env python
"""Generate Postman artifacts from the dashboard OpenAPI spec."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml


ROOT = Path(__file__).resolve().parents[3]
SPEC_PATH = ROOT / "docs" / "api-spec" / "ncsa-dashboard-openapi.yaml"
OUTPUT_DIR = ROOT / "docs" / "api-spec" / "postman"
COLLECTION_PATH = OUTPUT_DIR / "ncsa-dashboard.postman_collection.json"
ENV_PATH = OUTPUT_DIR / "ncsa-dashboard.local.postman_environment.json"


def _path_with_variables(path: str) -> str:
    return re.sub(r"\{([^}]+)\}", r"{{\1}}", path)


def _request_name(method: str, path: str, summary: str | None) -> str:
    return summary or f"{method.upper()} {path}"


def _default_json_body(schema: Dict[str, Any], examples: Dict[str, Any] | None) -> Dict[str, Any]:
    if examples:
        first = next(iter(examples.values()))
        if isinstance(first, dict) and "value" in first:
            return first["value"]
    if "$ref" in schema:
        return {}
    if schema.get("type") == "object":
        return {
            key: None
            for key in (schema.get("properties") or {}).keys()
        }
    return {}


def _build_request(path: str, method: str, spec: Dict[str, Any]) -> Dict[str, Any]:
    raw_url = "{{base_url}}" + _path_with_variables(path)
    headers: List[Dict[str, str]] = []
    body: Dict[str, Any] | None = None
    query_params: List[Dict[str, str]] = []

    security = spec.get("security")
    if security != []:
        headers.append({"key": "Authorization", "value": "Bearer {{bearer_token}}", "type": "text"})

    for parameter in spec.get("parameters") or []:
        if parameter.get("in") != "query":
            continue
        name = parameter.get("name")
        if not name:
            continue
        query_params.append({"key": name, "value": "{{" + name + "}}", "disabled": False})

    request_body = spec.get("requestBody") or {}
    content = request_body.get("content") or {}
    if "application/json" in content:
        headers.append({"key": "Content-Type", "value": "application/json", "type": "text"})
        media = content["application/json"]
        payload = _default_json_body(media.get("schema") or {}, media.get("examples"))
        body = {"mode": "raw", "raw": json.dumps(payload, indent=2)}
    elif "multipart/form-data" in content:
        media = content["multipart/form-data"]
        schema = media.get("schema") or {}
        formdata = []
        for key in (schema.get("properties") or {}).keys():
            formdata.append({"key": key, "value": "", "type": "text"})
        body = {"mode": "formdata", "formdata": formdata}

    request: Dict[str, Any] = {
        "method": method.upper(),
        "header": headers,
        "url": {"raw": raw_url, "query": query_params},
    }
    if body is not None:
        request["body"] = body
    return request


def main() -> None:
    spec = yaml.safe_load(SPEC_PATH.read_text())
    folders: Dict[str, List[Dict[str, Any]]] = {}

    for path, methods in spec.get("paths", {}).items():
        for method, operation in methods.items():
            if not isinstance(operation, dict):
                continue
            tags = operation.get("tags") or ["Misc"]
            folder_name = tags[0]
            folders.setdefault(folder_name, []).append(
                {
                    "name": _request_name(method, path, operation.get("summary")),
                    "request": _build_request(path, method, operation),
                }
            )

    collection = {
        "info": {
            "name": "NCSA Dashboard Web API",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "description": "Generated from docs/api-spec/ncsa-dashboard-openapi.yaml",
        },
        "item": [
            {
                "name": folder,
                "item": items,
            }
            for folder, items in folders.items()
        ],
        "variable": [
            {"key": "base_url", "value": "http://127.0.0.1:8000"},
            {"key": "bearer_token", "value": ""},
            {"key": "start_date", "value": "2026-02-04"},
            {"key": "end_date", "value": "2026-02-05"},
            {"key": "page", "value": "1"},
            {"key": "page_size", "value": "20"},
            {"key": "sort_by", "value": "risk"},
            {"key": "sort_order", "value": "desc"},
            {"key": "query", "value": ""},
            {"key": "threat_types", "value": ""},
            {"key": "sources", "value": ""},
            {"key": "severities", "value": ""},
            {"key": "risk_levels", "value": ""},
            {"key": "ioc_types", "value": ""},
            {"key": "status", "value": ""},
            {"key": "high_risk_only", "value": "false"},
            {"key": "tab", "value": "ioc-summary"},
            {"key": "validation_status", "value": "needs_review"},
            {"key": "review_state", "value": "pending"},
            {"key": "report_key", "value": "attack-origin"},
            {"key": "event_id", "value": "siOlLJwBShRd39Jer2tm"},
            {"key": "action_id", "value": "fixture-action-review-20260205"},
            {"key": "ioc_id", "value": "domain::alex-fabow.online"},
            {"key": "article_id", "value": "siOlLJwBShRd39Jer2tm"},
            {"key": "export_id", "value": ""},
        ],
    }

    environment = {
        "name": "NCSA Dashboard Local",
        "values": [
            {"key": "base_url", "value": "http://127.0.0.1:8000", "enabled": True},
            {"key": "bearer_token", "value": "", "enabled": True},
            {"key": "start_date", "value": "2026-02-04", "enabled": True},
            {"key": "end_date", "value": "2026-02-05", "enabled": True},
            {"key": "page", "value": "1", "enabled": True},
            {"key": "page_size", "value": "20", "enabled": True},
            {"key": "sort_by", "value": "risk", "enabled": True},
            {"key": "sort_order", "value": "desc", "enabled": True},
            {"key": "query", "value": "", "enabled": True},
            {"key": "threat_types", "value": "", "enabled": True},
            {"key": "sources", "value": "", "enabled": True},
            {"key": "severities", "value": "", "enabled": True},
            {"key": "risk_levels", "value": "", "enabled": True},
            {"key": "ioc_types", "value": "", "enabled": True},
            {"key": "status", "value": "", "enabled": True},
            {"key": "high_risk_only", "value": "false", "enabled": True},
            {"key": "tab", "value": "ioc-summary", "enabled": True},
            {"key": "validation_status", "value": "needs_review", "enabled": True},
            {"key": "review_state", "value": "pending", "enabled": True},
            {"key": "report_key", "value": "attack-origin", "enabled": True},
            {"key": "event_id", "value": "siOlLJwBShRd39Jer2tm", "enabled": True},
            {"key": "action_id", "value": "fixture-action-review-20260205", "enabled": True},
            {"key": "ioc_id", "value": "domain::alex-fabow.online", "enabled": True},
            {"key": "article_id", "value": "siOlLJwBShRd39Jer2tm", "enabled": True},
            {"key": "export_id", "value": "", "enabled": True},
        ],
        "_postman_variable_scope": "environment",
        "_postman_exported_at": "2026-03-11T00:00:00Z",
        "_postman_exported_using": "Codex",
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    COLLECTION_PATH.write_text(json.dumps(collection, indent=2))
    ENV_PATH.write_text(json.dumps(environment, indent=2))
    print(f"Wrote {COLLECTION_PATH}")
    print(f"Wrote {ENV_PATH}")


if __name__ == "__main__":
    main()
