#!/usr/bin/env python3
"""Run a live smoke test of external sharing APIs against a running server and real ELK data."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error, parse, request


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke test external sharing APIs against a live server")
    parser.add_argument("--base-url", default=os.getenv("EXTERNAL_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--reader-key", default=os.getenv("EXTERNAL_READER_API_KEY", ""))
    parser.add_argument("--writer-key", default=os.getenv("EXTERNAL_WRITER_API_KEY", ""))
    parser.add_argument("--indicator-id", default=os.getenv("EXTERNAL_INDICATOR_ID", ""))
    parser.add_argument("--page-size", type=int, default=20)
    parser.add_argument("--tlp", default="amber")
    parser.add_argument("--start-date", default=os.getenv("EXTERNAL_START_DATE", "2026-03-10"))
    parser.add_argument("--end-date", default=os.getenv("EXTERNAL_END_DATE", "2026-03-12"))
    parser.add_argument(
        "--output",
        default="",
        help="Optional path to write JSON results",
    )
    return parser.parse_args()


def _write_output(path: str, payload: Dict[str, Any]) -> None:
    if not path:
        return
    output_path = Path(path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))


def _build_url(base_url: str, path: str, query: Optional[Dict[str, Any]] = None) -> str:
    normalized_base = base_url.rstrip("/")
    normalized_path = path if path.startswith("/") else f"/{path}"
    if not query:
        return f"{normalized_base}{normalized_path}"
    cleaned: List[tuple[str, str]] = []
    for key, value in query.items():
        if value is None or value == "":
            continue
        if isinstance(value, list):
            for item in value:
                cleaned.append((key, str(item)))
            continue
        cleaned.append((key, str(value)))
    encoded = parse.urlencode(cleaned, doseq=True)
    return f"{normalized_base}{normalized_path}?{encoded}" if encoded else f"{normalized_base}{normalized_path}"


def _sample_keys(payload: Any) -> List[str]:
    if isinstance(payload, dict):
        return sorted(payload.keys())[:20]
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return sorted(payload[0].keys())[:20]
    return []


def _capture_success(response: Any, body: bytes) -> Dict[str, Any]:
    content_type = response.headers.get("Content-Type", "")
    entry: Dict[str, Any] = {
        "status_code": response.status,
        "content_type": content_type,
    }
    if content_type.startswith("application/json"):
        payload = json.loads(body.decode("utf-8"))
        if isinstance(payload, dict):
            entry["top_level_keys"] = sorted(payload.keys())
            if "data" in payload:
                entry["sample_keys"] = _sample_keys(payload["data"])
            if "meta" in payload and isinstance(payload["meta"], dict):
                entry["meta_keys"] = sorted(payload["meta"].keys())
        else:
            entry["top_level_type"] = type(payload).__name__
            entry["sample_keys"] = _sample_keys(payload)
        entry["payload"] = payload
    else:
        entry["body_preview"] = body[:500].decode("utf-8", errors="replace")
        entry["content_length"] = len(body)
    return entry


def _request_json(
    *,
    base_url: str,
    method: str,
    path: str,
    api_key: str,
    query: Optional[Dict[str, Any]] = None,
    body: Optional[Dict[str, Any]] = None,
    expected_statuses: tuple[int, ...] = (200,),
) -> Dict[str, Any]:
    url = _build_url(base_url, path, query)
    payload_bytes = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"X-API-Key": api_key}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = request.Request(url=url, method=method, data=payload_bytes, headers=headers)
    try:
        with request.urlopen(req) as response:
            raw = response.read()
            result = _capture_success(response, raw)
            if response.status not in expected_statuses:
                raise RuntimeError(f"{method} {path} returned {response.status}, expected {expected_statuses}")
            return result
    except error.HTTPError as exc:
        raw = exc.read()
        content_type = exc.headers.get("Content-Type", "")
        details: Dict[str, Any] = {
            "status_code": exc.code,
            "content_type": content_type,
            "body_preview": raw[:500].decode("utf-8", errors="replace"),
        }
        if content_type.startswith("application/json"):
            try:
                details["payload"] = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                pass
        if exc.code not in expected_statuses:
            raise RuntimeError(f"{method} {path} failed with {exc.code}: {details['body_preview']}") from exc
        return details


def _assert_json_envelope(entry: Dict[str, Any], *, required_data_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    payload = entry.get("payload")
    if not isinstance(payload, dict):
        raise RuntimeError("Expected JSON payload")
    for key in ("data", "meta", "error"):
        if key not in payload:
            raise RuntimeError(f"Missing '{key}' in response payload")
    if required_data_keys:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise RuntimeError("Expected response data to be an object")
        for key in required_data_keys:
            if key not in data:
                raise RuntimeError(f"Missing data key '{key}'")
    return payload


def _record(results: List[Dict[str, Any]], name: str, method: str, path: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    result = {
        "name": name,
        "method": method,
        "path": path,
        **{key: value for key, value in entry.items() if key != "payload"},
    }
    if "payload" in entry:
        payload = entry["payload"]
        result["top_level_keys"] = sorted(payload.keys()) if isinstance(payload, dict) else []
        if isinstance(payload, dict) and "data" in payload:
            result["sample_keys"] = _sample_keys(payload["data"])
    result["ok"] = True
    results.append(result)
    return entry


def main() -> None:
    args = _parse_args()
    if not args.reader_key:
        raise SystemExit("Missing --reader-key or EXTERNAL_READER_API_KEY")
    if not args.writer_key:
        raise SystemExit("Missing --writer-key or EXTERNAL_WRITER_API_KEY")

    timestamp = int(time.time())
    results: List[Dict[str, Any]] = []
    created_submission_ids: List[str] = []

    profile = _record(
        results,
        "profile",
        "GET",
        "/api/v1/external/profile",
        _request_json(base_url=args.base_url, method="GET", path="/api/v1/external/profile", api_key=args.reader_key),
    )
    _assert_json_envelope(profile, required_data_keys=["partner_id", "partner_name", "permissions", "max_tlp"])

    for name, path, key, required in [
        ("lookups_ioc_types", "/api/v1/external/lookups/ioc-types", args.reader_key, ["items"]),
        ("lookups_threat_types", "/api/v1/external/lookups/threat-types", args.reader_key, ["items"]),
        ("lookups_severities", "/api/v1/external/lookups/severities", args.reader_key, ["items"]),
        ("lookups_tlp_levels", "/api/v1/external/lookups/tlp-levels", args.reader_key, ["items"]),
        ("lookups_export_formats", "/api/v1/external/lookups/export-formats", args.writer_key, ["items"]),
    ]:
        entry = _record(
            results,
            name,
            "GET",
            path,
            _request_json(base_url=args.base_url, method="GET", path=path, api_key=key),
        )
        _assert_json_envelope(entry, required_data_keys=required)

    changes = _record(
        results,
        "changes",
        "GET",
        "/api/v1/external/changes",
        _request_json(
            base_url=args.base_url,
            method="GET",
            path="/api/v1/external/changes",
            api_key=args.reader_key,
            query={"page_size": args.page_size, "tlp": args.tlp},
        ),
    )
    changes_payload = _assert_json_envelope(changes, required_data_keys=["created", "updated", "revoked"])

    indicators = _record(
        results,
        "indicators",
        "GET",
        "/api/v1/external/indicators",
        _request_json(
            base_url=args.base_url,
            method="GET",
            path="/api/v1/external/indicators",
            api_key=args.reader_key,
            query={
                "page": 1,
                "page_size": args.page_size,
                "tlp": args.tlp,
                "start_date": args.start_date,
                "end_date": args.end_date,
            },
        ),
    )
    indicators_payload = _assert_json_envelope(indicators, required_data_keys=["items"])
    chosen_indicator = args.indicator_id
    if not chosen_indicator:
        items = indicators_payload["data"].get("items") or []
        if items:
            chosen_indicator = items[0]["indicator_id"]

    def run_indicator_detail_flow(indicator_id: str, *, retry_not_found: bool = False) -> None:
        encoded_indicator = parse.quote(indicator_id, safe="")
        for name, path, required in [
            ("indicator_detail", f"/api/v1/external/indicators/{encoded_indicator}", ["indicator_id", "ioc_type", "ioc_value"]),
            ("indicator_observations", f"/api/v1/external/indicators/{encoded_indicator}/observations", ["items"]),
            ("indicator_relationships", f"/api/v1/external/indicators/{encoded_indicator}/relationships", ["indicator_id", "graph_summary"]),
        ]:
            last_error: Optional[Exception] = None
            for attempt in range(10 if retry_not_found else 1):
                try:
                    entry = _record(
                        results,
                        name if attempt == 0 else f"{name}_retry_{attempt}",
                        "GET",
                        path,
                        _request_json(
                            base_url=args.base_url,
                            method="GET",
                            path=path,
                            api_key=args.reader_key,
                            query={"page": 1, "page_size": 5} if name == "indicator_observations" else None,
                        ),
                    )
                    break
                except RuntimeError as exc:
                    last_error = exc
                    if not retry_not_found or "404" not in str(exc) or attempt == 9:
                        raise
                    time.sleep(1)
            else:
                if last_error:
                    raise last_error
            _assert_json_envelope(entry, required_data_keys=required)

    if chosen_indicator:
        run_indicator_detail_flow(chosen_indicator)

    indicator_ioc = f"smoke-{timestamp}.example"
    indicator_submission = _record(
        results,
        "submit_indicator",
        "POST",
        "/api/v1/external/indicators",
        _request_json(
            base_url=args.base_url,
            method="POST",
            path="/api/v1/external/indicators",
            api_key=args.writer_key,
            body={
                "ioc_value": indicator_ioc,
                "ioc_type": "domain",
                "title": "Live smoke indicator submission",
                "description": "Live smoke test indicator",
                "threat_types": ["Phishing"],
                "severity": "high",
                "confidence": 80,
                "tlp": "green",
                "references": [f"https://smoke.example/{timestamp}/indicator"],
                "observed_at": "2026-03-12T01:00:00Z",
            },
        ),
    )
    indicator_submission_payload = _assert_json_envelope(indicator_submission, required_data_keys=["submission_id", "status"])
    created_submission_ids.append(indicator_submission_payload["data"]["submission_id"])
    if not chosen_indicator:
        chosen_indicator = f"domain::{indicator_ioc}"
        run_indicator_detail_flow(chosen_indicator, retry_not_found=True)

    event_submission = _record(
        results,
        "submit_event",
        "POST",
        "/api/v1/external/events",
        _request_json(
            base_url=args.base_url,
            method="POST",
            path="/api/v1/external/events",
            api_key=args.writer_key,
            body={
                "event_type": "incident_report",
                "title": "Live smoke event submission",
                "description": "Live smoke test event",
                "severity": "critical",
                "confidence": 90,
                "tlp": "amber",
                "observed_at": "2026-03-12T02:00:00Z",
                "indicators": [
                    {"ioc_value": f"198.51.100.{timestamp % 200 + 1}", "ioc_type": "ip"},
                    {"ioc_value": f"https://smoke-{timestamp}.example/login", "ioc_type": "url"},
                ],
                "references": [f"https://smoke.example/{timestamp}/event"],
            },
        ),
    )
    event_submission_payload = _assert_json_envelope(event_submission, required_data_keys=["submission_id", "status"])
    created_submission_ids.append(event_submission_payload["data"]["submission_id"])

    bulk_submission = _record(
        results,
        "submit_bulk",
        "POST",
        "/api/v1/external/bulk",
        _request_json(
            base_url=args.base_url,
            method="POST",
            path="/api/v1/external/bulk",
            api_key=args.writer_key,
            body={
                "default_tlp": "amber",
                "dedupe_strategy": "indicator_id",
                "items": [
                    {
                        "kind": "indicator",
                        "ioc_value": f"bulk-{timestamp}.example",
                        "ioc_type": "domain",
                        "description": "Live smoke bulk indicator",
                        "severity": "medium",
                        "confidence": 70,
                    },
                    {
                        "kind": "event",
                        "event_type": "bulk_event",
                        "description": "Live smoke bulk event",
                        "severity": "high",
                        "confidence": 75,
                        "indicators": [
                            {"ioc_value": f"203.0.113.{timestamp % 200 + 1}", "ioc_type": "ip"},
                        ],
                    },
                ],
            },
        ),
    )
    bulk_submission_payload = _assert_json_envelope(bulk_submission, required_data_keys=["submission_id", "status"])
    created_submission_ids.append(bulk_submission_payload["data"]["submission_id"])

    status_path = f"/api/v1/external/submissions/{parse.quote(created_submission_ids[0], safe='')}"
    submission_status = _record(
        results,
        "submission_status",
        "GET",
        status_path,
        _request_json(base_url=args.base_url, method="GET", path=status_path, api_key=args.writer_key),
    )
    _assert_json_envelope(submission_status, required_data_keys=["submission_id", "status", "accepted_count"])

    revoke_path = f"/api/v1/external/submissions/{parse.quote(created_submission_ids[0], safe='')}/revoke"
    revoke = _record(
        results,
        "revoke_submission",
        "POST",
        revoke_path,
        _request_json(base_url=args.base_url, method="POST", path=revoke_path, api_key=args.writer_key),
    )
    _assert_json_envelope(revoke, required_data_keys=["submission_id", "status", "updated_count"])

    for cleanup_submission_id in created_submission_ids[1:]:
        cleanup_path = f"/api/v1/external/submissions/{parse.quote(cleanup_submission_id, safe='')}/revoke"
        try:
            cleanup_entry = _request_json(base_url=args.base_url, method="POST", path=cleanup_path, api_key=args.writer_key)
            _record(results, f"cleanup_revoke_{cleanup_submission_id}", "POST", cleanup_path, cleanup_entry)
        except RuntimeError as exc:
            results.append(
                {
                    "name": f"cleanup_revoke_{cleanup_submission_id}",
                    "method": "POST",
                    "path": cleanup_path,
                    "ok": False,
                    "error": str(exc),
                }
            )

    export = _record(
        results,
        "create_export",
        "POST",
        "/api/v1/external/exports",
        _request_json(
            base_url=args.base_url,
            method="POST",
            path="/api/v1/external/exports",
            api_key=args.writer_key,
            body={
                "format": "json",
                "tlp": args.tlp,
                "ioc_types": ["domain", "ip"],
                "min_risk_score": 0,
                "start_date": args.start_date,
                "end_date": args.end_date,
            },
        ),
    )
    export_payload = _assert_json_envelope(export, required_data_keys=["export_id", "status", "download_url"])
    export_id = export_payload["data"]["export_id"]

    export_status_path = f"/api/v1/external/exports/{parse.quote(export_id, safe='')}"
    export_status = _record(
        results,
        "export_status",
        "GET",
        export_status_path,
        _request_json(base_url=args.base_url, method="GET", path=export_status_path, api_key=args.writer_key),
    )
    _assert_json_envelope(export_status, required_data_keys=["export_id", "status", "download_url", "record_count"])

    export_download_path = f"/api/v1/external/exports/{parse.quote(export_id, safe='')}/download"
    export_download = _record(
        results,
        "export_download",
        "GET",
        export_download_path,
        _request_json(base_url=args.base_url, method="GET", path=export_download_path, api_key=args.writer_key),
    )
    if (
        export_download.get("content_length", 0) <= 0
        and not export_download.get("body_preview")
        and "payload" not in export_download
    ):
        raise RuntimeError("Export download returned empty content")

    output = {
        "base_url": args.base_url,
        "indicator_id": chosen_indicator,
        "reader_key_present": bool(args.reader_key),
        "writer_key_present": bool(args.writer_key),
        "results": results,
    }
    _write_output(args.output, output)
    print(json.dumps(output, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
