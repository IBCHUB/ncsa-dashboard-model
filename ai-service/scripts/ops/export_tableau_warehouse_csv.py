#!/usr/bin/env python3
"""Export datawarehouse IOC records to Tableau-friendly CSV.

The export is intentionally "long" format:
- one source warehouse document can produce multiple rows when it has multiple
  threat types;
- `record_id` stays stable so Tableau can use COUNTD(record_id) for unique IOC
  counts;
- `threat_volume` is 1 per row and is intended for treemap size/volume.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_ES_URL = "http://192.168.100.43:9200"
DEFAULT_INDEX = "cyber-logs-datawarehouse"

SOURCE_INCLUDES = [
    "ioc_id",
    "ioc_type",
    "ioc_value",
    "canonical_id",
    "source",
    "source_name",
    "source_type",
    "sources",
    "source_count",
    "severity",
    "ai_severity",
    "ai_risk_score",
    "ai_classification_confidence",
    "ai_threat_types",
    "classification_mode",
    "classification_reason",
    "validation_status",
    "event_time",
    "first_seen",
    "last_seen",
    "collect_time",
    "published_at",
    "processed_at",
    "created_at",
    "target_sector",
    "ai_score_breakdown.target_sector",
    "source_actionable",
    "source_risk_score",
    "external_evidence_sources",
    "virustotal_malicious",
    "virustotal_suspicious",
    "related_doc_count",
    "source_campaigns",
    "source_target_countries",
    "source_malware_family",
    "geo_country",
    "country",
    "city",
    "asn_org",
    "asn_name",
    "network_owner",
]

CSV_COLUMNS = [
    "record_id",
    "ioc_id",
    "ioc_type",
    "ioc_value",
    "threat_type",
    "has_threat_type",
    "threat_type_severity",
    "threat_type_severity_rank",
    "threat_type_color",
    "source_severity",
    "source_severity_rank",
    "ai_severity",
    "ai_risk_score",
    "ai_classification_confidence",
    "source_name",
    "source_display_name",
    "source_type",
    "sources",
    "source_count",
    "validation_status",
    "classification_mode",
    "classification_reason",
    "sector_key",
    "sector_name",
    "sector_name_th",
    "country",
    "city",
    "asn_org",
    "event_time",
    "event_date",
    "event_month",
    "first_seen",
    "last_seen",
    "collect_time",
    "published_at",
    "published_date",
    "processed_at",
    "processed_date",
    "created_at",
    "source_actionable",
    "source_risk_score",
    "external_evidence_sources",
    "virustotal_malicious",
    "virustotal_suspicious",
    "related_doc_count",
    "source_campaigns",
    "source_target_countries",
    "source_malware_family",
    "threat_volume",
]

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "clean": 0,
}

THREAT_TYPE_SEVERITY: dict[str, tuple[str, int, str]] = {
    "apt": ("Critical", 4, "#e11d48"),
    "credential theft": ("Critical", 4, "#e11d48"),
    "data breach": ("Critical", 4, "#e11d48"),
    "defacement": ("Critical", 4, "#e11d48"),
    "exploited vulnerability": ("Critical", 4, "#e11d48"),
    "malware": ("Critical", 4, "#e11d48"),
    "ransomware": ("Critical", 4, "#e11d48"),
    "remote code execution": ("Critical", 4, "#e11d48"),
    "vulnerability": ("Critical", 4, "#e11d48"),
    "web defacement": ("Critical", 4, "#e11d48"),
    "botnet": ("High", 3, "#f97316"),
    "c2": ("High", 3, "#f97316"),
    "c2 server": ("High", 3, "#f97316"),
    "compromised": ("High", 3, "#f97316"),
    "ddos": ("High", 3, "#f97316"),
    "phishing": ("High", 3, "#f97316"),
    "phishing website": ("High", 3, "#f97316"),
    "brute force": ("Medium", 2, "#fbbf24"),
    "other": ("Low", 1, "#60a5fa"),
    "unknown": ("Low", 1, "#60a5fa"),
    "clean": ("Clean", 0, "#22c55e"),
    "unclassified": ("Unclassified", -1, "#64748b"),
}

SOURCE_LABELS = {
    "cyberint_iocs": "Cyberint IOCs",
    "cyble threat intelligence feed": "Cyble Threat Intelligence Feed",
    "misp": "MISP",
    "misp_attributes": "MISP Attributes",
    "zone-h": "Zone-H",
    "bleepingcomputer news": "BleepingComputer News",
    "darkreading": "DarkReading",
    "sandbox": "Sandbox",
}


def now_tag() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--es-url", default=os.environ.get("ELASTICSEARCH_URL", DEFAULT_ES_URL))
    parser.add_argument("--index", default=os.environ.get("WAREHOUSE_INDEX", DEFAULT_INDEX))
    parser.add_argument("--output", default="")
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--scroll-ttl", default="10m")
    parser.add_argument("--limit", type=int, default=0, help="Testing limit. 0 means full export.")
    parser.add_argument("--gzip", action="store_true", help="Write .csv.gz instead of plain .csv.")
    parser.add_argument("--progress-every", type=int, default=100_000)
    parser.add_argument("--slice-id", type=int, default=0, help="Elasticsearch sliced-scroll slice id.")
    parser.add_argument("--slice-max", type=int, default=1, help="Total Elasticsearch sliced-scroll slices.")
    return parser.parse_args()


def request_json(method: str, url: str, body: dict[str, Any] | None = None, timeout: int = 180) -> dict[str, Any]:
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Elasticsearch HTTP {exc.code} for {url}: {payload[:1000]}") from exc


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    return [value]


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "|".join(clean_text(item) for item in value if clean_text(item))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    text = str(value).strip()
    if text.lower() in {"none", "null", "n/a", "na"}:
        return ""
    return text


def first_value(*values: Any) -> str:
    for value in values:
        text = clean_text(value)
        if text:
            return text
    return ""


def date_part(value: Any) -> str:
    text = clean_text(value)
    if len(text) >= 10:
        return text[:10]
    return ""


def month_part(value: Any) -> str:
    text = clean_text(value)
    if len(text) >= 7:
        return text[:7]
    return ""


def source_display_name(raw: Any) -> str:
    text = clean_text(raw)
    if not text:
        return ""
    key = text.lower().replace("_", " ").strip()
    return SOURCE_LABELS.get(key, SOURCE_LABELS.get(text.lower(), text.replace("_", " ").title()))


def severity_rank(value: Any) -> str:
    text = clean_text(value).lower()
    if not text:
        return ""
    return str(SEVERITY_RANK.get(text, ""))


def threat_type_metadata(threat_type: str) -> tuple[str, int, str]:
    key = threat_type.lower().strip()
    return THREAT_TYPE_SEVERITY.get(key, ("Medium", 2, "#fbbf24"))


def get_sector(source: dict[str, Any]) -> tuple[str, str, str]:
    sector = source.get("target_sector")
    if not isinstance(sector, dict):
        sector = (
            source.get("ai_score_breakdown", {})
            .get("target_sector", {})
            if isinstance(source.get("ai_score_breakdown"), dict)
            else {}
        )
    if not isinstance(sector, dict):
        sector = {}
    return (
        clean_text(sector.get("sector")),
        clean_text(sector.get("sector_name")),
        clean_text(sector.get("sector_name_th")),
    )


def pick_country(source: dict[str, Any]) -> str:
    return first_value(source.get("country"), source.get("geo_country"))


def build_rows(hit: dict[str, Any]) -> list[dict[str, str]]:
    source = hit.get("_source", {})
    record_id = clean_text(source.get("canonical_id")) or clean_text(source.get("ioc_id")) or clean_text(hit.get("_id"))
    sector_key, sector_name, sector_name_th = get_sector(source)

    threat_types = [clean_text(item) for item in as_list(source.get("ai_threat_types"))]
    threat_types = [item for item in threat_types if item]
    has_threat_type = bool(threat_types)
    if not threat_types:
        threat_types = ["Unclassified"]

    rows: list[dict[str, str]] = []
    for threat_type in threat_types:
        threat_severity, threat_severity_rank, threat_color = threat_type_metadata(threat_type)
        row = {
            "record_id": record_id,
            "ioc_id": first_value(source.get("ioc_id"), source.get("canonical_id"), hit.get("_id")),
            "ioc_type": clean_text(source.get("ioc_type")),
            "ioc_value": clean_text(source.get("ioc_value")),
            "threat_type": threat_type,
            "has_threat_type": "true" if has_threat_type else "false",
            "threat_type_severity": threat_severity,
            "threat_type_severity_rank": str(threat_severity_rank),
            "threat_type_color": threat_color,
            "source_severity": clean_text(source.get("severity")),
            "source_severity_rank": severity_rank(source.get("severity")),
            "ai_severity": clean_text(source.get("ai_severity")),
            "ai_risk_score": clean_text(source.get("ai_risk_score")),
            "ai_classification_confidence": clean_text(source.get("ai_classification_confidence")),
            "source_name": first_value(source.get("source_name"), source.get("source")),
            "source_display_name": source_display_name(first_value(source.get("source_name"), source.get("source"))),
            "source_type": clean_text(source.get("source_type")),
            "sources": clean_text(source.get("sources")),
            "source_count": clean_text(source.get("source_count")),
            "validation_status": clean_text(source.get("validation_status")),
            "classification_mode": clean_text(source.get("classification_mode")),
            "classification_reason": clean_text(source.get("classification_reason")),
            "sector_key": sector_key,
            "sector_name": sector_name,
            "sector_name_th": sector_name_th,
            "country": pick_country(source),
            "city": clean_text(source.get("city")),
            "asn_org": first_value(source.get("asn_org"), source.get("asn_name"), source.get("network_owner")),
            "event_time": clean_text(source.get("event_time")),
            "event_date": date_part(source.get("event_time")),
            "event_month": month_part(source.get("event_time")),
            "first_seen": clean_text(source.get("first_seen")),
            "last_seen": clean_text(source.get("last_seen")),
            "collect_time": clean_text(source.get("collect_time")),
            "published_at": clean_text(source.get("published_at")),
            "published_date": date_part(source.get("published_at")),
            "processed_at": clean_text(source.get("processed_at")),
            "processed_date": date_part(source.get("processed_at")),
            "created_at": clean_text(source.get("created_at")),
            "source_actionable": clean_text(source.get("source_actionable")),
            "source_risk_score": clean_text(source.get("source_risk_score")),
            "external_evidence_sources": clean_text(source.get("external_evidence_sources")),
            "virustotal_malicious": clean_text(source.get("virustotal_malicious")),
            "virustotal_suspicious": clean_text(source.get("virustotal_suspicious")),
            "related_doc_count": clean_text(source.get("related_doc_count")),
            "source_campaigns": clean_text(source.get("source_campaigns")),
            "source_target_countries": clean_text(source.get("source_target_countries")),
            "source_malware_family": clean_text(source.get("source_malware_family")),
            "threat_volume": "1",
        }
        rows.append(row)
    return rows


def main() -> int:
    args = parse_args()
    output = args.output
    if not output:
        suffix = ".csv.gz" if args.gzip else ".csv"
        output = f"/opt/tcti/app/tableau_exports/warehouse_threat_volume_severity_{now_tag()}{suffix}"

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    opener = gzip.open if args.gzip else open
    docs_seen = 0
    rows_written = 0
    started = time.time()
    scroll_id = ""

    search_url = f"{args.es_url.rstrip('/')}/{args.index}/_search?scroll={args.scroll_ttl}"
    scroll_url = f"{args.es_url.rstrip('/')}/_search/scroll"
    clear_url = f"{args.es_url.rstrip('/')}/_search/scroll"

    query = {
        "size": args.batch_size,
        "sort": ["_doc"],
        "_source": {"includes": SOURCE_INCLUDES},
        "query": {"match_all": {}},
    }
    if args.slice_max > 1:
        if args.slice_id < 0 or args.slice_id >= args.slice_max:
            raise ValueError("--slice-id must be between 0 and --slice-max - 1")
        query["slice"] = {"id": args.slice_id, "max": args.slice_max}

    print(
        json.dumps(
            {
                "event": "export_start",
                "index": args.index,
                "output": str(output_path),
                "batch_size": args.batch_size,
                "limit": args.limit,
                "gzip": args.gzip,
                "slice_id": args.slice_id,
                "slice_max": args.slice_max,
            },
            ensure_ascii=False,
        ),
        file=sys.stderr,
        flush=True,
    )

    try:
        response = request_json("POST", search_url, query)
        scroll_id = clean_text(response.get("_scroll_id"))
        hits = response.get("hits", {}).get("hits", [])

        with opener(output_path, "wt", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()

            while hits:
                for hit in hits:
                    if args.limit and docs_seen >= args.limit:
                        hits = []
                        break
                    docs_seen += 1
                    for row in build_rows(hit):
                        writer.writerow(row)
                        rows_written += 1

                    if docs_seen % args.progress_every == 0:
                        elapsed = max(time.time() - started, 1)
                        print(
                            json.dumps(
                                {
                                    "event": "progress",
                                    "docs_seen": docs_seen,
                                    "rows_written": rows_written,
                                    "docs_per_second": round(docs_seen / elapsed, 2),
                                    "elapsed_seconds": round(elapsed, 1),
                                    "output_mb": round(output_path.stat().st_size / 1024 / 1024, 2),
                                },
                                ensure_ascii=False,
                            ),
                            file=sys.stderr,
                            flush=True,
                        )

                if args.limit and docs_seen >= args.limit:
                    break
                response = request_json("POST", scroll_url, {"scroll": args.scroll_ttl, "scroll_id": scroll_id})
                scroll_id = clean_text(response.get("_scroll_id", scroll_id))
                hits = response.get("hits", {}).get("hits", [])
    finally:
        if scroll_id:
            try:
                request_json("DELETE", clear_url, {"scroll_id": [scroll_id]}, timeout=30)
            except Exception as exc:  # pragma: no cover - cleanup best effort
                print(f"warning: failed to clear scroll: {exc}", file=sys.stderr)

    elapsed = max(time.time() - started, 1)
    summary = {
        "event": "export_complete",
        "index": args.index,
        "output": str(output_path),
        "docs_seen": docs_seen,
        "rows_written": rows_written,
        "elapsed_seconds": round(elapsed, 1),
        "docs_per_second": round(docs_seen / elapsed, 2),
        "output_bytes": output_path.stat().st_size,
        "output_mb": round(output_path.stat().st_size / 1024 / 1024, 2),
        "slice_id": args.slice_id,
        "slice_max": args.slice_max,
        "columns": CSV_COLUMNS,
    }
    summary_path = output_path.with_suffix(output_path.suffix + ".summary.json")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), file=sys.stderr, flush=True)
    print(str(output_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
