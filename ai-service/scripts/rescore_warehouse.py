#!/usr/bin/env python3
"""
Re-score existing warehouse documents using the updated AI Scorer.

Reads warehouse docs in batches via scroll API, recalculates ai_risk_score
and ai_severity using the corrected scorer, and bulk-updates in place.

Usage:
    python scripts/rescore_warehouse.py --batch 500
    python scripts/rescore_warehouse.py --batch 500 --dry-run
    python scripts/rescore_warehouse.py --batch 500 --warehouse-url http://192.168.100.43:9200
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elastic_client import (
    WAREHOUSE_ELASTICSEARCH_URL,
    WAREHOUSE_INDEX,
)
from models.scorer import calculate_risk_score

logger = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


def scroll_warehouse(
    url: str,
    index: str,
    batch_size: int = 500,
    scroll_time: str = "5m",
):
    if httpx is None:
        raise RuntimeError("httpx is required: pip install httpx")

    resp = httpx.post(
        f"{url}/{index}/_search?scroll={scroll_time}",
        json={
            "size": batch_size,
            "query": {"match_all": {}},
            "_source": [
                "ioc_value", "ioc_type", "description",
                "sources", "source_objects", "source_count",
                "external_evidence_sources", "source_risk_score",
                "ai_threat_types", "ai_threat_actors", "ai_mitre_techniques",
                "ai_classification_confidence", "ai_risk_score", "ai_severity",
                "domain_age_days", "ioc_age_days",
                "severity",
            ],
        },
        timeout=120.0,
    )
    resp.raise_for_status()
    data = resp.json()
    scroll_id = data.get("_scroll_id")
    hits = data["hits"]["hits"]

    while hits:
        yield hits

        resp = httpx.post(
            f"{url}/_search/scroll",
            json={"scroll": scroll_time, "scroll_id": scroll_id},
            timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
        scroll_id = data.get("_scroll_id")
        hits = data["hits"]["hits"]

    if scroll_id:
        try:
            httpx.delete(
                f"{url}/_search/scroll",
                json={"scroll_id": scroll_id},
                timeout=10.0,
            )
        except Exception:
            pass


def rescore_doc(doc: Dict[str, Any]) -> Dict[str, Any] | None:
    src = doc.get("_source", {})
    ioc_value = src.get("ioc_value", "")
    ioc_type = src.get("ioc_type", "")
    if not ioc_value:
        return None

    source_objects = src.get("source_objects") or []
    if not source_objects:
        raw_names = src.get("sources") or []
        if isinstance(raw_names, list):
            source_objects = [
                {"name": n, "confidence": 0, "type": "unknown"}
                for n in raw_names
                if isinstance(n, str) and n.strip()
            ]

    # Merge enrichment sources (VirusTotal, MISP, etc.) that are stored
    # in a separate field — the original pipeline counted these for
    # cross_source scoring but rescore was missing them.
    evidence_sources = src.get("external_evidence_sources") or []
    existing_names = {o["name"] for o in source_objects}
    source_risk_score = src.get("source_risk_score") or 0
    for ev in evidence_sources:
        if isinstance(ev, str) and ev.strip() and ev not in existing_names:
            source_objects.append(
                {"name": ev, "confidence": source_risk_score, "type": "source_evidence"}
            )
            existing_names.add(ev)

    threat_types = src.get("ai_threat_types") or []
    threat_actors = src.get("ai_threat_actors") or []
    mitre_techniques = src.get("ai_mitre_techniques") or []
    confidence = float(src.get("ai_classification_confidence") or 0.8)

    result = calculate_risk_score(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        description=src.get("description", ""),
        sources=source_objects or [ioc_value],
        domain_age_days=src.get("domain_age_days"),
        ioc_age_days=src.get("ioc_age_days"),
        threat_classification={
            "threat_types": threat_types,
            "threat_actors": threat_actors,
            "mitre_techniques": mitre_techniques,
            "confidence": confidence,
        },
    )

    new_score = result.get("risk_score", 0)
    new_severity = result.get("severity", "low")
    new_severity_th = result.get("severity_th", "ต่ำ")

    old_score = src.get("ai_risk_score", 0)
    old_severity = src.get("ai_severity", "")

    if new_score == old_score and new_severity == old_severity:
        return None

    return {
        "_id": doc["_id"],
        "ai_risk_score": new_score,
        "ai_severity": new_severity,
        "ai_severity_th": new_severity_th,
        "severity": new_severity,
        "ai_score_breakdown": result.get("breakdown", {}),
        "ai_top_factors": result.get("top_factors", []),
        "score_model_version": result.get("score_model_version"),
    }


def bulk_update(
    url: str,
    index: str,
    updates: List[Dict[str, Any]],
) -> int:
    if not updates:
        return 0

    lines = []
    for u in updates:
        doc_id = u.pop("_id")
        lines.append(json.dumps({"update": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps({"doc": u}))

    body = "\n".join(lines) + "\n"
    resp = httpx.post(
        f"{url}/_bulk",
        content=body.encode(),
        headers={"Content-Type": "application/x-ndjson"},
        timeout=120.0,
    )
    resp.raise_for_status()
    result = resp.json()
    errors = sum(1 for item in result.get("items", []) if item.get("update", {}).get("error"))
    return len(updates) - errors


def main():
    parser = argparse.ArgumentParser(description="Re-score warehouse documents")
    parser.add_argument("--batch", type=int, default=500, help="Batch size for scroll")
    parser.add_argument("--warehouse-url", default=WAREHOUSE_ELASTICSEARCH_URL)
    parser.add_argument("--warehouse-index", default=WAREHOUSE_INDEX)
    parser.add_argument("--dry-run", action="store_true", help="Calculate but don't write")
    parser.add_argument("--limit", type=int, default=0, help="Stop after N docs (0=all)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    print(f"Re-scoring warehouse: {args.warehouse_url}/{args.warehouse_index}")
    print(f"Batch size: {args.batch}, Dry run: {args.dry_run}")

    total_scanned = 0
    total_changed = 0
    total_written = 0
    severity_before: Dict[str, int] = {}
    severity_after: Dict[str, int] = {}
    t0 = time.time()

    for batch in scroll_warehouse(args.warehouse_url, args.warehouse_index, args.batch):
        updates = []
        for doc in batch:
            total_scanned += 1
            src = doc.get("_source", {})
            old_sev = src.get("ai_severity", src.get("severity", "unknown"))
            severity_before[old_sev] = severity_before.get(old_sev, 0) + 1

            update = rescore_doc(doc)
            if update:
                total_changed += 1
                new_sev = update["ai_severity"]
                severity_after[new_sev] = severity_after.get(new_sev, 0) + 1
                updates.append(update)
            else:
                severity_after[old_sev] = severity_after.get(old_sev, 0) + 1

        if updates and not args.dry_run:
            written = bulk_update(args.warehouse_url, args.warehouse_index, updates)
            total_written += written

        elapsed = time.time() - t0
        rate = total_scanned / elapsed if elapsed > 0 else 0
        print(
            f"\r  Scanned: {total_scanned:>10,} | Changed: {total_changed:>10,} | "
            f"Written: {total_written:>10,} | Rate: {rate:,.0f}/s",
            end="", flush=True,
        )

        if args.limit and total_scanned >= args.limit:
            print(f"\n  Stopped at limit={args.limit}")
            break

    elapsed = time.time() - t0
    print(f"\n\nDone in {elapsed:.1f}s")
    print(f"  Total scanned:  {total_scanned:,}")
    print(f"  Total changed:  {total_changed:,}")
    print(f"  Total written:  {total_written:,}")

    print(f"\n{'SEVERITY BEFORE':=<50}")
    for sev, count in sorted(severity_before.items(), key=lambda x: -x[1]):
        pct = count / total_scanned * 100 if total_scanned else 0
        print(f"  {sev:10s}  {count:>10,}  ({pct:5.1f}%)")

    print(f"\n{'SEVERITY AFTER':=<50}")
    for sev, count in sorted(severity_after.items(), key=lambda x: -x[1]):
        pct = count / total_scanned * 100 if total_scanned else 0
        print(f"  {sev:10s}  {count:>10,}  ({pct:5.1f}%)")


if __name__ == "__main__":
    main()
