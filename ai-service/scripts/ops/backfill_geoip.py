"""
Backfill geo_country for warehouse documents that have IP-type IOCs
but are missing country data.

Uses MaxMind GeoLite2-Country (free) for lookups.

Examples:
  # Dry-run: see how many docs would be enriched
  python scripts/ops/backfill_geoip.py

  # Actually write updates
  python scripts/ops/backfill_geoip.py --write

  # Limit to 1000 documents
  python scripts/ops/backfill_geoip.py --write --limit 1000
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from elastic_client import ElasticClient  # noqa: E402
from utils.geoip_enrichment import lookup_country, lookup_country_detail  # noqa: E402


IP_TYPES = {"ip", "ipv4", "ipv6", "ip-src", "ip-dst", "ip_address", "ip_addresses"}


def find_missing_geo_docs(
    client: ElasticClient,
    limit: int = 0,
) -> List[Dict[str, Any]]:
    """Find warehouse docs with IP IOCs but no geo_country."""
    body = {
        "query": {
            "bool": {
                "must": [
                    {"terms": {"ioc_type.keyword": list(IP_TYPES)}},
                ],
                "must_not": [
                    {"exists": {"field": "geo_country"}},
                ],
            }
        },
        "sort": [{"event_time": {"order": "desc", "unmapped_type": "date"}}],
        "_source": ["ioc_type", "ioc_value", "geo_country"],
    }

    print("  Searching for IP docs without geo_country...")
    hits = client.scroll_search(client.warehouse_index, body, page_size=2000)
    docs = [{"_id": hit["_id"], **hit["_source"]} for hit in hits]
    if limit > 0:
        docs = docs[:limit]
    print(f"  Found {len(docs)} IP documents missing geo_country")
    return docs


def find_empty_geo_docs(
    client: ElasticClient,
    limit: int = 0,
) -> List[Dict[str, Any]]:
    """Find warehouse docs with IP IOCs and empty string geo_country."""
    body = {
        "query": {
            "bool": {
                "must": [
                    {"terms": {"ioc_type.keyword": list(IP_TYPES)}},
                    {"term": {"geo_country.keyword": ""}},
                ],
            }
        },
        "sort": [{"event_time": {"order": "desc", "unmapped_type": "date"}}],
        "_source": ["ioc_type", "ioc_value", "geo_country"],
    }

    print("  Searching for IP docs with empty geo_country...")
    hits = client.scroll_search(client.warehouse_index, body, page_size=2000)
    docs = [{"_id": hit["_id"], **hit["_source"]} for hit in hits]
    if limit > 0:
        docs = docs[:limit]
    print(f"  Found {len(docs)} IP documents with empty geo_country")
    return docs


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Backfill geo_country for IP-type warehouse documents using GeoIP."
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Actually write updates to warehouse (default: dry-run)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum documents to process (0 = all)",
    )
    parser.add_argument(
        "--summary-file",
        help="Optional path to write JSON summary output",
    )
    args = parser.parse_args()

    client = ElasticClient()

    # Find docs missing geo_country (field doesn't exist OR is empty string)
    missing_docs = find_missing_geo_docs(client, limit=args.limit)
    empty_docs = find_empty_geo_docs(
        client,
        limit=max(args.limit - len(missing_docs), 0) if args.limit > 0 else 0,
    )

    all_docs = missing_docs + empty_docs
    # Deduplicate by _id
    seen_ids = set()
    unique_docs = []
    for doc in all_docs:
        if doc["_id"] not in seen_ids:
            seen_ids.add(doc["_id"])
            unique_docs.append(doc)

    print(f"\n=== GeoIP Backfill ({len(unique_docs)} candidates) ===")

    enriched = 0
    failed_lookup = 0
    country_counts: Counter = Counter()
    updates: List[Dict[str, Any]] = []

    for doc in unique_docs:
        ip_value = str(doc.get("ioc_value", "")).strip()
        detail = lookup_country_detail(ip_value)
        if not detail:
            failed_lookup += 1
            continue

        country_code = detail["iso_code"]
        country_counts[country_code] += 1
        enriched += 1
        updates.append({
            "doc_id": doc["_id"],
            "update_body": {"geo_country": country_code},
        })

    print(f"  Enrichable: {enriched}")
    print(f"  Failed lookup (private/invalid IP): {failed_lookup}")
    print(f"  Top countries: {dict(country_counts.most_common(20))}")

    written = 0
    write_failed = 0

    if args.write and updates:
        print(f"\n  Writing {len(updates)} updates to warehouse...")
        CHUNK_SIZE = 500
        for chunk_start in range(0, len(updates), CHUNK_SIZE):
            chunk = updates[chunk_start : chunk_start + CHUNK_SIZE]
            for item in chunk:
                try:
                    success = client.update_warehouse_document(
                        item["doc_id"], item["update_body"]
                    )
                    if success:
                        written += 1
                    else:
                        write_failed += 1
                except Exception as exc:
                    write_failed += 1
                    print(f"    Failed to update {item['doc_id']}: {exc}")
            progress = min(chunk_start + CHUNK_SIZE, len(updates))
            print(f"    Progress: {progress}/{len(updates)} ({written} written, {write_failed} failed)")

    summary = {
        "mode": "write" if args.write else "dry-run",
        "total_candidates": len(unique_docs),
        "enrichable": enriched,
        "failed_lookup": failed_lookup,
        "written": written,
        "write_failed": write_failed,
        "top_countries": dict(country_counts.most_common(20)),
    }

    if args.summary_file:
        output_path = Path(args.summary_file).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2))

    print(f"\n{json.dumps(summary, ensure_ascii=False, indent=2)}")
    return 0 if write_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
