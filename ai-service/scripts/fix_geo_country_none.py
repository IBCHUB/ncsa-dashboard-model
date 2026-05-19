#!/usr/bin/env python3
"""
Fix geo_country="None" (string literal) in warehouse to null.

The old pipeline converted Python None → str(None) → "None" in ES.
This script sets those to null so they don't pollute the Threat Map.

Usage:
    python scripts/fix_geo_country_none.py
    python scripts/fix_geo_country_none.py --dry-run
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elastic_client import WAREHOUSE_ELASTICSEARCH_URL, WAREHOUSE_INDEX

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


def run_update_by_query(url: str, index: str, dry_run: bool = False):
    if httpx is None:
        raise RuntimeError("httpx is required: pip install httpx")

    query = {
        "script": {
            "source": "ctx._source.geo_country = null",
            "lang": "painless",
        },
        "query": {
            "term": {"geo_country": "None"}
        },
    }

    if dry_run:
        count_resp = httpx.post(
            f"{url}/{index}/_count",
            json={"query": {"term": {"geo_country": "None"}}},
            timeout=120.0,
        )
        count_resp.raise_for_status()
        total = count_resp.json().get("count", 0)
        print(f"[DRY RUN] Would null out geo_country for {total:,} docs with geo_country='None'")
        return

    print(f"Running update_by_query on {url}/{index}...")
    t0 = time.time()

    resp = httpx.post(
        f"{url}/{index}/_update_by_query?wait_for_completion=false&conflicts=proceed",
        json=query,
        timeout=30.0,
    )
    resp.raise_for_status()
    task_id = resp.json().get("task")
    print(f"Task submitted: {task_id}")

    while True:
        time.sleep(10)
        task_resp = httpx.get(f"{url}/_tasks/{task_id}", timeout=30.0)
        task_resp.raise_for_status()
        task_data = task_resp.json()
        task_status = task_data.get("task", {}).get("status", {})
        completed = task_data.get("completed", False)
        total = task_status.get("total", 0)
        updated = task_status.get("updated", 0)
        elapsed = time.time() - t0
        rate = updated / elapsed if elapsed > 0 else 0

        print(
            f"\r  Updated: {updated:>12,} / {total:>12,} | "
            f"Elapsed: {elapsed:.0f}s | Rate: {rate:,.0f}/s",
            end="", flush=True,
        )

        if completed:
            response = task_data.get("response", {})
            print(f"\n\nDone in {elapsed:.1f}s")
            print(f"  Total: {response.get('total', 0):,}")
            print(f"  Updated: {response.get('updated', 0):,}")
            print(f"  Noops: {response.get('noops', 0):,}")
            print(f"  Failures: {len(response.get('failures', []))}")
            break


def main():
    parser = argparse.ArgumentParser(description="Fix geo_country='None' to null")
    parser.add_argument("--warehouse-url", default=WAREHOUSE_ELASTICSEARCH_URL)
    parser.add_argument("--warehouse-index", default=WAREHOUSE_INDEX)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    run_update_by_query(args.warehouse_url, args.warehouse_index, args.dry_run)


if __name__ == "__main__":
    main()
