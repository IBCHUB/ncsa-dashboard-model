"""
Targeted Data Lake -> Warehouse backfill for selected source index patterns.

This is intentionally separate from /pipeline/run because the production
readonly datalake alias can contain tens of millions of CyberInt records. Use
this script when we need to backfill a small source family such as MISP or
external tcti-feeds without advancing the global pipeline cursor.

Examples:
  python scripts/ops/backfill_targeted_datalake_sources.py --dry-run \
    --index-pattern 'misp_attributes-*' --index-pattern 'tcti-feeds-*'

  python scripts/ops/backfill_targeted_datalake_sources.py --write --force \
    --index-pattern 'misp_attributes-*' --index-pattern 'tcti-feeds-*'
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Sequence, Tuple


AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from elastic_client import ElasticClient  # noqa: E402
from models.validation import REJECTED  # noqa: E402
from utils.pipeline_documents import build_enriched_ioc_document  # noqa: E402


def _source_index(doc: Dict[str, Any]) -> str:
    return str(doc.get("_index") or doc.get("source_index") or "").strip()


def _group_key(doc: Dict[str, Any]) -> Tuple[str, str]:
    return (
        ElasticClient.normalize_ioc_type(doc.get("ioc_type")),
        ElasticClient.normalize_ioc_value(doc.get("ioc_value")).lower(),
    )


def _build_index_filter(index_patterns: Sequence[str], exclude_patterns: Sequence[str]) -> Dict[str, Any]:
    must = []
    if index_patterns:
        must.append({
            "bool": {
                "should": [{"wildcard": {"_index": pattern}} for pattern in index_patterns],
                "minimum_should_match": 1,
            }
        })

    must_not = [{"wildcard": {"_index": pattern}} for pattern in exclude_patterns]
    return {"bool": {"must": must or [{"match_all": {}}], "must_not": must_not}}


def search_target_hits(
    client: ElasticClient,
    *,
    index_patterns: Sequence[str],
    exclude_patterns: Sequence[str],
    limit: int,
) -> List[Dict[str, Any]]:
    body = {
        "query": _build_index_filter(index_patterns, exclude_patterns),
        "sort": [{"_doc": {"order": "asc"}}],
        "track_total_hits": True,
        "size": limit,
    }
    result = client._search_index(client.datalake_index, body)
    return list(result.get("hits", {}).get("hits", []) or [])


def normalize_hits(client: ElasticClient, hits: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [client._normalize_datalake_hit(hit) for hit in hits]


def filter_unprocessed(
    client: ElasticClient,
    docs: Sequence[Dict[str, Any]],
    *,
    force: bool,
) -> Tuple[List[Dict[str, Any]], Counter[str]]:
    if force:
        return list(docs), Counter()

    state_map = client.get_processed_state_map(docs)
    skipped: Counter[str] = Counter()
    selected: List[Dict[str, Any]] = []
    finished = {"processed", "rejected", "quarantined"}
    for doc in docs:
        state = state_map.get(client._build_processed_state_id(doc))
        if state and state.get("status") in finished:
            skipped[str(state.get("status") or "existing")] += 1
            continue
        selected.append(doc)
    return selected, skipped


def group_documents(docs: Sequence[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for doc in docs:
        key = _group_key(doc)
        if not key[1]:
            key = ("unknown", str(doc.get("_id") or doc.get("source_fingerprint") or ""))
        grouped.setdefault(key, []).append(doc)
    return grouped


def build_and_write(
    client: ElasticClient,
    docs: Sequence[Dict[str, Any]],
    *,
    write: bool,
) -> Dict[str, Any]:
    grouped = group_documents(docs)
    source_indices = Counter(_source_index(doc) for doc in docs)
    adapters = Counter(str(doc.get("adapter_name") or "unknown") for doc in docs)
    statuses: Counter[str] = Counter()
    modes: Counter[str] = Counter()
    source_names: Counter[str] = Counter()
    warehouse_items: List[Dict[str, Any]] = []
    state_items: List[Dict[str, Any]] = []
    quarantined = 0
    failed = 0
    errors: List[Dict[str, Any]] = []

    for ioc_docs in grouped.values():
        first = ioc_docs[0]
        if first.get("adapter_status") == "quarantined":
            quarantined += len(ioc_docs)
            if write:
                for doc in ioc_docs:
                    if not client.save_quarantine(doc, reason=doc.get("quarantine_reason")):
                        failed += 1
            continue

        try:
            result = build_enriched_ioc_document(ioc_docs)
            document = result["document"]
            doc_id = ElasticClient._build_warehouse_doc_id(document)
            status = str(document.get("validation_status") or "unknown")
            statuses[status] += 1
            modes[str(document.get("classification_mode") or "unknown")] += 1
            source_names[str(document.get("source_name") or "unknown")] += 1
            warehouse_items.append({"doc_id": doc_id, "document": dict(document)})
            state_status = "rejected" if status == REJECTED else "processed"
            for source_doc in ioc_docs:
                state_items.append({
                    "doc": source_doc,
                    "status": state_status,
                    "warehouse_doc_id": doc_id,
                })
        except Exception as exc:  # pragma: no cover - operational guard
            failed += 1
            errors.append({
                "source_index": _source_index(first),
                "ioc_type": first.get("ioc_type"),
                "ioc_value": first.get("ioc_value"),
                "error": str(exc),
            })

    warehouse_result = {"success": 0, "failed": 0, "failed_ids": []}
    state_result = {"success": 0, "failed": 0, "failed_ids": []}
    if write and warehouse_items:
        warehouse_result = client.bulk_save_to_warehouse(warehouse_items)
        failed += int(warehouse_result.get("failed", 0) or 0)
        failed_ids = set(warehouse_result.get("failed_ids") or [])
        state_items = [
            item for item in state_items
            if item.get("warehouse_doc_id") not in failed_ids
        ]

    if write and state_items:
        state_result = client.bulk_mark_source_states(state_items)
        failed += int(state_result.get("failed", 0) or 0)

    return {
        "source_indices": dict(source_indices.most_common()),
        "adapter_counts": dict(adapters.most_common()),
        "source_names": dict(source_names.most_common()),
        "grouped_iocs": len(grouped),
        "warehouse_candidates": len(warehouse_items),
        "status_counts": dict(statuses.most_common()),
        "classification_modes": dict(modes.most_common()),
        "quarantined": quarantined,
        "warehouse_write": warehouse_result,
        "processed_state_write": state_result,
        "failed": failed,
        "errors": errors[:20],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Targeted backfill from readonly datalake sources.")
    parser.add_argument("--index-pattern", action="append", default=[], help="Source _index wildcard to include")
    parser.add_argument("--exclude-index-pattern", action="append", default=["cyberint_iocs-*"], help="Source _index wildcard to exclude")
    parser.add_argument("--limit", type=int, default=5000, help="Maximum raw datalake docs to read")
    parser.add_argument("--summary-file", help="Write JSON summary to this path")
    parser.add_argument("--force", action="store_true", help="Reprocess even when processed-state already exists")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()

    started_at = datetime.now(timezone.utc).isoformat()
    client = ElasticClient()
    client.create_processed_index()
    client.create_quarantine_index()

    raw_hits = search_target_hits(
        client,
        index_patterns=args.index_pattern,
        exclude_patterns=args.exclude_index_pattern,
        limit=args.limit,
    )
    normalized = normalize_hits(client, raw_hits)
    selected, skipped = filter_unprocessed(client, normalized, force=args.force)
    result = build_and_write(client, selected, write=args.write)

    summary = {
        "mode": "write" if args.write else "dry-run",
        "started_at": started_at,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "index_patterns": args.index_pattern,
        "exclude_index_patterns": args.exclude_index_pattern,
        "limit": args.limit,
        "force": args.force,
        "raw_hits": len(raw_hits),
        "normalized": len(normalized),
        "selected": len(selected),
        "skipped_existing_state": dict(skipped.most_common()),
        **result,
    }

    if args.summary_file:
        output = Path(args.summary_file)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, ensure_ascii=False, indent=2))

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if int(summary.get("failed", 0) or 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
