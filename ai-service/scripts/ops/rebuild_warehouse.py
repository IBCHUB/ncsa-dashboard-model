"""
Backfill / rebuild Warehouse documents from Data Lake using the current
classifier + scorer logic.

Examples:
  python scripts/ops/rebuild_warehouse.py --limit 500
  python scripts/ops/rebuild_warehouse.py --date-from 2026-02-04T00:00:00+07:00 --date-to 2026-02-05T23:59:59+07:00
  python scripts/ops/rebuild_warehouse.py --write --date-from 2026-02-04T00:00:00+07:00 --date-to 2026-02-05T23:59:59+07:00
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import sys

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from elastic_client import ElasticClient  # noqa: E402
from models.validation import NEEDS_REVIEW, REJECTED, VALIDATED_AUTO  # noqa: E402
from utils.pipeline_documents import build_enriched_ioc_document  # noqa: E402


REVIEW_METADATA_FIELDS = ("validation_status", "review_state", "review_required", "warehouse_eligible")


def is_synthetic_document(document: Dict[str, Any]) -> bool:
    source_name = str(document.get("source_name", "")).strip().lower()
    ioc_value = str(document.get("ioc_value", "")).strip().lower()
    tags = [str(item).strip().lower() for item in document.get("tags", []) or []]
    if source_name == "syntheticdashboardtest":
        return True
    if "synthetic" in tags or "dashboard-fixture" in tags or "codex" in tags:
        return True
    if "review-fixture-" in ioc_value:
        return True
    return False


def has_review_metadata(document: Optional[Dict[str, Any]]) -> bool:
    if not document:
        return False
    return any(field in document for field in REVIEW_METADATA_FIELDS)


def build_summary(
    *,
    mode: str,
    date_from: Optional[str],
    date_to: Optional[str],
    limit: int,
    loaded_raw_documents: int,
    synthetic_skipped: int,
    aggregated_iocs: int,
    status_counts: Counter[str],
    reason_counts: Counter[str],
    eligible_count: int,
    review_required_count: int,
    skipped_existing_metadata: int,
    write_candidates: int,
    written: int,
    failed: int,
    samples: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    return {
        "mode": mode,
        "date_from": date_from,
        "date_to": date_to,
        "limit": limit,
        "loaded_raw_documents": loaded_raw_documents,
        "synthetic_skipped": synthetic_skipped,
        "filtered_raw_documents": max(loaded_raw_documents - synthetic_skipped, 0),
        "aggregated_iocs": aggregated_iocs,
        "status_counts": {
            VALIDATED_AUTO: int(status_counts.get(VALIDATED_AUTO, 0)),
            NEEDS_REVIEW: int(status_counts.get(NEEDS_REVIEW, 0)),
            REJECTED: int(status_counts.get(REJECTED, 0)),
        },
        "reason_counts": dict(reason_counts.most_common()),
        "warehouse_eligible": eligible_count,
        "review_required": review_required_count,
        "skipped_existing_review_metadata": skipped_existing_metadata,
        "write_candidates": write_candidates,
        "written": written,
        "failed": failed,
        "samples": samples,
    }


def write_summary(path: Optional[str], summary: Dict[str, Any]) -> None:
    if not path:
        return
    output_path = Path(path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2))


def group_iocs(documents: List[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for doc in documents:
        ioc_type = str(doc.get("ioc_type", "unknown")).strip().lower()
        ioc_value = str(doc.get("ioc_value", "")).strip()
        if not ioc_value:
            continue
        grouped[(ioc_type, ioc_value.lower())].append(doc)
    return grouped


def load_documents(client: ElasticClient, date_from: Optional[str], date_to: Optional[str], limit: int) -> List[Dict[str, Any]]:
    batch_size = min(limit, 500) if limit > 0 else 500
    offset = 0
    loaded: List[Dict[str, Any]] = []

    while True:
        remaining = limit - len(loaded)
        if limit > 0 and remaining <= 0:
            break

        page_size = batch_size if limit <= 0 else min(batch_size, remaining)
        page = client.search_datalake_documents(
            date_from=date_from,
            date_to=date_to,
            limit=page_size,
            offset=offset
        )
        if not page:
            break

        loaded.extend(page)
        offset += len(page)
        if len(page) < page_size:
            break

    return loaded


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild warehouse documents from the datalake.")
    parser.add_argument("--date-from", dest="date_from", help="Lower bound for event/collect time (ISO 8601)")
    parser.add_argument("--date-to", dest="date_to", help="Upper bound for event/collect time (ISO 8601)")
    parser.add_argument("--limit", type=int, default=500, help="Maximum number of raw datalake documents to read")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--dry-run", action="store_true", help="Compute documents without writing to warehouse")
    mode_group.add_argument("--write", action="store_true", help="Write rebuilt documents to warehouse")
    parser.add_argument("--summary-file", help="Optional path to write JSON summary output")
    parser.add_argument("--sample-size", type=int, default=5, help="Number of sample IOCs to retain per status")
    parser.add_argument(
        "--include-synthetic",
        action="store_true",
        help="Include synthetic dashboard fixture documents in the rebuild set",
    )
    parser.add_argument(
        "--overwrite-existing-review-metadata",
        action="store_true",
        help="Overwrite warehouse docs even if review metadata already exists",
    )
    parser.add_argument(
        "--allow-zero-eligible-write",
        action="store_true",
        help="Allow write mode even when dry-run finds zero warehouse-eligible documents",
    )
    args = parser.parse_args()

    if args.write and (not args.date_from or not args.date_to):
        parser.error("--write requires both --date-from and --date-to for safe scoped backfill")

    mode = "write" if args.write else "dry-run"

    client = ElasticClient()
    documents = load_documents(client, args.date_from, args.date_to, args.limit)
    synthetic_skipped = 0
    if not args.include_synthetic:
        filtered_documents: List[Dict[str, Any]] = []
        for document in documents:
            if is_synthetic_document(document):
                synthetic_skipped += 1
                continue
            filtered_documents.append(document)
        documents = filtered_documents
    grouped = group_iocs(documents)

    status_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    samples: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    eligible_count = 0
    review_required_count = 0
    skipped_existing_metadata = 0
    failed = 0
    built_documents: List[Dict[str, Any]] = []
    for ioc_docs in grouped.values():
        try:
            build_result = build_enriched_ioc_document(ioc_docs)
            pipeline_doc = build_result["document"]
            status = pipeline_doc["validation_status"]
            status_counts[status] += 1
            reason_counts.update(
                str(reason).strip()
                for reason in pipeline_doc.get("validation_reasons", []) or []
                if str(reason).strip()
            )
            if pipeline_doc["warehouse_eligible"]:
                eligible_count += 1
            if pipeline_doc["review_required"]:
                review_required_count += 1

            sample_bucket = samples[status]
            if len(sample_bucket) < max(args.sample_size, 0):
                sample_bucket.append(
                    {
                        "ioc_type": pipeline_doc["ioc_type"],
                        "ioc_value": pipeline_doc["ioc_value"],
                        "risk_score": pipeline_doc["ai_risk_score"],
                        "severity": pipeline_doc["ai_severity"],
                        "source_count": pipeline_doc["source_count"],
                        "validation_reasons": pipeline_doc.get("validation_reasons", []),
                    }
                )

            doc_id = ElasticClient._build_warehouse_doc_id(pipeline_doc)
            existing_document = client.get_warehouse_document(doc_id)
            if has_review_metadata(existing_document) and not args.overwrite_existing_review_metadata:
                skipped_existing_metadata += 1
                continue

            built_documents.append({"doc_id": doc_id, "document": dict(pipeline_doc)})
        except Exception as exc:
            failed += 1
            print(f"Failed rebuilding {ioc_docs[0].get('ioc_type')}:{ioc_docs[0].get('ioc_value')}: {exc}")

    write_candidates = len(built_documents)
    if args.write and eligible_count == 0 and not args.allow_zero_eligible_write:
        failed += 1
    summary = build_summary(
        mode=mode,
        date_from=args.date_from,
        date_to=args.date_to,
        limit=args.limit,
        loaded_raw_documents=len(documents) + synthetic_skipped,
        synthetic_skipped=synthetic_skipped,
        aggregated_iocs=len(grouped),
        status_counts=status_counts,
        reason_counts=reason_counts,
        eligible_count=eligible_count,
        review_required_count=review_required_count,
        skipped_existing_metadata=skipped_existing_metadata,
        write_candidates=write_candidates,
        written=0,
        failed=failed,
        samples={key: value for key, value in samples.items()},
    )

    if args.write and failed == 0:
        written = 0
        for item in built_documents:
            if client.save_to_warehouse(dict(item["document"])):
                written += 1
            else:
                failed += 1
        summary["written"] = written
        summary["failed"] = failed

    if args.write and eligible_count == 0 and not args.allow_zero_eligible_write:
        summary["guardrail"] = {
            "blocked": True,
            "reason": "zero warehouse-eligible documents detected; refusing to overwrite live warehouse without --allow-zero-eligible-write",
        }
    elif args.write:
        summary["guardrail"] = {"blocked": False}

    write_summary(args.summary_file, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
