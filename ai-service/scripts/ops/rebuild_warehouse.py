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
from models.validation import REJECTED, VALIDATED  # noqa: E402
from models.campaign_clusterer import cluster_iocs, build_cluster_summary  # noqa: E402
from models.relationship_graph import build_relationship_graph  # noqa: E402
from utils.pipeline_documents import build_enriched_ioc_document  # noqa: E402


REVIEW_METADATA_FIELDS = ("validation_status", "warehouse_eligible")


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
            VALIDATED: int(status_counts.get(VALIDATED, 0)),
            REJECTED: int(status_counts.get(REJECTED, 0)),
        },
        "reason_counts": dict(reason_counts.most_common()),
        "warehouse_eligible": eligible_count,
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
        "--skip-existing-check",
        action="store_true",
        help="Skip per-IOC warehouse lookup. Use for fast dry-run throughput/readiness audits only.",
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
            if not args.skip_existing_check:
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

        # --- Phase 2: HDBSCAN Clustering ---
        if written > 0:
            try:
                print(f"\n=== HDBSCAN Campaign Clustering ({written} documents) ===")
                written_docs = [item["document"] for item in built_documents]
                cluster_results = cluster_iocs(written_docs)
                clustered_count = sum(1 for r in cluster_results if r["cluster_label"] >= 0)
                noise_count = sum(1 for r in cluster_results if r["cluster_label"] < 0)
                print(f"  Clustered: {clustered_count}, Noise: {noise_count}")

                # Update warehouse documents with cluster labels (create new dicts, no mutation)
                cluster_updates = 0
                cluster_lookup = {r["ioc_value"]: r for r in cluster_results}
                for item in built_documents:
                    doc = item["document"]
                    cr = cluster_lookup.get(doc.get("ioc_value"))
                    if cr and cr["cluster_label"] >= 0:
                        item["document"] = {
                            **doc,
                            "cluster_label": cr["cluster_label"],
                            "cluster_probability": round(cr["cluster_probability"], 4),
                        }
                        update_body = {
                            "cluster_label": cr["cluster_label"],
                            "cluster_probability": round(cr["cluster_probability"], 4),
                        }
                        if client.update_warehouse_document(item["doc_id"], update_body):
                            cluster_updates += 1
                print(f"  Warehouse updated with cluster labels: {cluster_updates}")

                cluster_summary = build_cluster_summary(written_docs, cluster_results)
                summary["clustering"] = {
                    "clustered": clustered_count,
                    "noise": noise_count,
                    "clusters": len([c for c in cluster_summary.values() if isinstance(c, dict)]),
                    "updated": cluster_updates,
                }
            except Exception as exc:
                print(f"  [ERROR] Clustering phase failed: {exc}")
                summary["clustering"] = {"error": str(exc)}

            # --- Phase 3: Relationship Graph ---
            try:
                # Merge enrichment from datalake into docs for infrastructure links
                enrichment_by_ioc = defaultdict(dict)
                for ioc_docs in grouped.values():
                    for dl_doc in ioc_docs:
                        ioc_val = str(dl_doc.get("ioc_value", "")).strip().lower()
                        enrich = dl_doc.get("enrichment")
                        if isinstance(enrich, dict) and enrich and ioc_val:
                            existing = enrichment_by_ioc[ioc_val]
                            for k, v in enrich.items():
                                if k not in existing or not existing[k]:
                                    existing[k] = v

                graph_docs = []
                for item in built_documents:
                    doc = {**item["document"]}
                    ioc_val = str(doc.get("ioc_value", "")).strip().lower()
                    if ioc_val in enrichment_by_ioc:
                        doc["enrichment"] = enrichment_by_ioc[ioc_val]
                    graph_docs.append(doc)

                print(f"\n=== Relationship Graph ({len(graph_docs)} documents) ===")
                graph = build_relationship_graph(graph_docs)
                print(f"  Nodes: {graph['meta']['node_count']}, Links: {graph['meta']['link_count']}")

                # Save graph to file
                graph_path = AI_SERVICE_ROOT / ".reports" / "relationship_graph.json"
                graph_path.parent.mkdir(parents=True, exist_ok=True)
                graph_path.write_text(json.dumps(graph, ensure_ascii=False, indent=2))
                print(f"  Graph saved to: {graph_path}")

                summary["graph"] = graph["meta"]
            except Exception as exc:
                print(f"  [ERROR] Graph build phase failed: {exc}")
                summary["graph"] = {"error": str(exc)}

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
