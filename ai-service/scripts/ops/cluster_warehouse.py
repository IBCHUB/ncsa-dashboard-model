"""
Standalone post-ingest HDBSCAN clustering for the warehouse.

Runs N worker processes in parallel; each handles a disjoint ES slice via
PIT + slice + search_after. Per-batch HDBSCAN with a global label offset
keeps cluster_label unique across workers and batches.

Designed to be RESILIENT — built for the production environment where the
warehouse contains tens of millions of docs and ES occasionally throttles:

    * Each worker is independent. One worker's failure (timeout, OOM, etc.)
      does NOT kill the other workers. Without this, multiprocessing.Pool
      would propagate the exception and collapse the entire job.
    * Skips docs already clustered (must_not exists cluster_label) so the
      job can be killed and resumed without redoing finished work.
    * Long ES request timeout (180s) — single-node ES under heavy ingest +
      query load takes >10s for some bulk writes.
    * Bulk-update has retry_on_conflict so concurrent writes don't blow up.

Usage (run inside the ai-service container):

    cd /app && CLUSTER_WORKERS=8 python scripts/ops/cluster_warehouse.py

Env knobs:
    CLUSTER_WORKERS         number of parallel worker processes (default 8)
    CLUSTER_BATCH_SIZE      docs per HDBSCAN batch (default 10000)
    CLUSTER_ES_TIMEOUT_S    per-request ES timeout in seconds (default 180)
"""
from __future__ import annotations

import logging
import multiprocessing as mp
import os
import sys
import time
import traceback
from typing import Any, Dict, List

sys.path.insert(0, "/app")

BATCH_SIZE = int(os.getenv("CLUSTER_BATCH_SIZE", "10000"))
ES_TIMEOUT_S = int(os.getenv("CLUSTER_ES_TIMEOUT_S", "180"))
N_WORKERS = int(os.getenv("CLUSTER_WORKERS", "8"))

# Global label numbering: worker_id * WORKER_STRIDE + batch_id * BATCH_STRIDE
# + local_label. Stride values are loose to keep IDs unique across all
# reasonable workloads (max possible IDs ≈ N_WORKERS × 10M).
WORKER_STRIDE = 100_000_000
BATCH_STRIDE = 100_000

# Source fields needed by campaign_clusterer.extract_features. Pulling
# only these keeps the scroll payload small.
SOURCE_FIELDS = [
    "ioc_value", "ioc_type", "ai_threat_types", "asn_data",
    "enrichment.ip_info.asn", "geo_country", "domain_age_days",
    "ai_risk_score", "source_count",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(processName)s %(levelname)s %(message)s",
)


def worker_main(worker_id: int, worker_total: int) -> Dict[str, int]:
    """Cluster one slice. Wraps the inner loop in try/except so an ES
    timeout or any other error inside this process never propagates up
    and kills the multiprocessing pool — other workers keep running."""
    log = logging.getLogger(f"w{worker_id}")
    try:
        return _worker_impl(worker_id, worker_total, log)
    except Exception as exc:  # noqa: BLE001 - intentional broad catch
        log.error(
            "worker %s/%s aborted: %s\n%s",
            worker_id, worker_total, exc, traceback.format_exc(),
        )
        return {
            "processed": 0, "updated": 0, "noise": 0,
            "error": str(exc), "worker_id": worker_id,
        }


def _worker_impl(worker_id: int, worker_total: int, log: logging.Logger) -> Dict[str, int]:
    from elastic_client import get_elastic_client
    from models.campaign_clusterer import cluster_iocs

    es = get_elastic_client()
    client = es._get_client(es.warehouse_index)
    if client is None:
        log.error("No ES client")
        return {"processed": 0, "updated": 0, "noise": 0}

    # Use a long PIT keepalive — clustering scrolls take hours on large
    # warehouses and ES will close stale PITs aggressively otherwise.
    pit = client.options(request_timeout=ES_TIMEOUT_S).open_point_in_time(
        index=es.warehouse_index, keep_alive="2h",
    )
    pit_id = pit["id"]
    log.info("worker %s/%s PIT opened", worker_id, worker_total)

    search_after = None
    batch_idx = 0
    processed = 0
    updated = 0
    noise = 0
    start = time.time()
    try:
        while True:
            # Skip docs that already have cluster_label so this script can
            # be killed and resumed without redoing finished work.
            query: Dict[str, Any] = {
                "size": BATCH_SIZE,
                "_source": SOURCE_FIELDS,
                "pit": {"id": pit_id, "keep_alive": "2h"},
                "sort": [{"_shard_doc": "asc"}],
                "slice": {"id": worker_id, "max": worker_total},
                "query": {
                    "bool": {
                        "must_not": [{"exists": {"field": "cluster_label"}}],
                    }
                },
            }
            if search_after:
                query["search_after"] = search_after

            try:
                result = client.options(request_timeout=ES_TIMEOUT_S).search(body=query)
            except Exception as search_exc:  # ES timeout, etc. — retry once
                log.warning("search failed, retrying once: %s", search_exc)
                time.sleep(5)
                result = client.options(request_timeout=ES_TIMEOUT_S).search(body=query)

            hits = result["hits"]["hits"]
            if not hits:
                break

            docs = [h["_source"] for h in hits]
            doc_ids = [h["_id"] for h in hits]
            cluster_results = cluster_iocs(docs)

            worker_offset = worker_id * WORKER_STRIDE
            batch_offset = batch_idx * BATCH_STRIDE

            updates: List = []
            for hit_id, cr in zip(doc_ids, cluster_results):
                local_label = cr["cluster_label"]
                if local_label < 0:
                    noise += 1
                    global_label = -1
                else:
                    global_label = worker_offset + batch_offset + local_label
                updates.append((hit_id, {
                    "cluster_label": global_label,
                    "cluster_probability": round(cr["cluster_probability"], 4),
                }))

            if updates:
                try:
                    upd = es.bulk_update_warehouse_documents(updates)
                    updated += int(upd.get("success", 0) or 0)
                except Exception as upd_exc:
                    log.warning(
                        "bulk update failed (batch %s): %s — skipping batch, continuing",
                        batch_idx, upd_exc,
                    )

            processed += len(hits)
            batch_idx += 1
            search_after = hits[-1]["sort"]

            if batch_idx % 5 == 0 or batch_idx == 1:
                elapsed = int(time.time() - start)
                rate = int(processed / elapsed) if elapsed > 0 else 0
                log.info(
                    "w%s batch=%s processed=%s updated=%s noise=%s rate=%s/s",
                    worker_id, batch_idx, f"{processed:,}",
                    f"{updated:,}", f"{noise:,}", rate,
                )
    finally:
        try:
            client.close_point_in_time(body={"id": pit_id})
        except Exception:
            pass

    elapsed = int(time.time() - start)
    log.info(
        "w%s DONE batches=%s processed=%s updated=%s noise=%s elapsed=%ss",
        worker_id, batch_idx, f"{processed:,}", f"{updated:,}",
        f"{noise:,}", elapsed,
    )
    return {"processed": processed, "updated": updated, "noise": noise}


def main() -> int:
    log = logging.getLogger("main")
    log.info(
        "Starting %s clustering workers (batch=%s, es_timeout=%ss)",
        N_WORKERS, BATCH_SIZE, ES_TIMEOUT_S,
    )
    start = time.time()
    # spawn pool so each subprocess is fully independent (fork can hit GIL
    # or shared-fd surprises with sklearn+httpx); workers don't share state
    # across the boundary anyway so the spawn overhead is acceptable once.
    with mp.get_context("spawn").Pool(processes=N_WORKERS) as pool:
        results = pool.starmap(
            worker_main,
            [(i, N_WORKERS) for i in range(N_WORKERS)],
        )
    elapsed = int(time.time() - start)
    total_p = sum(r.get("processed", 0) for r in results)
    total_u = sum(r.get("updated", 0) for r in results)
    total_n = sum(r.get("noise", 0) for r in results)
    errored = [r for r in results if r.get("error")]
    log.info(
        "ALL DONE processed=%s updated=%s noise=%s elapsed=%ss errored_workers=%s",
        f"{total_p:,}", f"{total_u:,}", f"{total_n:,}", elapsed, len(errored),
    )
    for r in errored:
        log.warning("worker %s errored: %s", r.get("worker_id"), r.get("error"))
    return 0 if not errored else 2


if __name__ == "__main__":
    sys.exit(main())
