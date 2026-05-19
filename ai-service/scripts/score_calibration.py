#!/usr/bin/env python3
"""
Score Calibration Harness

Pull a sample of IOCs from the datalake, run them through the adapter →
build_enriched_ioc_document → AI scorer pipeline, and print the resulting
ai_severity distribution.

Usage:
    python scripts/score_calibration.py --sample 5000
    python scripts/score_calibration.py --sample 10000 --index "cyberint_iocs-2025.09.01"
    python scripts/score_calibration.py --sample 5000 --weights '{"cross_source":0.15,"threat_type_severity":0.25}'
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from collections import Counter
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elastic_client import (
    DATALAKE_ELASTICSEARCH_URL,
    DATALAKE_USERNAME,
    DATALAKE_PASSWORD,
    ElasticClient,
)
from datalake_adapters import normalize_datalake_hit
from models.scorer import calculate_risk_score

logger = logging.getLogger(__name__)

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore


def fetch_sample(
    url: str,
    index: str,
    size: int,
    username: str = "",
    password: str = "",
) -> List[Dict[str, Any]]:
    if httpx is None:
        raise RuntimeError("httpx is required: pip install httpx")

    auth = (username, password) if username else None
    query = {
        "size": min(size, 10000),
        "query": {"function_score": {"query": {"match_all": {}}, "random_score": {}}},
    }
    resp = httpx.post(
        f"{url}/{index}/_search",
        json=query,
        auth=auth,
        timeout=60.0,
    )
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    return hits


def run_calibration(
    hits: List[Dict[str, Any]],
    weight_overrides: Dict[str, float] | None = None,
) -> Dict[str, Any]:
    if weight_overrides:
        import config
        for k, v in weight_overrides.items():
            if k in config.SCORING_WEIGHTS:
                config.SCORING_WEIGHTS[k] = v

    normalize_type = ElasticClient.normalize_ioc_type
    normalize_value = ElasticClient.normalize_ioc_value

    adapted = []
    adapter_failures = 0
    for hit in hits:
        doc = normalize_datalake_hit(hit, normalize_type, normalize_value)
        if doc is None:
            adapter_failures += 1
            continue
        if doc.get("adapter_status") == "quarantined":
            continue
        adapted.append(doc)

    grouped: Dict[tuple, List[Dict[str, Any]]] = {}
    for doc in adapted:
        ioc_type = ElasticClient.normalize_ioc_type(doc.get("ioc_type"))
        ioc_value = ElasticClient.normalize_ioc_value(doc.get("ioc_value"))
        if not ioc_value:
            continue
        key = (ioc_type, ioc_value.lower())
        grouped.setdefault(key, []).append(doc)

    severity_counts: Counter = Counter()
    score_values: List[int] = []
    source_count_values: List[int] = []
    activity_severity: Dict[str, Counter] = {}
    errors = 0

    for (_, _), ioc_docs in grouped.items():
        try:
            source_names = []
            source_objects = []
            descriptions = []
            threat_types_raw: List[str] = []
            for doc in ioc_docs:
                sn = str(doc.get("source_name", "")).strip()
                if sn:
                    matched = next((o for o in source_objects if o["name"] == sn), None)
                    conf = float(doc.get("confidence", 0) or 0)
                    if matched:
                        matched["confidence"] = max(matched["confidence"], conf)
                    else:
                        source_objects.append({"name": sn, "confidence": conf, "type": doc.get("source_type", "unknown")})
                    if sn not in source_names:
                        source_names.append(sn)
                desc = str(doc.get("description", "")).strip()
                if desc:
                    descriptions.append(desc)
                for t in (doc.get("threat_type") or []):
                    if t and str(t) not in threat_types_raw:
                        threat_types_raw.append(str(t))

            primary = ioc_docs[0]
            ioc_value = primary.get("ioc_value", "")
            ioc_type = primary.get("ioc_type", "")
            merged_desc = "\n".join(descriptions[:5])

            score_result = calculate_risk_score(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                description=merged_desc,
                sources=source_objects or source_names,
                threat_classification={
                    "threat_types": threat_types_raw,
                    "threat_actors": [],
                    "mitre_techniques": [],
                    "confidence": 1.0,
                },
            )

            sev = score_result.get("severity", "unknown")
            score = score_result.get("risk_score", 0)
            src_count = len(source_names)
            severity_counts[sev] += 1
            score_values.append(score)
            source_count_values.append(src_count)

            activity = threat_types_raw[0] if threat_types_raw else ""
            if activity:
                activity_severity.setdefault(activity, Counter())[sev] += 1
        except Exception as e:
            errors += 1
            if errors <= 5:
                logger.warning("Error processing IOC group: %s", e)

    total = sum(severity_counts.values())
    percentiles = {}
    if score_values:
        sorted_scores = sorted(score_values)
        n = len(sorted_scores)
        for p in [10, 25, 50, 75, 90, 95, 99]:
            idx = min(int(n * p / 100), n - 1)
            percentiles[f"p{p}"] = sorted_scores[idx]

    return {
        "total_hits": len(hits),
        "adapter_failures": adapter_failures,
        "unique_iocs": len(grouped),
        "scoring_errors": errors,
        "severity_distribution": {
            k: {"count": v, "pct": round(v / total * 100, 1) if total else 0}
            for k, v in severity_counts.most_common()
        },
        "score_percentiles": percentiles,
        "source_count_distribution": dict(Counter(source_count_values).most_common(10)),
        "activity_severity_breakdown": {
            activity: dict(counts.most_common())
            for activity, counts in sorted(activity_severity.items(), key=lambda x: -sum(x[1].values()))[:10]
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Score calibration harness")
    parser.add_argument("--sample", type=int, default=5000, help="Number of docs to sample")
    parser.add_argument("--index", default="tcti-feeds", help="Datalake index to sample from")
    parser.add_argument("--url", default=DATALAKE_ELASTICSEARCH_URL, help="Datalake ES URL")
    parser.add_argument("--username", default=DATALAKE_USERNAME)
    parser.add_argument("--password", default=DATALAKE_PASSWORD)
    parser.add_argument("--weights", default="", help='JSON weight overrides, e.g. \'{"cross_source":0.15}\'')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    weight_overrides = json.loads(args.weights) if args.weights else None

    print(f"Fetching {args.sample} random docs from {args.url}/{args.index} ...")
    t0 = time.time()
    hits = fetch_sample(args.url, args.index, args.sample, args.username, args.password)
    print(f"Fetched {len(hits)} docs in {time.time() - t0:.1f}s")

    print("Running adapter → pipeline → scorer ...")
    t1 = time.time()
    result = run_calibration(hits, weight_overrides)
    elapsed = time.time() - t1
    print(f"Scored {result['unique_iocs']} unique IOCs in {elapsed:.1f}s\n")

    print("=" * 60)
    print("SEVERITY DISTRIBUTION")
    print("=" * 60)
    for sev, info in result["severity_distribution"].items():
        bar = "#" * int(info["pct"] / 2)
        print(f"  {sev:10s}  {info['count']:>6,}  ({info['pct']:5.1f}%)  {bar}")

    print(f"\n{'SCORE PERCENTILES':=<60}")
    for k, v in result["score_percentiles"].items():
        print(f"  {k:>5s}: {v}")

    print(f"\n{'SOURCE COUNT DISTRIBUTION':=<60}")
    for count, num in sorted(result["source_count_distribution"].items()):
        print(f"  source_count={count}: {num:,} IOCs")

    print(f"\n{'ACTIVITY → SEVERITY BREAKDOWN':=<60}")
    for activity, counts in result["activity_severity_breakdown"].items():
        parts = [f"{sev}={n}" for sev, n in counts.items()]
        print(f"  {activity:30s}  {', '.join(parts)}")

    print(f"\n  Adapter failures: {result['adapter_failures']}")
    print(f"  Scoring errors:   {result['scoring_errors']}")


if __name__ == "__main__":
    main()
