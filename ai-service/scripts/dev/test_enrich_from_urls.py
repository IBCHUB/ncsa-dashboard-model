#!/usr/bin/env python3
"""
Test Script: Enrich sparse IOCs by scraping reference URLs.

FOR TESTING ONLY — in production, description comes from the data lake.

This script:
1. Loads source-enrichment JSON from data_lake/
2. Identifies sparse records (no description, no enrichment, no threat_type)
3. Scrapes title + meta description from reference URLs
4. Injects scraped text as description
5. Runs full AI pipeline on a sample (before vs after comparison)
6. Reports the difference in classification quality

Usage:
    cd ai-service
    ./venv/bin/python scripts/dev/test_enrich_from_urls.py [--sample N] [--scrape]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = AI_SERVICE_ROOT.parent
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

CACHE_PATH = AI_SERVICE_ROOT / "data" / "url_scrape_cache.json"


# ---------------------------------------------------------------------------
# URL Scraping
# ---------------------------------------------------------------------------

def _scrape_url(url: str, timeout: int = 15) -> dict:
    """Scrape title + meta description from a URL. Returns dict, never mutates."""
    import urllib.request
    import urllib.error
    import ssl

    result = {"url": url, "title": "", "meta_description": "", "error": None}

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            html = resp.read().decode("utf-8", errors="replace")

        # Title
        title_m = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
        if title_m:
            result["title"] = re.sub(r"\s+", " ", title_m.group(1)).strip()

        # Meta description (name="description")
        meta_m = re.search(
            r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)',
            html, re.I,
        )
        if meta_m:
            result["meta_description"] = meta_m.group(1).strip()

        # Fallback: og:description
        if not result["meta_description"]:
            og_m = re.search(
                r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']*)',
                html, re.I,
            )
            if og_m:
                result["meta_description"] = og_m.group(1).strip()

        # Fallback: LD+JSON description
        if not result["meta_description"]:
            ld_m = re.search(
                r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
                html, re.S,
            )
            if ld_m:
                try:
                    ld = json.loads(ld_m.group(1))
                    if isinstance(ld, list):
                        ld = ld[0]
                    result["meta_description"] = str(ld.get("description", ""))[:500]
                except Exception:
                    pass

    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def scrape_urls(urls: list[str], cache_path: Path = CACHE_PATH) -> dict[str, dict]:
    """Scrape a list of URLs with caching. Returns {url: scrape_result}."""
    cache: dict = {}
    if cache_path.exists():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
            logger.info(f"Loaded {len(cache)} cached scrape results")
        except Exception:
            cache = {}

    to_scrape = [u for u in urls if u not in cache]
    logger.info(f"URLs: {len(urls)} total, {len(cache)} cached, {len(to_scrape)} to scrape")

    for i, url in enumerate(to_scrape):
        result = _scrape_url(url)
        cache[url] = result
        if result["error"]:
            logger.debug(f"  [{i+1}/{len(to_scrape)}] FAIL {url[:60]} — {result['error'][:60]}")
        else:
            logger.debug(f"  [{i+1}/{len(to_scrape)}] OK {url[:60]} — {result['title'][:50]}")

        # Rate limit
        time.sleep(0.5)

        # Save cache periodically
        if (i + 1) % 20 == 0:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")

    # Final save
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"Cache saved: {len(cache)} entries")

    return {url: cache[url] for url in urls if url in cache}


def build_description_from_scrape(scrape: dict) -> str:
    """Build a description string from scrape result. Pure function."""
    parts = []
    title = scrape.get("title", "").strip()
    meta = scrape.get("meta_description", "").strip()

    if title:
        parts.append(title)
    if meta and meta != title:
        parts.append(meta)

    return ". ".join(parts) if parts else ""


# ---------------------------------------------------------------------------
# Pipeline comparison
# ---------------------------------------------------------------------------

def run_pipeline_comparison(
    records: list[dict],
    scrape_results: dict[str, dict],
    sample_size: int = 30,
) -> dict:
    """Run pipeline on sparse records before/after injecting scraped descriptions."""
    from utils.pipeline_documents import build_enriched_ioc_document

    # Group records by IOC value (pipeline processes groups)
    by_ioc: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        ioc = r.get("ioc", {})
        key = f"{ioc.get('type', '?')}:{ioc.get('value', '?')}"
        by_ioc[key].append(r)

    # Filter to sparse IOCs only
    sparse_iocs = {}
    for key, docs in by_ioc.items():
        has_data = any(
            (isinstance(d.get("enrichment"), dict) and d["enrichment"])
            or d.get("description", "").strip()
            or (d.get("threat_type") and any(d.get("threat_type", [])))
            for d in docs
        )
        if not has_data:
            sparse_iocs[key] = docs

    logger.info(f"Sparse IOC groups: {len(sparse_iocs)}")

    # Sample
    import random
    random.seed(42)
    sample_keys = random.sample(list(sparse_iocs.keys()), min(sample_size, len(sparse_iocs)))

    results = []
    for key in sample_keys:
        docs = sparse_iocs[key]
        ioc_val = docs[0].get("ioc", {}).get("value", "?")
        ioc_type = docs[0].get("ioc", {}).get("type", "?")

        # --- BEFORE: run pipeline with original data ---
        from scripts.ops.import_to_datalake import normalize_ioc
        normalized_before = [normalize_ioc(d) for d in docs]
        try:
            result_before = build_enriched_ioc_document(normalized_before)
            doc_before = result_before["document"]
        except Exception as e:
            doc_before = {"error": str(e)}

        # --- AFTER: inject scraped description ---
        enriched_docs = []
        for d in docs:
            new_doc = {**d}  # shallow copy, don't mutate original
            ref = d.get("reference", "").strip()
            if ref in scrape_results:
                desc = build_description_from_scrape(scrape_results[ref])
                if desc:
                    new_doc = {**new_doc, "description": desc}
            enriched_docs.append(new_doc)

        normalized_after = [normalize_ioc(d) for d in enriched_docs]
        try:
            result_after = build_enriched_ioc_document(normalized_after)
            doc_after = result_after["document"]
        except Exception as e:
            doc_after = {"error": str(e)}

        results.append({
            "ioc_value": ioc_val,
            "ioc_type": ioc_type,
            "source": docs[0].get("source_name", "?"),
            "reference": docs[0].get("reference", "")[:80],
            "before": {
                "risk_score": doc_before.get("ai_risk_score", 0),
                "severity": doc_before.get("ai_severity", "?"),
                "threat_types": doc_before.get("ai_threat_types", []),
                "threat_actors": doc_before.get("ai_threat_actors", []),
                "mitre_techniques": doc_before.get("ai_mitre_techniques", []),
                "confidence": doc_before.get("ai_classification_confidence", 0),
                "validation": doc_before.get("validation_status", "?"),
            },
            "after": {
                "risk_score": doc_after.get("ai_risk_score", 0),
                "severity": doc_after.get("ai_severity", "?"),
                "threat_types": doc_after.get("ai_threat_types", []),
                "threat_actors": doc_after.get("ai_threat_actors", []),
                "mitre_techniques": doc_after.get("ai_mitre_techniques", []),
                "confidence": doc_after.get("ai_classification_confidence", 0),
                "validation": doc_after.get("validation_status", "?"),
            },
            "description_injected": build_description_from_scrape(
                scrape_results.get(docs[0].get("reference", ""), {})
            )[:150],
        })

    return {"sample_size": len(results), "comparisons": results}


def print_report(comparison: dict) -> None:
    """Print human-readable comparison report."""
    results = comparison["comparisons"]

    print("\n" + "=" * 80)
    print("PIPELINE COMPARISON: BEFORE vs AFTER URL ENRICHMENT")
    print("=" * 80)
    print(f"Sample size: {comparison['sample_size']}")
    print()

    # Aggregate stats
    score_improved = 0
    types_gained = 0
    actors_gained = 0
    mitre_gained = 0
    confidence_improved = 0

    for r in results:
        b, a = r["before"], r["after"]
        if a["risk_score"] > b["risk_score"]:
            score_improved += 1
        if len(a["threat_types"]) > len(b["threat_types"]):
            types_gained += 1
        if len(a["threat_actors"]) > len(b["threat_actors"]):
            actors_gained += 1
        if len(a["mitre_techniques"]) > len(b["mitre_techniques"]):
            mitre_gained += 1
        if a["confidence"] > b["confidence"]:
            confidence_improved += 1

    n = len(results)
    print("AGGREGATE IMPROVEMENTS:")
    print(f"  Risk score improved:     {score_improved}/{n} ({score_improved/n*100:.0f}%)")
    print(f"  Threat types gained:     {types_gained}/{n} ({types_gained/n*100:.0f}%)")
    print(f"  Threat actors gained:    {actors_gained}/{n} ({actors_gained/n*100:.0f}%)")
    print(f"  MITRE techniques gained: {mitre_gained}/{n} ({mitre_gained/n*100:.0f}%)")
    print(f"  Confidence improved:     {confidence_improved}/{n} ({confidence_improved/n*100:.0f}%)")
    print()

    # Detail table
    print(f"{'IOC':<30} {'Type':<6} {'Score':>5}{'->':>3}{'Score':>5} {'Severity':<8}{'->':>3}{'Severity':<8} {'Types':>5}{'->':>3}{'Types':>5}")
    print("-" * 100)
    for r in results:
        b, a = r["before"], r["after"]
        changed = "***" if a["risk_score"] != b["risk_score"] else "   "
        print(
            f"{r['ioc_value'][:30]:<30} {r['ioc_type']:<6} "
            f"{b['risk_score']:>5}{' ->':>3}{a['risk_score']:>5} "
            f"{b['severity']:<8}{' ->':>3}{a['severity']:<8} "
            f"{len(b['threat_types']):>5}{' ->':>3}{len(a['threat_types']):>5} {changed}"
        )

    # Show most improved
    print()
    print("TOP 5 MOST IMPROVED:")
    ranked = sorted(results, key=lambda r: r["after"]["risk_score"] - r["before"]["risk_score"], reverse=True)
    for r in ranked[:5]:
        b, a = r["before"], r["after"]
        delta = a["risk_score"] - b["risk_score"]
        if delta <= 0:
            continue
        print(f"\n  {r['ioc_value']} ({r['ioc_type']})")
        print(f"    Score: {b['risk_score']} -> {a['risk_score']} (+{delta})")
        print(f"    Severity: {b['severity']} -> {a['severity']}")
        print(f"    Types: {b['threat_types']} -> {a['threat_types']}")
        print(f"    Actors: {b['threat_actors']} -> {a['threat_actors']}")
        print(f"    Description: \"{r['description_injected']}\"")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Test IOC enrichment from reference URLs")
    parser.add_argument("--sample", type=int, default=30, help="Number of IOCs to compare")
    parser.add_argument("--scrape", action="store_true", help="Actually scrape URLs (vs cache only)")
    parser.add_argument("--data-file", default=str(REPO_ROOT / "data_lake" / "source-enrichment-23032026.json"))
    args = parser.parse_args()

    # Load data
    logger.info(f"Loading data from {args.data_file}")
    with open(args.data_file, encoding="utf-8") as f:
        data = json.load(f)
    records = [h.get("_source", h) for h in data["hits"]["hits"]]
    logger.info(f"Loaded {len(records)} records")

    # Collect reference URLs from sparse records
    sparse = [r for r in records if not (
        (isinstance(r.get("enrichment"), dict) and r["enrichment"])
        or r.get("description", "").strip()
        or (r.get("threat_type") and any(r.get("threat_type", [])))
    )]

    urls = list({
        r.get("reference", "").strip()
        for r in sparse
        if r.get("reference", "").strip().startswith("http")
    })
    logger.info(f"Sparse records: {len(sparse)}, unique URLs: {len(urls)}")

    # Scrape or use cache
    if args.scrape:
        scrape_results = scrape_urls(urls)
    elif CACHE_PATH.exists():
        cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        scrape_results = {u: cache[u] for u in urls if u in cache}
        logger.info(f"Using cached scrape results: {len(scrape_results)}/{len(urls)}")
    else:
        logger.info("No cache found. Run with --scrape to fetch URLs.")
        logger.info("Running without descriptions for baseline only...")
        scrape_results = {}

    # Run comparison
    comparison = run_pipeline_comparison(records, scrape_results, sample_size=args.sample)

    # Save results
    report_path = AI_SERVICE_ROOT / ".reports" / "url_enrichment_comparison.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(comparison, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info(f"Results saved to {report_path}")

    # Print report
    print_report(comparison)


if __name__ == "__main__":
    main()
