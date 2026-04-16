#!/usr/bin/env python3
"""
Data Lake Import Script

Imports raw threat data from the repo `data_lake/` directory
into the configured Elasticsearch Data Lake index.

Usage:
    python scripts/ops/import_to_datalake.py
    
Or with custom Elasticsearch URL:
    ELASTICSEARCH_URL=http://localhost:9200 python scripts/ops/import_to_datalake.py
"""

import os
import sys
import json
import glob
import logging
import hashlib
import argparse
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

AI_SERVICE_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = AI_SERVICE_ROOT.parent
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration defaults
DEFAULT_DATA_LAKE_DIR = os.getenv("DATA_LAKE_DIR", str(REPO_ROOT / "data_lake"))
DEFAULT_ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
DEFAULT_DATALAKE_INDEX = os.getenv("DATALAKE_INDEX", "cyber-logs-datalake")


def build_datalake_doc_id(doc: dict) -> str:
    """
    Build unique doc id per IOC observation to preserve cross-source evidence.
    """
    ioc_type = str(doc.get("ioc_type", "unknown")).strip().lower()
    ioc_value = str(doc.get("ioc_value", "")).strip().lower()
    source = str(doc.get("source_name", "unknown")).strip().lower()
    source_type = str(doc.get("source_type", "unknown")).strip().lower()
    event_time = str(doc.get("event_time", "")).strip()
    collect_time = str(doc.get("collect_time", "")).strip()
    reference = str(doc.get("reference", "")).strip()
    desc = str(doc.get("description", ""))[:256]
    fingerprint = f"{source}|{source_type}|{event_time}|{collect_time}|{reference}|{desc}"
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:24]
    return f"{ioc_type}:{ioc_value}:{digest}"


def parse_date(date_str: str) -> str:
    """Parse various date formats to ISO format."""
    if not date_str:
        return datetime.now(timezone.utc).isoformat()
    
    # Try common formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y",
    ]
    
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.isoformat() + "Z"
        except (ValueError, TypeError):
            continue
    
    # Return as-is if parsing fails
    return date_str


def _compute_domain_age_days(enrichment: dict) -> int | None:
    """Compute domain age in days from WHOIS or enrichment events."""
    whois = enrichment.get("whois", {}) if isinstance(enrichment, dict) else {}
    events = enrichment.get("events", {}) if isinstance(enrichment, dict) else {}

    creation_str = (
        whois.get("creation_date")
        or events.get("registration")
    )
    if not creation_str:
        return None

    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            creation_dt = datetime.strptime(creation_str.strip(), fmt)
            return max(0, (datetime.now(tz=None) - creation_dt.replace(tzinfo=None)).days)
        except (ValueError, TypeError):
            continue
    return None


def _resolve_geo_country(geo: dict, enrichment: dict) -> str:
    """Extract country code with enrichment fallbacks."""
    country = geo.get("country", "") if isinstance(geo, dict) else ""
    if country:
        return country

    if not isinstance(enrichment, dict):
        return ""

    ip_info = enrichment.get("ip_info", {})
    if isinstance(ip_info, dict):
        asn_data = ip_info.get("asn_data", {})
        country = (
            ip_info.get("country", "")
            or ip_info.get("country_code", "")
            or (asn_data.get("country", "") if isinstance(asn_data, dict) else "")
        )
        if country:
            return country

    whois = enrichment.get("whois", {})
    if isinstance(whois, dict):
        country = whois.get("registrant_country", "")
        if country:
            return country

    return ""


def _parse_confidence(value) -> int:
    """Parse source confidence to int 0-100, treating missing/invalid as 0."""
    if value is None or str(value).strip() in ("", "null", "none"):
        return 0
    try:
        return min(max(int(float(str(value))), 0), 100)
    except (ValueError, TypeError):
        return 0


def normalize_ioc(raw_event: dict) -> dict:
    """Convert raw event to Data Lake document format.

    Preserves enrichment data, confidence, source traceability,
    and IOC relationships for downstream pipeline consumption.
    """
    ioc = raw_event.get("ioc", {})
    geo = raw_event.get("geo_info", {})
    enrichment = raw_event.get("enrichment", {}) if isinstance(raw_event.get("enrichment"), dict) else {}

    return {
        # Core IOC fields
        "ioc_value": ioc.get("value", ""),
        "ioc_type": ioc.get("type", "unknown"),
        "source_name": raw_event.get("source_name", "unknown"),
        "source_type": raw_event.get("source_type", "unknown"),
        "description": raw_event.get("description", ""),
        "threat_type": raw_event.get("threat_type", []),
        "severity": raw_event.get("severity", ""),
        "tags": raw_event.get("tags", []),
        "reference": raw_event.get("reference", ""),
        "collect_time": parse_date(raw_event.get("collect_time")),
        "event_time": parse_date(raw_event.get("event_time")),
        "geo_country": _resolve_geo_country(geo, enrichment),
        "ai_processed": False,
        # Source confidence & traceability
        "confidence": _parse_confidence(raw_event.get("confidence")),
        "source_url": raw_event.get("source_url", ""),
        "source_id": raw_event.get("source_id", ""),
        # IOC relationships
        "related_hash": ioc.get("related_hash", ""),
        "related_domain": ioc.get("related_domain", ""),
        # Enrichment blob (stored as opaque object in ES)
        "enrichment": enrichment,
        # Computed from enrichment
        "domain_age_days": _compute_domain_age_days(enrichment),
    }


def load_json_files(directory: str) -> list:
    """Load all JSON files from directory."""
    all_events = []
    
    json_files = glob.glob(os.path.join(directory, "*.json"))
    logger.info(f"Found {len(json_files)} JSON files in {directory}")
    
    for filepath in json_files:
        file_events = 0
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            events = []
            
            # Handle Elasticsearch nested format: {"hits": {"hits": [{"_source": {...}}]}}
            if isinstance(data, dict):
                if "hits" in data and isinstance(data["hits"], dict):
                    es_hits = data["hits"].get("hits", [])
                    for hit in es_hits:
                        source = hit.get("_source", {})
                        if source:
                            events.append(source)
                elif "hits" in data and isinstance(data["hits"], list):
                    for hit in data["hits"]:
                        source = hit.get("_source", hit)
                        if source:
                            events.append(source)
                elif "events" in data:
                    events = data["events"]
                elif "data" in data:
                    events = data["data"]
                elif "ioc" in data:
                    # Single event format
                    events = [data]
            elif isinstance(data, list):
                events = data
            
            for event in events:
                if isinstance(event, dict):
                    ioc = event.get("ioc", {})
                    if ioc.get("value"):
                        all_events.append(normalize_ioc(event))
                        file_events += 1
            
            logger.info(f"  Loaded {filepath}: {file_events} IOCs")
            
        except Exception as e:
            logger.error(f"  Error loading {filepath}: {e}")
    
    return all_events


def import_to_elasticsearch(
    documents: list,
    elasticsearch_url: str,
    datalake_index: str
) -> dict:
    """Import documents to Elasticsearch Data Lake index."""
    try:
        from elastic_client import ElasticClient
    except ImportError:
        # Fallback to httpx
        import httpx
        
        logger.info("Using httpx for Elasticsearch import")
        
        success = 0
        failed = 0
        
        # Create index if not exists
        mapping = {
            "mappings": {
                "properties": {
                    "ioc_value": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "source_name": {"type": "keyword"},
                    "description": {"type": "text"},
                    "ai_processed": {"type": "boolean"}
                }
            }
        }
        
        try:
            httpx.put(f"{elasticsearch_url}/{datalake_index}", json=mapping, timeout=30)
        except Exception as e:
            logger.warning(f"Index creation failed (may already exist): {e}")
        
        for doc in documents:
            try:
                ioc_id = build_datalake_doc_id(doc)
                doc["created_at"] = datetime.now(timezone.utc).isoformat()
                
                resp = httpx.put(
                    f"{elasticsearch_url}/{datalake_index}/_doc/{quote(ioc_id, safe='')}",
                    json=doc,
                    timeout=10
                )
                
                if resp.status_code in (200, 201):
                    success += 1
                else:
                    failed += 1
                    logger.debug(f"Failed to index {ioc_id}: {resp.text}")
            except Exception as e:
                failed += 1
                logger.debug(f"Error indexing document: {e}")
        
        return {"success": success, "failed": failed}
    
    # Use elastic_client
    client = ElasticClient(elasticsearch_url)
    client.create_indexes()
    return client.bulk_index_datalake(documents)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the import script."""
    parser = argparse.ArgumentParser(
        description="Import JSON IOC files into the datalake index."
    )
    parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_LAKE_DIR,
        help="Directory containing JSON files to import"
    )
    parser.add_argument(
        "--elasticsearch-url",
        default=DEFAULT_ELASTICSEARCH_URL,
        help="Elasticsearch base URL"
    )
    parser.add_argument(
        "--index",
        default=DEFAULT_DATALAKE_INDEX,
        help="Destination datalake index name"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load and normalize JSON files without writing to Elasticsearch"
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    args = parse_args(argv)

    logger.info("=" * 60)
    logger.info("TCTI Data Lake Import Script")
    logger.info("=" * 60)
    logger.info(f"Data Lake Directory: {args.data_dir}")
    logger.info(f"Elasticsearch URL: {args.elasticsearch_url}")
    logger.info(f"Data Lake Index: {args.index}")
    logger.info("")
    
    # Check if data_lake directory exists
    if not os.path.exists(args.data_dir):
        logger.error(f"Data Lake directory not found: {args.data_dir}")
        sys.exit(1)
    
    # Load JSON files
    logger.info("Loading JSON files...")
    documents = load_json_files(args.data_dir)
    
    if not documents:
        logger.warning("No IOCs found in JSON files")
        sys.exit(0)
    
    logger.info(f"Total IOCs to import: {len(documents)}")
    logger.info("")

    if args.dry_run:
        logger.info("Dry run enabled, skipping Elasticsearch import")
        return
    
    # Import to Elasticsearch
    logger.info("Importing to Elasticsearch...")
    result = import_to_elasticsearch(
        documents,
        elasticsearch_url=args.elasticsearch_url,
        datalake_index=args.index
    )
    
    logger.info("")
    logger.info("=" * 60)
    logger.info(f"Import completed!")
    logger.info(f"  Success: {result['success']}")
    logger.info(f"  Failed:  {result['failed']}")
    logger.info("=" * 60)
    
    # Show next steps
    logger.info("")
    logger.info("Next Steps:")
    logger.info("  1. Run AI Pipeline to process imported IOCs:")
    logger.info("     curl -X POST http://localhost:8000/pipeline/run -H 'X-API-Key: $AI_SERVICE_API_KEY'")
    logger.info("  2. Check pipeline status:")
    logger.info("     curl http://localhost:8000/pipeline/status -H 'X-API-Key: $AI_SERVICE_API_KEY'")


if __name__ == "__main__":
    main()
