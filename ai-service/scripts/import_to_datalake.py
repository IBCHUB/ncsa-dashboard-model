#!/usr/bin/env python3
"""
Data Lake Import Script

Imports raw threat data from JSON files in data_lake/ directory
into Elasticsearch Data Lake index (tcti-datalake).

Usage:
    python scripts/import_to_datalake.py
    
Or with custom Elasticsearch URL:
    ELASTICSEARCH_URL=http://localhost:9200 python scripts/import_to_datalake.py
"""

import os
import sys
import json
import glob
import logging
import hashlib
from datetime import datetime
from urllib.parse import quote

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Configuration
DATA_LAKE_DIR = os.getenv("DATA_LAKE_DIR", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "..", "data_lake"
))
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")


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
    digest = hashlib.sha1(fingerprint.encode("utf-8")).hexdigest()[:24]
    return f"{ioc_type}:{ioc_value}:{digest}"


def parse_date(date_str: str) -> str:
    """Parse various date formats to ISO format."""
    if not date_str:
        return datetime.utcnow().isoformat() + "Z"
    
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


def normalize_ioc(raw_event: dict) -> dict:
    """Convert raw event to Data Lake document format."""
    ioc = raw_event.get("ioc", {})
    geo = raw_event.get("geo_info", {})
    
    return {
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
        "geo_country": geo.get("country", ""),
        "ai_processed": False
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


def import_to_elasticsearch(documents: list) -> dict:
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
            httpx.put(f"{ELASTICSEARCH_URL}/tcti-datalake", json=mapping, timeout=30)
        except:
            pass
        
        for doc in documents:
            try:
                ioc_id = build_datalake_doc_id(doc)
                doc["created_at"] = datetime.utcnow().isoformat() + "Z"
                
                resp = httpx.put(
                    f"{ELASTICSEARCH_URL}/tcti-datalake/_doc/{quote(ioc_id, safe='')}",
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
    client = ElasticClient(ELASTICSEARCH_URL)
    client.create_indexes()
    return client.bulk_index_datalake(documents)


def main():
    logger.info("=" * 60)
    logger.info("TCTI Data Lake Import Script")
    logger.info("=" * 60)
    logger.info(f"Data Lake Directory: {DATA_LAKE_DIR}")
    logger.info(f"Elasticsearch URL: {ELASTICSEARCH_URL}")
    logger.info("")
    
    # Check if data_lake directory exists
    if not os.path.exists(DATA_LAKE_DIR):
        logger.error(f"Data Lake directory not found: {DATA_LAKE_DIR}")
        sys.exit(1)
    
    # Load JSON files
    logger.info("Loading JSON files...")
    documents = load_json_files(DATA_LAKE_DIR)
    
    if not documents:
        logger.warning("No IOCs found in JSON files")
        sys.exit(0)
    
    logger.info(f"Total IOCs to import: {len(documents)}")
    logger.info("")
    
    # Import to Elasticsearch
    logger.info("Importing to Elasticsearch...")
    result = import_to_elasticsearch(documents)
    
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
    logger.info("     curl -X POST http://localhost:8000/pipeline/run -H 'X-API-Key: tcti-dev-key-2024'")
    logger.info("  2. Check pipeline status:")
    logger.info("     curl http://localhost:8000/pipeline/status -H 'X-API-Key: tcti-dev-key-2024'")


if __name__ == "__main__":
    main()
