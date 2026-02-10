#!/usr/bin/env python3
"""
Import enriched threat intelligence data from enrich.json into Elasticsearch Data Lake
"""

import json
import os
from datetime import datetime
from pathlib import Path
import httpx

# Configuration
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
DATALAKE_INDEX = os.getenv("DATALAKE_INDEX", "cyber-logs-datalake")
DATALAKE_API_KEY = os.getenv("DATALAKE_API_KEY", "")

def _parse_bool(value: str, default: bool) -> bool:
    if value is None:
        return default
    v = value.strip().lower()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return default

# SSL verification: default true; set ELASTICSEARCH_VERIFY_SSL=false for self-signed endpoints.
VERIFY_SSL = _parse_bool(os.getenv("ELASTICSEARCH_VERIFY_SSL", "true"), default=True)

# Data lake directory: prefer env, otherwise use repo-local ./data_lake, fallback to /app/data_lake (container mount).
_repo_data_lake = (Path(__file__).resolve().parent / "data_lake")
DATA_LAKE_PATH = os.getenv("DATA_LAKE_DIR") or os.getenv("DATA_LAKE_PATH") or (str(_repo_data_lake) if _repo_data_lake.exists() else "/app/data_lake")

def index_document(doc, doc_id=None):
    """Index a single document"""
    headers = {"Content-Type": "application/json"}
    if DATALAKE_API_KEY:
        headers["Authorization"] = f"ApiKey {DATALAKE_API_KEY}"
    
    # Use the original _id if available
    if doc_id:
        url = f"{ES_URL}/{DATALAKE_INDEX}/_doc/{doc_id}"
    else:
        url = f"{ES_URL}/{DATALAKE_INDEX}/_doc"
    
    try:
        if doc_id:
            response = httpx.put(url, json=doc, headers=headers, timeout=30, verify=VERIFY_SSL)
        else:
            response = httpx.post(url, json=doc, headers=headers, timeout=30, verify=VERIFY_SSL)
        if response.status_code not in [200, 201]:
            print(f"Failed to index doc: {response.status_code} {response.text[:200]}")
            return False
        return True
    except Exception as e:
        print(f"Error indexing document: {e}")
        return False

def process_enrich_json(file_path):
    """Process the enrich.json file with Elasticsearch search results format"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract hits from Elasticsearch response
    if isinstance(data, dict) and 'hits' in data:
        hits = data['hits']['hits']
        print(f"Found {len(hits)} records in search results")
        
        success_count = 0
        failed_count = 0
        
        for hit in hits:
            source = hit.get('_source', {})
            original_id = hit.get('_id')
            
            # Extract IOC info from nested structure
            ioc_data = source.get('ioc', {})
            ioc_value = ioc_data.get('value', '')
            ioc_type = ioc_data.get('type', '')
            
            # Build flattened document
            doc = {
                'ioc_value': ioc_value,
                'ioc_type': ioc_type,
                'source_name': source.get('source_name', ''),
                'source_type': source.get('source_type', ''),
                'source_url': source.get('source_url', ''),
                'collect_time': source.get('collect_time', ''),
                'event_time': source.get('event_time', ''),
                'threat_type': source.get('threat_type', []),
                'severity': source.get('severity', ''),
                'confidence': source.get('confidence', 0),
                'description': source.get('description', ''),
                'reference': source.get('reference', ''),
                'tags': source.get('tags', []),
                'geo_info': source.get('geo_info', {}),
                'enrichment': source.get('enrichment', {}),
                'ai_processed': False,
                'created_at': datetime.utcnow().isoformat() + 'Z'
            }
            
            # Index with original ID to prevent duplicates
            if index_document(doc, original_id):
                success_count += 1
            else:
                failed_count += 1
        
        print(f"\nImport completed:")
        print(f"  Success: {success_count}")
        print(f"  Failed: {failed_count}")
        return success_count, failed_count
    else:
        print(f"Unexpected data format in {file_path}")
        return 0, 0

def main():
    """Main import function"""
    print(f"Starting import from {DATA_LAKE_PATH}")
    print(f"Elasticsearch URL: {ES_URL} (verify_ssl={VERIFY_SSL})")
    print(f"Target index: {DATALAKE_INDEX}")
    
    enrich_file = os.path.join(DATA_LAKE_PATH, "enrich.json")
    
    if os.path.exists(enrich_file):
        print(f"\nProcessing {enrich_file}")
        process_enrich_json(enrich_file)
    else:
        print(f"File not found: {enrich_file}")

if __name__ == "__main__":
    main()
