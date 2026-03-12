#!/usr/bin/env python3
"""
URL Enrichment Script for Data Lake

This script fetches reference URLs from the data lake, extracts content,
classifies threats using AI, and stores results in a master file.

Features:
- Incremental mode: Only processes new URLs not in master file
- Rate limiting: Configurable delay between requests
- Error handling: Continues on failures, logs errors
- Caching: Stores results in url_classifications.json

Usage:
    python enrich_urls.py                    # Process new URLs only
    python enrich_urls.py --force            # Reprocess all URLs
    python enrich_urls.py --limit 10         # Process max 10 URLs
"""

import os
import sys
import json
import time
import asyncio
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import re

AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = AI_SERVICE_ROOT.parent
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

import httpx
from bs4 import BeautifulSoup

# Configuration
DATA_LAKE_DIR = REPO_ROOT / "data_lake"
OUTPUT_FILE = REPO_ROOT / "data_lake" / "url_classifications.json"
AI_SERVICE_URL = os.getenv("AI_SERVICE_URL", "http://localhost:8000")

# Rate limiting
REQUEST_DELAY_SECONDS = 2.0  # Delay between requests
REQUEST_TIMEOUT = 15  # Seconds

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def collect_urls_from_datalake() -> Dict[str, List[str]]:
    """Collect all unique reference URLs from data lake files."""
    url_to_iocs: Dict[str, List[str]] = {}
    
    for file_path in DATA_LAKE_DIR.glob("*.json"):
        if file_path.name == "url_classifications.json":
            continue
            
        try:
            with open(file_path) as fp:
                data = json.load(fp)
            
            # Handle both formats
            hits = data.get('hits', {})
            if isinstance(hits, dict):
                hits = hits.get('hits', [])
            
            for hit in hits:
                record = hit.get('_source', hit)
                ref_url = record.get('reference', '').strip()
                ioc_value = record.get('ioc', {}).get('value', '')
                source = record.get('source_name', '')
                
                if ref_url and ioc_value:
                    if ref_url not in url_to_iocs:
                        url_to_iocs[ref_url] = []
                    url_to_iocs[ref_url].append({
                        'ioc': ioc_value,
                        'source': source
                    })
                    
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            
    return url_to_iocs


def load_existing_classifications() -> Dict[str, dict]:
    """Load existing classifications from master file."""
    if OUTPUT_FILE.exists():
        try:
            with open(OUTPUT_FILE) as fp:
                return json.load(fp)
        except Exception as e:
            logger.warning(f"Error loading existing classifications: {e}")
    return {}


def save_classifications(classifications: Dict[str, dict]):
    """Save classifications to master file."""
    with open(OUTPUT_FILE, 'w') as fp:
        json.dump(classifications, fp, indent=2, ensure_ascii=False)
    logger.info(f"Saved {len(classifications)} classifications to {OUTPUT_FILE}")


async def fetch_url_content(client: httpx.AsyncClient, url: str) -> Optional[Dict]:
    """Fetch URL and extract title and content."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        response = await client.get(url, headers=headers, follow_redirects=True, timeout=REQUEST_TIMEOUT)
        
        if response.status_code != 200:
            return {'error': f"HTTP {response.status_code}"}
        
        content_type = response.headers.get('content-type', '')
        if 'html' not in content_type.lower():
            return {'error': f"Not HTML: {content_type}"}
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract title
        title = ""
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.get_text().strip()[:200]
        
        # Extract meta description
        meta_desc = ""
        meta_tag = soup.find('meta', attrs={'name': 'description'}) or \
                   soup.find('meta', attrs={'property': 'og:description'})
        if meta_tag:
            meta_desc = meta_tag.get('content', '')[:300]
        
        # Extract article content (first 1000 chars of main text)
        article_text = ""
        
        # Try common article containers
        for selector in ['article', '.article-body', '.post-content', 
                         '.entry-content', 'main', '.content']:
            container = soup.select_one(selector)
            if container:
                # Remove script/style
                for tag in container(['script', 'style', 'nav', 'footer', 'header']):
                    tag.decompose()
                article_text = container.get_text(' ', strip=True)[:1000]
                break
        
        # Fallback: get body text
        if not article_text:
            body = soup.find('body')
            if body:
                for tag in body(['script', 'style', 'nav', 'footer', 'header']):
                    tag.decompose()
                article_text = body.get_text(' ', strip=True)[:1000]
        
        return {
            'title': title,
            'meta_description': meta_desc,
            'content': article_text,
            'status': 'success'
        }
        
    except httpx.TimeoutException:
        return {'error': 'Timeout'}
    except Exception as e:
        return {'error': str(e)[:100]}


async def classify_content(client: httpx.AsyncClient, text: str) -> Optional[Dict]:
    """Classify content using AI service."""
    try:
        response = await client.post(
            f"{AI_SERVICE_URL}/classify",
            json={'text': text},
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            logger.warning(f"AI service returned {response.status_code}")
            return None
            
    except Exception as e:
        logger.warning(f"AI classification failed: {e}")
        return None


def extract_threat_actors_simple(text: str) -> List[str]:
    """Simple regex-based threat actor extraction."""
    known_actors = [
        'Lazarus', 'APT28', 'APT29', 'APT41', 'Fancy Bear', 'Cozy Bear',
        'Kimsuky', 'Mustang Panda', 'Turla', 'Sandworm', 'Winnti',
        'LockBit', 'BlackCat', 'ALPHV', 'REvil', 'Conti', 'Clop',
        'Qakbot', 'Emotet', 'TrickBot', 'IcedID', 'BazarLoader',
        'Cobalt Strike', 'Metasploit', 'Mimikatz',
    ]
    
    found = []
    text_lower = text.lower()
    for actor in known_actors:
        if actor.lower() in text_lower:
            found.append(actor)
    
    return list(set(found))


async def process_url(
    client: httpx.AsyncClient,
    url: str,
    iocs: List[dict]
) -> Dict:
    """Process a single URL: fetch, extract, classify."""
    result = {
        'url': url,
        'processed_at': datetime.now().isoformat(),
        'iocs': [i['ioc'] for i in iocs],
        'source': iocs[0]['source'] if iocs else 'unknown'
    }
    
    # Fetch content
    content_result = await fetch_url_content(client, url)
    
    if not content_result or 'error' in content_result:
        result['error'] = content_result.get('error', 'Unknown error') if content_result else 'Fetch failed'
        result['status'] = 'failed'
        return result
    
    result['title'] = content_result.get('title', '')
    result['meta_description'] = content_result.get('meta_description', '')[:200]
    
    # Combine text for classification
    full_text = f"{result['title']} {content_result.get('meta_description', '')} {content_result.get('content', '')}"
    
    # Classify using AI
    classification = await classify_content(client, full_text)
    
    if classification:
        result['threat_types'] = classification.get('threat_types', [])
        result['confidence'] = classification.get('confidence', 0)
    else:
        result['threat_types'] = []
        result['confidence'] = 0
    
    # Extract threat actors
    result['threat_actors'] = extract_threat_actors_simple(full_text)
    
    result['status'] = 'success'
    return result


async def main():
    parser = argparse.ArgumentParser(description='Enrich URLs from data lake')
    parser.add_argument('--force', action='store_true', help='Reprocess all URLs')
    parser.add_argument('--limit', type=int, default=0, help='Limit number of URLs to process')
    parser.add_argument('--delay', type=float, default=REQUEST_DELAY_SECONDS, help='Delay between requests')
    args = parser.parse_args()
    
    logger.info("🚀 Starting URL Enrichment Pipeline")
    
    # Collect URLs from data lake
    url_to_iocs = collect_urls_from_datalake()
    total_urls = len(url_to_iocs)
    logger.info(f"📂 Found {total_urls} unique URLs in data lake")
    
    # Load existing classifications
    classifications = {} if args.force else load_existing_classifications()
    existing_count = len(classifications)
    if existing_count > 0:
        logger.info(f"📋 Loaded {existing_count} existing classifications")
    
    # Find URLs to process
    urls_to_process = {
        url: iocs for url, iocs in url_to_iocs.items()
        if url not in classifications
    }
    
    # Skip private platforms that require auth
    skip_domains = ['cyberint.io', 'worldinfinity']
    urls_to_process = {
        url: iocs for url, iocs in urls_to_process.items()
        if not any(skip in url for skip in skip_domains)
    }
    
    if args.limit > 0:
        urls_to_process = dict(list(urls_to_process.items())[:args.limit])
    
    new_count = len(urls_to_process)
    
    if new_count == 0:
        logger.info("✅ No new URLs to process")
        return
    
    logger.info(f"🔄 Processing {new_count} new URLs (delay: {args.delay}s)")
    
    # Process URLs
    async with httpx.AsyncClient() as client:
        processed = 0
        success = 0
        failed = 0
        
        for url, iocs in urls_to_process.items():
            processed += 1
            domain = urlparse(url).netloc[:30]
            logger.info(f"[{processed}/{new_count}] Fetching: {domain}...")
            
            result = await process_url(client, url, iocs)
            classifications[url] = result
            
            if result.get('status') == 'success':
                success += 1
                actors = result.get('threat_actors', [])
                types = result.get('threat_types', [])
                logger.info(f"  ✅ Types: {types[:3]}, Actors: {actors}")
            else:
                failed += 1
                logger.warning(f"  ❌ {result.get('error', 'Unknown error')}")
            
            # Save periodically
            if processed % 10 == 0:
                save_classifications(classifications)
            
            # Rate limiting
            if processed < new_count:
                await asyncio.sleep(args.delay)
    
    # Final save
    save_classifications(classifications)
    
    logger.info(f"\n{'='*50}")
    logger.info(f"📊 Summary:")
    logger.info(f"   Total URLs: {total_urls}")
    logger.info(f"   Processed: {processed}")
    logger.info(f"   Success: {success}")
    logger.info(f"   Failed: {failed}")
    logger.info(f"   Saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
