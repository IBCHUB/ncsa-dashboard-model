#!/usr/bin/env python3
"""
TCTI Ingestion Pipeline Script
Reads raw JSON files from data_lake, processes them through AI classifier and scorer,
and outputs normalized IOCs to legacy/dashboard-poc/public/data/normalized_iocs.json

Usage:
    python ingest.py [--data-dir PATH] [--output PATH]
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

AI_SERVICE_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = AI_SERVICE_ROOT.parent
if str(AI_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_SERVICE_ROOT))

from models.classifier import classify_threat, extract_threat_actors, extract_mitre_techniques
from models.scorer import calculate_risk_score
from scraper import enrich_description


def load_raw_json(file_path: Path) -> list[dict]:
    """Load and extract IOC records from a raw JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle Elasticsearch export format
        if 'hits' in data and 'hits' in data['hits']:
            return [hit.get('_source', {}) for hit in data['hits']['hits']]
        
        # Handle array format
        if isinstance(data, list):
            return data
        
        # Handle single object
        if isinstance(data, dict) and 'ioc' in data:
            return [data]
        
        print(f"  Warning: Unrecognized format in {file_path.name}")
        return []
    
    except Exception as e:
        print(f"  Error loading {file_path.name}: {e}")
        return []


def extract_country_from_enrichment(record: dict) -> str | None:
    """Extract country code from enrichment data."""
    enrichment = record.get('enrichment', {})
    
    # From IP info
    if 'ip_info' in enrichment and 'asn_data' in enrichment['ip_info']:
        country = enrichment['ip_info']['asn_data'].get('country')
        if country:
            return country
    
    # From geo
    if 'geo' in enrichment:
        country = enrichment['geo'].get('country')
        if country:
            return country
    
    # From whois
    if 'whois' in enrichment:
        return enrichment['whois'].get('registrant_country') or enrichment['whois'].get('country')
    
    return None


def calculate_domain_age(record: dict) -> int | None:
    """Calculate domain age in days from enrichment data."""
    enrichment = record.get('enrichment', {})
    
    # From whois creation_date
    if 'whois' in enrichment:
        creation_date = enrichment['whois'].get('creation_date')
        if creation_date:
            try:
                # Handle various date formats
                for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S']:
                    try:
                        created = datetime.strptime(creation_date[:19], fmt[:len(creation_date[:19])])
                        return (datetime.now() - created).days
                    except ValueError:
                        continue
            except:
                pass
    
    # From events.registration
    if 'events' in enrichment:
        registration = enrichment['events'].get('registration')
        if registration:
            try:
                created = datetime.fromisoformat(registration.replace('Z', '+00:00'))
                return (datetime.now(created.tzinfo) - created).days
            except:
                pass
    
    return None


def calculate_ioc_age(record: dict) -> int | None:
    """Calculate IOC age in days from event_time or collect_time."""
    # Try event_time first (when the threat was observed)
    event_time = record.get('event_time', '')
    if event_time:
        try:
            for fmt in ['%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d']:
                try:
                    event_dt = datetime.strptime(event_time[:len(fmt)-2], fmt[:len(event_time)])
                    return (datetime.now() - event_dt).days
                except ValueError:
                    continue
            # Try ISO format
            event_dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            return (datetime.now(event_dt.tzinfo) - event_dt).days
        except:
            pass
    
    # Fall back to collect_time
    collect_time = record.get('collect_time', '')
    if collect_time:
        try:
            collect_dt = datetime.fromisoformat(collect_time.replace('Z', '+00:00'))
            return (datetime.now(collect_dt.tzinfo) - collect_dt).days
        except:
            pass
    
    return None


def process_record(record: dict, source_counts: dict[str, int]) -> dict | None:
    """Process a single IOC record through classifier and scorer."""
    ioc = record.get('ioc', {})
    ioc_value = ioc.get('value', '')
    ioc_type = ioc.get('type', '')
    
    if not ioc_value or not ioc_type:
        return None
    
    # Build description from available fields
    description = record.get('description', '')
    reference = record.get('reference', '')
    source_url = record.get('source_url', '')
    source_name = record.get('source_name', '')
    
    # Only scrape from news sources (not feeds/logs)
    SCRAPABLE_SOURCES = [
        'BleepingComputer',
        'TheHackerNews', 
        'DarkReading',
        'The Hacker News'
    ]
    
    # Enrich empty descriptions by scraping URL content (smart filtering)
    scraped = False
    scrape_error = None
    should_scrape = any(src.lower() in source_name.lower() for src in SCRAPABLE_SOURCES)
    
    if should_scrape and (not description or len(description.strip()) < 20):
        enrichment = enrich_description(description, source_url)
        if enrichment['scraped']:
            description = enrichment['description']
            scraped = True
        if enrichment.get('scrape_error'):
            scrape_error = enrichment['scrape_error']
    
    full_text = f"{description} {reference} {source_url}"
    
    # Get source information
    source_name = record.get('source_name', 'Unknown')
    sources = [source_name]
    
    # Track cross-source validation
    ioc_key = f"{ioc_type}:{ioc_value.lower()}"
    source_counts[ioc_key] = source_counts.get(ioc_key, 0) + 1
    
    # Classify threat using NLP
    classification = classify_threat(full_text)
    
    # Extract additional intelligence
    threat_actors = extract_threat_actors(full_text)
    mitre_techniques = extract_mitre_techniques(full_text)
    
    # Get enrichment data
    country_code = extract_country_from_enrichment(record)
    domain_age = calculate_domain_age(record)
    ioc_age = calculate_ioc_age(record)  # For decay factor
    
    # Calculate risk score
    score_result = calculate_risk_score(
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        description=full_text,
        sources=sources,
        country_code=country_code,
        domain_age_days=domain_age,
        threat_classification=classification,
        ioc_age_days=ioc_age  # Apply decay factor
    )
    
    # Build normalized output
    normalized = {
        # Original fields
        'source_type': record.get('source_type', ''),
        'source_name': source_name,
        'source_url': source_url,
        'collect_time': record.get('collect_time', ''),
        'event_time': record.get('event_time', ''),
        'threat_type': record.get('threat_type', []),
        'severity': record.get('severity', ''),
        'confidence': record.get('confidence', 0),
        'ioc': ioc,
        'geo_info': record.get('geo_info', {}),
        'description': description,
        'reference': reference,
        'tags': record.get('tags', []),
        'status': record.get('status', 'new'),
        'enrichment': record.get('enrichment'),
        
        # AI-enriched fields
        'aiRiskScore': score_result['risk_score'],
        'aiSeverity': score_result['severity'],
        'aiScoreBreakdown': score_result['breakdown'],
        'aiThreatTypes': classification.get('threat_types', []),
        'aiThreatActors': threat_actors,
        'aiMitreTechniques': mitre_techniques,
        'aiClassificationConfidence': classification.get('confidence', 0),
        
        # Scraping metadata
        'scraped': scraped,
        'scrape_error': scrape_error,
        
        # Metadata
        'processed_time': datetime.utcnow().isoformat() + 'Z'
    }
    
    return normalized


def update_cross_source_scores(normalized_iocs: list[dict], source_counts: dict[str, int]):
    """Update scores for IOCs that appear in multiple sources."""
    for ioc in normalized_iocs:
        ioc_key = f"{ioc['ioc']['type']}:{ioc['ioc']['value'].lower()}"
        count = source_counts.get(ioc_key, 1)
        
        if count > 1:
            # Boost score for cross-source validation
            boost = min(count * 10, 40)  # Max 40 points from cross-source
            ioc['aiRiskScore'] = min(ioc['aiRiskScore'] + boost, 100)
            ioc['aiScoreBreakdown']['cross_source'] = {
                'score': boost,
                'source_count': count,
                'description': f'Found in {count} different sources'
            }


def main():
    parser = argparse.ArgumentParser(description='TCTI Ingestion Pipeline')
    parser.add_argument('--data-dir', type=str, default='data_lake',
                        help='Path to data_lake directory')
    parser.add_argument('--output', type=str, default='legacy/dashboard-poc/public/data/normalized_iocs.json',
                        help='Output path for normalized IOCs')
    parser.add_argument('--limit', type=int, default=None,
                        help='Limit number of IOCs to process (for testing)')
    args = parser.parse_args()
    
    # Resolve paths relative to repo root.
    script_dir = REPO_ROOT
    data_dir = Path(args.data_dir)
    if not data_dir.is_absolute():
        data_dir = script_dir / data_dir
    
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = script_dir / args.output
    
    print(f"🚀 TCTI Ingestion Pipeline")
    print(f"   Data Directory: {data_dir}")
    print(f"   Output Path: {output_path}")
    print()
    
    if not data_dir.exists():
        print(f"❌ Error: Data directory not found: {data_dir}")
        sys.exit(1)
    
    # Find all JSON files
    json_files = sorted(list(data_dir.glob('*.json')))
    print(f"📂 Found {len(json_files)} JSON files")
    
    # Process all files
    all_records = []
    source_counts: dict[str, int] = {}
    
    for json_file in json_files:
        print(f"  📄 Loading {json_file.name}...")
        records = load_raw_json(json_file)
        print(f"     → {len(records)} records")
        all_records.extend(records)
    
    print(f"\n📊 Total raw records: {len(all_records)}")
    
    # Load existing records to skip duplicates/already processed
    existing_iocs = {}
    if output_path.exists():
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Handle various formats: normalized_iocs, events, or direct list
                items = []
                if isinstance(data, list):
                    items = data
                else:
                    items = data.get('normalized_iocs') or data.get('events') or []
                
                for item in items:
                    ioc = item.get('ioc', {})
                    key = f"{ioc.get('type')}:{ioc.get('value')}"
                    existing_iocs[key] = item
            print(f"📖 Loaded {len(existing_iocs)} existing records from cache")
        except Exception as e:
            print(f"⚠️ Error loading existing cache: {e}")
            
    # Apply limit if specified
    if args.limit:
        all_records = all_records[:args.limit]
        print(f"   (Limited to {args.limit} for testing)")
    
    # Process records
    print(f"\n🔬 Processing through AI classifier and scorer...")
    normalized_iocs = []
    processed = 0
    scraped_count = 0
    errors = 0
    
    try:
        from tqdm import tqdm
        use_tqdm = True
    except ImportError:
        use_tqdm = False
        print("   (Install tqdm for progress bar: pip install tqdm)")
    
    iterator = tqdm(all_records, desc="Processing", unit="ioc") if use_tqdm else all_records
    
    skipped_count = 0
    
    for record in iterator:
        try:
            # Check if exists in cache and is sufficient
            ioc = record.get('ioc', {})
            key = f"{ioc.get('type')}:{ioc.get('value')}"
            
            if key in existing_iocs:
                existing = existing_iocs[key]
                # Skip if already scraped OR has good description
                desc = existing.get('description', '')
                if existing.get('scraped') or (desc and len(desc) >= 20):
                    normalized_iocs.append(existing)
                    skipped_count += 1
                    continue
            
            # Process new or incomplete record
            normalized = process_record(record, source_counts)
            if normalized:
                normalized_iocs.append(normalized)
                processed += 1
                if normalized.get('scraped'):
                    scraped_count += 1
                
                # Update progress description
                if use_tqdm:
                    iterator.set_postfix({
                        'ok': processed,
                        'skip': skipped_count,
                        'scr': scraped_count,
                        'err': errors
                    })
                elif processed % 10 == 0:
                    print(f"   ✅ Processed {processed}/{len(all_records)} (skipped: {skipped_count}, scraped: {scraped_count})")
        except Exception as e:
            errors += 1
            if errors <= 5:
                print(f"   ⚠️ Error processing record: {e}")
    
    # Update cross-source scores
    print(f"\n🔗 Updating cross-source validation scores...")
    update_cross_source_scores(normalized_iocs, source_counts)
    
    # Save output
    print(f"\n💾 Saving {len(normalized_iocs)} normalized IOCs to {output_path}...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    output_data = {
        'meta': {
            'generated': datetime.utcnow().isoformat() + 'Z',
            'source': 'TCTI Ingestion Pipeline',
            'total': len(normalized_iocs),
            'files_processed': len(json_files),
            'errors': errors
        },
        'events': normalized_iocs
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    
    # Generate trend predictions
    print(f"\n🔮 Generating trend predictions...")
    try:
        from models.trend_predictor import predict_trends, generate_trend_forecast
        
        predictions = predict_trends(normalized_iocs)
        forecast = generate_trend_forecast(normalized_iocs)
        
        predictions_data = {
            'meta': {
                'generated': datetime.utcnow().isoformat() + 'Z',
                'source': 'TCTI Trend Predictor',
                'date_range': predictions.get('date_range', {})
            },
            'predictions': predictions.get('predictions', []),
            'top_increasing': predictions.get('top_increasing', []),
            'summary': predictions.get('summary', {}),
            'forecast_chart': forecast
        }
        
        predictions_path = output_path.parent / 'predictions.json'
        with open(predictions_path, 'w', encoding='utf-8') as f:
            json.dump(predictions_data, f, ensure_ascii=False, indent=2)
        
        print(f"   📈 Predictions saved to {predictions_path}")
        print(f"   🔺 Top increasing threats:")
        for p in predictions.get('top_increasing', [])[:3]:
            print(f"      - {p['threat_type']}: +{p['change_percent']}%")
    except Exception as e:
        print(f"   ⚠️ Trend prediction error: {e}")
    
    # Summary
    print(f"\n✅ Pipeline complete!")
    print(f"   Total processed: {processed}")
    print(f"   Errors: {errors}")
    print(f"   Output: {output_path}")
    
    # Statistics
    severity_counts = {}
    for ioc in normalized_iocs:
        sev = ioc.get('aiSeverity', 'unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"\n📈 Severity Distribution:")
    for sev in ['critical', 'high', 'medium', 'low', 'clean']:
        count = severity_counts.get(sev, 0)
        print(f"   {sev}: {count}")


if __name__ == '__main__':
    main()
