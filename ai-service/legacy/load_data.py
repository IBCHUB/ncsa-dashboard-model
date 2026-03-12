
import json
import requests
import sys

# Config
ES_URL = "http://elasticsearch:9200"
INDEX_NAME = "tcti-warehouse"
FILE_PATH = "/app/data/normalized_iocs.json"

def bulk_import():
    print(f"Loading data from {FILE_PATH}...")
    try:
        with open(FILE_PATH, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Error: File not found!")
        return

    # Handle if data is wrapped in keys
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get('normalized_iocs') or data.get('events') or []
    
    print(f"Found {len(items)} items. Creating bulk request...")
    
    bulk_data = ""
    for item in items:
        # --- DATA CLEANING ---
        # Fix enrichment.status (sometimes it's a dict {}, sometimes a string)
        if 'enrichment' in item and item['enrichment']:
            if isinstance(item['enrichment'].get('status'), dict):
                # Flatten or convert to string
                item['enrichment']['status'] = str(item['enrichment']['status'])
            
            # Fix empty dates in Whois
            if 'whois' in item['enrichment']:
                whois = item['enrichment']['whois']
                if whois.get('regdate') == "":
                    item['enrichment']['whois']['regdate'] = None
                if whois.get('updateddate') == "":
                    item['enrichment']['whois']['updateddate'] = None
        # ---------------------

        # Action metadata
        bulk_data += json.dumps({"index": {"_index": INDEX_NAME}}) + "\n"
        # Document data
        bulk_data += json.dumps(item) + "\n"
    
    if not bulk_data:
        print("No data to import.")
        return

    # Send to Elasticsearch
    print(f"Sending bulk request to {ES_URL}/{INDEX_NAME}/_bulk ...")
    headers = {'Content-Type': 'application/x-ndjson'}
    resp = requests.post(f"{ES_URL}/_bulk", data=bulk_data, headers=headers)
    
    if resp.status_code == 200:
        res = resp.json()
        if res.get('errors'):
            print("Completed with ERRORS!")
            # Print first error
            for item in res['items']:
                if 'error' in item['index']:
                    print(f"Error: {item['index']['error']}")
                    break
        else:
            print(f"Successfully imported {len(items)} documents! ✅")
    else:
        print(f"Failed! Status: {resp.status_code}, {resp.text}")

if __name__ == "__main__":
    bulk_import()
