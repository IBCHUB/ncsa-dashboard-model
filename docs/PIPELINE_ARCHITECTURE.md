# TCTI Pipeline Architecture

Last updated: 2026-05-15

## Source of Truth

The current production/UAT pipeline is the code under:

```text
ai-service/
```

Important modules:

| Module | Responsibility |
| --- | --- |
| `datalake_adapters.py` | Normalize multiple raw datalake shapes into canonical IOC records |
| `elastic_client.py` | Elasticsearch connections, mappings, processed-state, cursor, bulk writes |
| `pipeline_classification_policy.py` | Choose `ml`, `source_rule`, or `skipped` classification |
| `utils/pipeline_documents.py` | Aggregate IOC observations and build warehouse documents |
| `models/scorer.py` | Risk scoring |
| `models/validation.py` | Warehouse eligibility and validation reasons |
| `main.py` | FastAPI pipeline run/status and scheduler |

## Data Flow

```text
tcti-feeds raw document
-> normalize_datalake_hit()
-> canonical IOC observation
-> processed-state lookup in cyber-logs-processed
-> group by canonical IOC
-> build_enriched_ioc_document()
-> classification policy
-> risk score
-> validation status
-> bulk write cyber-logs-datawarehouse
-> bulk write cyber-logs-processed
```

## Canonical IOC Fields

Adapters should output these fields when available:

```text
_index
_id
adapter_name
adapter_status
ioc_type
ioc_value
canonical_ioc_key
original_ioc_type
original_ioc_value
source_name
source_type
description
threat_type
severity
confidence
event_time
collect_time
tags
reference
source_url
source_evidence
```

Unsupported raw shapes are quarantined instead of crashing the pipeline.

## Classification Policy

`PIPELINE_CLASSIFICATION_MODE=auto` is the production default.

| Mode | Used when | Behavior |
| --- | --- | --- |
| `source_rule` | IOC feed, MISP, external-feed, sandbox, Zone-H-like feeds, context rule hits | No DeBERTa call; maps source metadata and keywords |
| `ml` | news/report/article/advisory/blog or rich context that needs interpretation | Runs zero-shot classifier with strict threshold |
| `skipped` | generic feed text, insufficient context, non-incident tutorial/removal content | No ML; low confidence |

Rule mapping examples:

| Source metadata | Warehouse threat type |
| --- | --- |
| `malware_payload`, `infecting_url`, `payload_delivery` | `Malware` |
| `phishing_website` | `Phishing` |
| `cnc_server` | `C2` |
| `botnet` | `Botnet` |
| `cc_skimming`, `stealer` | `Credential Theft` |
| `defacement`, `Zone-H` | `Defacement` |
| `CVE`, `RCE`, `actively exploited`, `KEV` | `Exploited Vulnerability`, `Remote Code Execution` |

## Warehouse Fields Added by Current Pipeline

Current warehouse documents include both legacy dashboard fields and pipeline audit fields:

```text
canonical_ioc_key
original_ioc_values
original_ioc_types
source_types
source_urls
source_risk_score
source_actionable
external_evidence_sources
virustotal_malicious
virustotal_suspicious
related_doc_count
source_campaigns
source_target_countries
source_malware_family
source_evidence
classification_mode
classification_reason
classifier_input_chars
classifier_effective_input_chars
classification_time_ms
validation_status
validation_reasons
warehouse_eligible
```

## Processed-State and Cursor

The datalake source is read-only, so the pipeline does not update `tcti-feeds`. Instead it writes state documents into `cyber-logs-processed`.

Finished states:

```text
processed
rejected
quarantined
```

The datalake scan cursor is also stored in `cyber-logs-processed` with `adapter_name=pipeline_cursor`.

Key variables:

```text
DATALAKE_SCAN_USE_CURSOR=true
DATALAKE_SCAN_CURSOR_ID=tcti-feeds-prod
DATALAKE_SCAN_BATCH_SIZE=1000
DATALAKE_SCAN_MAX_PAGES=50
```

## Bulk Writes

The pipeline writes warehouse and processed-state documents with bulk requests.

```text
ELASTIC_BULK_CHUNK_SIZE=500
```

This prevents oversized bulk payloads and avoids the previous `413 Request Entity Too Large` failure mode.

## Validation Policy

Validation does not simply accept every IOC. It uses:

- risk score
- source count
- source type
- classification mode
- source evidence
- confidence
- sanitization flags

Rule-based IOC feed records can be warehouse-eligible when they have enough trusted source/evidence signal. Low-signal records are still written with `validation_status=rejected` and `warehouse_eligible=false`.

