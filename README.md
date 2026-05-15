# TCTI AI Service and Data Pipeline

Last updated: 2026-05-15

This repository contains the backend AI service, datalake adapters, pipeline, Elasticsearch client, dashboard API, and external sharing API for the TCTI cyber intelligence platform.

## Current Production Topology

```text
Customer Data Lake
  http://192.168.100.41:9201
  index/alias: tcti-feeds
        |
        v
AI Service on 192.168.100.44
  FastAPI container: tcti-ai-service
  local port: 127.0.0.1:9000
        |
        v
Warehouse Elasticsearch on 192.168.100.43
  warehouse: cyber-logs-datawarehouse
  processed state: cyber-logs-processed
  quarantine: cyber-logs-quarantine
        |
        v
Dashboard on 192.168.100.44
  local port: 127.0.0.1:9001
  HTTPS via Nginx: https://ctidashboard.worldinfinity.co.th
```

The datalake is treated as read-only in UAT/production. The pipeline tracks processed source records in `cyber-logs-processed`.

## Runtime Components

| Path | Purpose |
| --- | --- |
| `ai-service/main.py` | FastAPI entrypoint, core AI endpoints, pipeline run/status, scheduler |
| `ai-service/elastic_client.py` | Elasticsearch access, mappings, bulk writes, processed-state tracking, datalake cursor |
| `ai-service/datalake_adapters.py` | Raw datalake shape normalizers into canonical IOC documents |
| `ai-service/pipeline_classification_policy.py` | ML/rule/skipped classification policy |
| `ai-service/utils/pipeline_documents.py` | IOC aggregation, enrichment, scoring, validation document builder |
| `ai-service/models/scorer.py` | Risk score formula and score breakdown |
| `ai-service/models/validation.py` | Warehouse eligibility / validation policy |
| `ai-service/services/dashboard_router.py` | `/api/v1` dashboard API |
| `ai-service/services/external_sharing_router.py` | `/api/v1/external` partner sharing API |
| `ai-service/tests/test_dashboard_api.py` | Dashboard API integration tests |

## Pipeline Summary

```text
raw datalake record
-> datalake adapter
-> canonical IOC fields
-> processed-state dedup
-> aggregate observations by canonical IOC
-> classification policy
   - source_rule for IOC feeds, MISP, sandbox, Zone-H style feeds
   - ml for news/report/context-rich text
   - skipped for insufficient/generic/non-incident context
-> risk scoring
-> validation policy
-> bulk write warehouse
-> bulk write processed-state
```

The current production backfill path is optimized for large IOC feeds:

- bulk warehouse writes
- bulk processed-state writes
- datalake cursor with `search_after`
- chunked Elasticsearch bulk requests to avoid `413 Request Entity Too Large`
- Docker resource limits on `.44`

## Important Environment Variables

| Variable | Production/UAT value or behavior |
| --- | --- |
| `DATALAKE_ELASTICSEARCH_URL` | `http://192.168.100.41:9201` |
| `DATALAKE_INDEX` | `tcti-feeds` |
| `DATALAKE_READONLY` | `true` |
| `DATALAKE_QUERY_MODE` | `all` |
| `DATALAKE_SCAN_USE_CURSOR` | `true` |
| `DATALAKE_SCAN_CURSOR_ID` | stable cursor name, currently `tcti-feeds-prod` on UAT |
| `DATALAKE_SCAN_BATCH_SIZE` | `1000` |
| `DATALAKE_SCAN_MAX_PAGES` | `50` |
| `WAREHOUSE_ELASTICSEARCH_URL` | `http://192.168.100.43:9200` |
| `WAREHOUSE_INDEX` | `cyber-logs-datawarehouse` |
| `PROCESSED_INDEX` | `cyber-logs-processed` |
| `QUARANTINE_INDEX` | `cyber-logs-quarantine` |
| `ELASTIC_BULK_CHUNK_SIZE` | `500` |
| `PIPELINE_CLASSIFICATION_MODE` | `auto` |
| `PIPELINE_ML_SOURCE_TYPES` | `news,rss,article,report,advisory,blog` |
| `PIPELINE_RULE_SOURCE_TYPES` | `customer-datalake,misp,external-feed,sandbox` |
| `PIPELINE_ML_MIN_CONTEXT_CHARS` | `300` |
| `PIPELINE_ML_MAX_INPUT_CHARS` | default `1800` in policy unless overridden |
| `PIPELINE_SCHEDULER_ENABLED` | disabled during manual backfill; enable after backfill |
| `PIPELINE_SCHEDULER_LIMIT` | recommended `10000` after backfill |
| `MODEL_EN` | `MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli` |
| `MODEL_EN_FALLBACK_LARGE` | `MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli` |

Do not commit `.env` files or secrets.

## Development

```bash
cd ai-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Run the core regression suite:

```bash
cd ai-service
pytest -q \
  tests/test_incremental_pipeline.py \
  tests/test_validation.py \
  tests/test_pipeline_classification_policy.py \
  tests/test_pipeline_documents_evidence.py \
  tests/test_golden_news_fixture.py \
  tests/test_sector_nlp.py::test_threat_labels_cover_current_datalake_news_taxonomy
```

## Documentation

| Document | Purpose |
| --- | --- |
| `docs/PIPELINE_ARCHITECTURE.md` | Current datalake, adapter, pipeline, ML/rule policy, warehouse fields |
| `docs/RUNBOOK.md` | Live operations commands for `.44` and backfill monitoring |
| `docs/PRODUCTION_READINESS.md` | Production readiness status, remaining checklist, go-live rules |
| `docs/API_REFERENCE.md` | Current API groups from FastAPI routers |
| `docs/API_INVENTORY.md` | Complete route-by-route FastAPI inventory |
