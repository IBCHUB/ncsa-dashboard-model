# Architecture Codemap

> Freshness: 2026-03-24 | Auto-generated

## System Overview

Thailand Cyber Threat Intelligence (TCTI) Platform — Python AI service for IOC classification, risk scoring, and validation.

## Data Flow

```
External Sources → Elasticsearch Data Lake → AI Pipeline → Data Warehouse → Dashboard/Consumers
```

## Services

| Service | Tech | Port | Purpose |
|---------|------|------|---------|
| ai-service | FastAPI + Python 3.11 | 8000 | NLP classification, scoring, pipeline |
| elasticsearch | ES 8.12 | 9200 | Dual-index storage (datalake + warehouse) |
| kibana | Kibana 8.12 | 5601 | Dev visualization (local only) |

## Module Dependency Graph

```
main.py (FastAPI app)
├── config.py (env vars, weights, labels, actors)
├── elastic_client.py (ES dual-index client)
├── models/
│   ├── classifier.py ← config, transformers, lingua
│   ├── scorer.py ← config, sector_classifier
│   ├── sector_classifier.py ← config
│   ├── validation.py ← config
│   └── actions.py (standalone)
├── services/
│   ├── dashboard_router.py ← elastic_client, dashboard_bootstrap, actions
│   ├── dashboard_compat_router.py ← dashboard_router, dashboard_bootstrap
│   ├── dashboard_bootstrap.py (in-process admin store)
│   └── review_queue.py ← elastic_client, validation
├── utils/
│   ├── pipeline_documents.py ← classifier, scorer, validation, actions, sanitizer
│   ├── sanitizer.py (standalone)
│   └── translator.py ← openai
└── integrations/
    └── helpdesk.py ← httpx (THCert HelpDesk stub)
```

## Infrastructure

| Component | Config |
|-----------|--------|
| Docker | docker-compose.yml (local), docker-compose.remote.yml (remote ELK) |
| Auth | X-API-Key header, per-index ES API keys |
| Models | HuggingFace cache at /root/.cache/huggingface |
| Translation | OpenAI GPT-4o-mini with in-memory cache |

## Key Design Decisions

1. Hybrid NLP: language detection → English (DeBERTa) or Multilingual (BGE-M3)
2. Observation aggregation: group same IOC from multiple sources before enrichment
3. Immutable Data Lake: raw data only marked as processed, never mutated
4. Review gate: auto-validate vs needs-review separation
5. Modular scoring: configurable weights (sum=1.0) for tuning without code changes
