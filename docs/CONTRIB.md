# Contributing Guide

> Auto-generated: 2026-03-24

## Prerequisites

- Python 3.11+
- Docker & Docker Compose (for local ELK stack)
- OpenAI API key (optional, for translation)

## Environment Setup

### 1. Clone & Install

```bash
cd ai-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Environment Variables

Create `ai-service/.env` (git-ignored):

```bash
# Server
AI_SERVICE_HOST=0.0.0.0
AI_SERVICE_PORT=8000
AI_SERVICE_DEBUG=false

# Authentication
AI_SERVICE_API_KEYS=tcti-dashboard-key,dev-key
AI_SERVICE_REQUIRE_AUTH=true

# Elasticsearch
ELASTICSEARCH_URL=http://localhost:9200
DATALAKE_INDEX=cyber-logs-datalake
WAREHOUSE_INDEX=cyber-logs-datawarehouse
# DATALAKE_API_KEY=       # Only for remote ELK with per-index auth
# WAREHOUSE_API_KEY=      # Only for remote ELK with per-index auth

# ML Models
DEVICE=cpu                # cpu or cuda
# MODEL_EN=               # Default: DeBERTa-v3-large
# MODEL_MULTI=            # Default: BGE-M3

# Translation (optional)
# OPENAI_API_KEY=sk-...

# HelpDesk (optional)
HELPDESK_MOCK_MODE=true

# Pipeline tuning
# ACTION_RISK_THRESHOLD=10
# ACTION_SOURCE_COUNT_THRESHOLD=2
# SCORE_MODEL_VERSION=scoring-v2.0.0

# Startup
# AI_SERVICE_SKIP_STARTUP_PRELOAD=true   # Skip model download on startup
# AI_SERVICE_AUTO_CREATE_INDEXES=true     # Auto-create ES indexes
```

### 3. Start Local ELK Stack

```bash
docker-compose up -d elasticsearch kibana
# Wait for healthy status
docker-compose logs -f elasticsearch
```

### 4. Run AI Service

```bash
cd ai-service
source venv/bin/activate
python main.py
# Service at http://localhost:8000
# Docs at http://localhost:8000/docs
```

## Development Workflow

### Running Tests

```bash
cd ai-service
./venv/bin/python -m pytest tests/ -v           # All tests
./venv/bin/python -m pytest tests/ --cov        # With coverage
./venv/bin/python -m pytest tests/test_scorer.py # Single file
```

### Dev Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `scripts/dev/verify_models.py` | Validate NLP model loading | `python scripts/dev/verify_models.py` |
| `scripts/dev/test_hybrid.py` | Test EN/Multi classifier | `python scripts/dev/test_hybrid.py` |
| `scripts/dev/verify_fake_news.py` | Test news classification | `python scripts/dev/verify_fake_news.py` |
| `scripts/dev/simulate_attack.py` | Generate attack scenarios | `python scripts/dev/simulate_attack.py` |
| `scripts/dev/seed_dashboard_fixture.py` | Seed test data via API | `python scripts/dev/seed_dashboard_fixture.py` |
| `scripts/dev/smoke_dashboard_contract.py` | API contract validation | `python scripts/dev/smoke_dashboard_contract.py` |
| `scripts/dev/smoke_dashboard_live.py` | Live integration tests | `python scripts/dev/smoke_dashboard_live.py` |
| `scripts/dev/generate_postman_from_openapi.py` | Generate Postman collection | `python scripts/dev/generate_postman_from_openapi.py` |

### Ops Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `scripts/ops/import_to_datalake.py` | Import raw JSON to ES | `python scripts/ops/import_to_datalake.py` |
| `scripts/ops/import_enrich.py` | Import + enrich in one step | `python scripts/ops/import_enrich.py` |
| `scripts/ops/rebuild_warehouse.py` | Backfill warehouse from datalake | `python scripts/ops/rebuild_warehouse.py --limit 100` |

## Project Structure

```
ai-service/
├── main.py                    # FastAPI app (83 routes)
├── config.py                  # Env vars, scoring weights, threat labels
├── elastic_client.py          # ES dual-index client
├── models/
│   ├── classifier.py          # NLP zero-shot classification
│   ├── scorer.py              # Multi-factor risk scoring
│   ├── validation.py          # Auto-validate / needs-review / reject
│   ├── sector_classifier.py   # Target sector detection
│   └── actions.py             # Operational action derivation
├── services/
│   ├── dashboard_router.py    # /api/v1 dashboard endpoints
│   ├── dashboard_compat_router.py  # Legacy route compatibility
│   ├── dashboard_bootstrap.py # In-process admin store
│   └── review_queue.py        # Human review workflow
├── utils/
│   ├── pipeline_documents.py  # IOC enrichment pipeline builder
│   ├── sanitizer.py           # PII/credential redaction
│   └── translator.py          # OpenAI GPT translation
├── integrations/
│   └── helpdesk.py            # THCert HelpDesk stub
├── scripts/{dev,ops}/         # Development & operations scripts
├── tests/                     # pytest test suite
├── config/threat_actors.json  # Threat actor database
├── requirements.txt           # Python dependencies
└── Dockerfile                 # Container build
```

## Commit Convention

```
<type>: <description>

Types: feat, fix, refactor, docs, test, chore, perf, ci
```

## Code Quality Checklist

- [ ] Tests pass (`pytest tests/`)
- [ ] No hardcoded secrets
- [ ] Functions < 50 lines
- [ ] Files < 800 lines
- [ ] Immutable patterns (no mutation)
- [ ] Input validation present
- [ ] Error handling with try/except
