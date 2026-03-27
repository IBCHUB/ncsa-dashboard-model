# Operations Runbook

> Auto-generated: 2026-03-24

## Deployment

### Local Development

```bash
docker-compose up -d
# Elasticsearch: http://localhost:9200
# Kibana:        http://localhost:5601
# AI Service:    http://localhost:8000
# API Docs:      http://localhost:8000/docs
```

### Remote ELK (Production)

```bash
# Set required env vars
export ELASTICSEARCH_URL=https://your-elk.example.com
export DATALAKE_INDEX=tcti-datalake
export WAREHOUSE_INDEX=tcti-warehouse
export DATALAKE_API_KEY=your-key
export WAREHOUSE_API_KEY=your-key
export OPENAI_API_KEY=sk-...

docker-compose -f docker-compose.remote.yml up -d
# AI Service: http://localhost:9000
```

### Docker Build & Deploy

```bash
# Build
docker-compose build ai-service

# Deploy with rebuild
docker-compose up -d --build ai-service

# View logs
docker-compose logs -f ai-service
```

## Health Checks

### Service Health

```bash
curl http://localhost:8000/health
# Expected: {"status": "ok", "version": "1.0.0", "classifier_loaded": true}
```

### Elasticsearch Status

```bash
curl -H "X-API-Key: tcti-dashboard-key" http://localhost:8000/pipeline/status
# Returns: index counts, connection status
```

### Model Loading

First request after startup takes 30-120s (model download). Subsequent requests are fast.

```bash
# Check if models loaded
curl http://localhost:8000/health | jq .classifier_loaded
```

## Monitoring

### Key Metrics to Watch

| Metric | Check | Alert Threshold |
|--------|-------|-----------------|
| `/health` response | Should return `status: ok` | Any non-200 |
| `classifier_loaded` | Should be `true` after startup | `false` after 5 min |
| Pipeline processing time | `/pipeline/run` response time | > 30s per IOC |
| ES connection | `/pipeline/status` | `unavailable` status |
| Model cache disk | `/root/.cache/huggingface` | > 10 GB |

### Log Locations

| Component | Location |
|-----------|----------|
| AI Service | `docker-compose logs ai-service` |
| Elasticsearch | `docker-compose logs elasticsearch` |
| HelpDesk tickets | `/tmp/helpdesk_tickets.jsonl` (mock mode) |

## Common Operations

### Run AI Pipeline

```bash
# Process 100 unprocessed IOCs from datalake
curl -X POST http://localhost:8000/pipeline/run \
  -H "X-API-Key: tcti-dashboard-key" \
  -H "Content-Type: application/json" \
  -d '{"limit": 100}'
```

### Import Data to Datalake

```bash
# Place JSON files in data_lake/ directory
cd ai-service
python scripts/ops/import_to_datalake.py
```

### Rebuild Warehouse (Backfill)

```bash
cd ai-service

# Dry run first
python scripts/ops/rebuild_warehouse.py \
  --date-from 2026-03-01T00:00:00+07:00 \
  --date-to 2026-03-24T23:59:59+07:00 \
  --limit 500

# Write to warehouse (after reviewing dry-run)
python scripts/ops/rebuild_warehouse.py \
  --write \
  --date-from 2026-03-01T00:00:00+07:00 \
  --date-to 2026-03-24T23:59:59+07:00
```

### Review Queue

```bash
# List items needing review
curl -H "X-API-Key: tcti-dashboard-key" \
  "http://localhost:8000/pipeline/review-queue?limit=20"

# Approve
curl -X POST http://localhost:8000/pipeline/review/DOC_ID/approve \
  -H "X-API-Key: tcti-dashboard-key" \
  -H "Content-Type: application/json" \
  -d '{"reviewer": "admin", "notes": "Verified"}'

# Reject
curl -X POST http://localhost:8000/pipeline/review/DOC_ID/reject \
  -H "X-API-Key: tcti-dashboard-key" \
  -H "Content-Type: application/json" \
  -d '{"reviewer": "admin", "notes": "False positive"}'
```

## Common Issues & Fixes

### 1. Model Download Fails

**Symptom:** `/health` returns `classifier_loaded: false`

**Fix:**
```bash
# Check disk space
df -h /root/.cache/huggingface

# Clear cache and restart
docker exec tcti-ai-service rm -rf /root/.cache/huggingface/*
docker-compose restart ai-service

# Or skip preload and load on first request
AI_SERVICE_SKIP_STARTUP_PRELOAD=true docker-compose up -d ai-service
```

### 2. Elasticsearch Connection Failed

**Symptom:** `/pipeline/status` shows `unavailable`

**Fix:**
```bash
# Check ES health
curl http://localhost:9200/_cluster/health

# Check container
docker-compose ps elasticsearch
docker-compose logs elasticsearch | tail -20

# Restart ES
docker-compose restart elasticsearch
```

### 3. Out of Memory (OOM)

**Symptom:** Container killed, restart loop

**Fix:**
```bash
# Increase ES heap
# In docker-compose.yml: ES_JAVA_OPTS=-Xms1g -Xmx1g

# Use CPU device (less memory than CUDA)
# DEVICE=cpu

# Reduce batch size in pipeline
curl -X POST .../pipeline/run -d '{"limit": 10}'
```

### 4. Translation Not Working

**Symptom:** `/translate` returns original text

**Fix:**
```bash
# Check API key
echo $OPENAI_API_KEY | head -c 10

# Test directly
curl -X POST http://localhost:8000/translate \
  -H "X-API-Key: tcti-dashboard-key" \
  -H "Content-Type: application/json" \
  -d '{"text": "test", "target_lang": "th"}'
```

### 5. Index Not Found

**Symptom:** Pipeline returns errors about missing index

**Fix:**
```bash
# Create indexes
curl -X POST http://localhost:8000/elasticsearch/setup \
  -H "X-API-Key: tcti-dashboard-key"

# Or set auto-create
AI_SERVICE_AUTO_CREATE_INDEXES=true
```

### 6. High Risk Score Discrepancy

**Symptom:** Scores don't match expectations

**Check:**
```bash
# Get score breakdown
curl -X POST http://localhost:8000/score \
  -H "X-API-Key: tcti-dashboard-key" \
  -H "Content-Type: application/json" \
  -d '{"ioc_value": "...", "ioc_type": "domain", "description": "...", "sources": ["VirusTotal"]}' \
  | jq '.breakdown, .top_factors'

# Check scoring model version
echo $SCORE_MODEL_VERSION   # Default: scoring-v2.0.0
echo $SCORE_CONFIG_VERSION  # Default: weights-v1
```

## Rollback Procedures

### Rollback AI Service

```bash
# Tag current version before deploy
docker tag tcti-ai-service:latest tcti-ai-service:backup-$(date +%Y%m%d)

# Rollback to previous image
docker-compose down ai-service
docker tag tcti-ai-service:backup-YYYYMMDD tcti-ai-service:latest
docker-compose up -d ai-service
```

### Rollback Warehouse Data

```bash
# Warehouse is append-only with validation_status tracking
# To "rollback" bad data: mark as rejected
curl -X POST http://localhost:8000/pipeline/review/DOC_ID/reject \
  -H "X-API-Key: tcti-dashboard-key" \
  -d '{"reviewer": "ops", "notes": "Rollback: bad scoring model"}'

# For bulk rollback: rebuild warehouse from datalake
python scripts/ops/rebuild_warehouse.py \
  --write \
  --date-from START \
  --date-to END
```

### Rollback Git

```bash
# View recent commits
git log --oneline -10

# Revert specific commit
git revert COMMIT_HASH

# Reset to previous state (destructive)
# git reset --hard COMMIT_HASH  # Use with caution
```

## Ports Reference

| Service | Local | Remote | Purpose |
|---------|-------|--------|---------|
| AI Service | 8000 | 9000 | FastAPI API |
| Elasticsearch | 9200 | - | REST API |
| Elasticsearch | 9300 | - | Node communication |
| Kibana | 5601 | - | Web UI |
