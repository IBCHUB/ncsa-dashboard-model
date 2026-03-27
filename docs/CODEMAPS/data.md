# Data Models Codemap

> Freshness: 2026-03-24 | Auto-generated

## Elasticsearch Indices

### Data Lake (`cyber-logs-datalake`)

Raw IOC observations from external sources.

| Field | Type | Purpose |
|-------|------|---------|
| ioc_value | keyword | IOC identifier (IP, domain, hash) |
| ioc_type | keyword | ip, domain, url, hash, email |
| source_name | keyword | Data source name |
| source_type | keyword | Source classification |
| description | text | Free-text description |
| threat_type | keyword | Source-reported threat type |
| severity | keyword | Source-reported severity |
| tags | keyword | Classification tags |
| reference | text | Source URL/reference |
| collect_time | date | When data was collected |
| event_time | date | When event occurred |
| geo_country | keyword | Country code |
| ai_processed | boolean | Pipeline processing flag |
| created_at | date | Document creation time |

**Doc ID**: `{ioc_type}:{ioc_value}:{sha1(source|source_type|event_time|collect_time|reference|desc[:256])[:24]}`

### Data Warehouse (`cyber-logs-datawarehouse`)

AI-enriched, validated intelligence.

| Field | Type | Purpose |
|-------|------|---------|
| **Identity** | | |
| ioc_value | keyword | IOC identifier |
| ioc_type | keyword | IOC category |
| **Aggregation** | | |
| sources | keyword[] | All source names |
| source_types | keyword[] | All source types |
| source_count | integer | Number of unique sources |
| first_seen | date | Earliest observation |
| last_seen | date | Latest observation |
| ioc_age_days | integer | Days since first seen |
| **AI Classification** | | |
| ai_threat_types | keyword[] | NLP-detected threat types |
| ai_threat_actors | keyword[] | Detected threat actors |
| ai_mitre_techniques | keyword[] | MITRE ATT&CK techniques |
| ai_classification_confidence | float | NLP confidence (0-1) |
| **AI Scoring** | | |
| ai_risk_score | integer | Composite risk (0-100) |
| ai_severity | keyword | critical/high/medium/low/clean |
| ai_severity_th | keyword | Thai severity label |
| credibility_score | integer | Source credibility |
| impact_score | integer | Impact assessment |
| ai_score_breakdown | object | Per-factor scores |
| ai_top_factors | object | Top contributing factors |
| **Validation** | | |
| validation_status | keyword | validated_auto/needs_review/rejected |
| validation_reasons | keyword[] | Validation gate results |
| warehouse_eligible | boolean | Eligible for consumption |
| review_required | boolean | Needs human review |
| review_state | keyword | pending/approved/rejected |
| reviewed_by | keyword | Reviewer identifier |
| reviewed_at | date | Review timestamp |
| review_notes | text | Reviewer comments |
| **Actions** | | |
| action_required | boolean | Needs operational action |
| action_status | keyword | open/in_progress/closed |
| action_title | text | Action description |
| action_reason | keyword | Action trigger reason |
| action_opened_at | date | Action creation time |
| **Sanitization** | | |
| cleaning_flags | keyword[] | Redaction flags |
| sanitization_summary | object | Redaction details |
| **Metadata** | | |
| processed_at | date | Pipeline processing time |
| created_at | date | Document creation time |

**Doc ID**: `{ioc_type}:{sha1(ioc_type:ioc_value)[:24]}`

## Pydantic Models (API)

### Request Models
```
ClassifyRequest(text, threshold=0.3)
ScoreRequest(ioc_value, ioc_type, description, sources[], country_code, domain_age_days, ioc_age_days)
EnrichRequest(ioc_value, ioc_type, description, title, sources[], country_code, domain_age_days, ioc_age_days)
BatchEnrichRequest(items: List[EnrichRequest])
TranslateRequest(text, target_lang="th", context)
CreateTicketRequest(ioc_value, ioc_type, description, risk_score, severity, threat_types[], threat_actors[])
PipelineRunRequest(limit=100)
```

### Response Models
```
ClassifyResponse(threat_types[], confidence, all_labels[], all_scores[], threat_actors[], mitre_techniques[])
ScoreResponse(risk_score, operational_score, credibility_score, impact_score, severity, breakdown, top_factors[])
EnrichResponse(ioc fields + AI enrichment + processing_time_ms)
TranslateResponse(original, translated, target_lang, cached)
CreateTicketResponse(success, ticket_id, message, mock)
PipelineRunResponse(processed, needs_review, rejected, failed, observations_updated, processing_time_ms)
HealthResponse(status, version, classifier_loaded)
```

## Configuration Data

### Scoring Weights (sum = 1.0)
| Factor | Weight |
|--------|--------|
| cross_source | 0.25 |
| threat_type_severity | 0.20 |
| threat_intel_source | 0.15 |
| high_risk_keywords | 0.10 |
| domain_age | 0.10 |
| threat_actor | 0.10 |
| entropy | 0.05 |
| mitre_techniques | 0.05 |

### Threat Actor Config (`config/threat_actors.json`)
20+ actors with: name, aliases[], origin, category (APT/Ransomware/Malware/Hacktivist), targets[]

### Sector Risk Multipliers
| Sector | Weight | Bonus |
|--------|--------|-------|
| critical_infrastructure | 1.5x | +15 |
| government | 1.4x | +12 |
| financial | 1.3x | +10 |
| healthcare | 1.3x | +10 |
| technology | 1.1x | +5 |
| education/general | 1.0x | +0 |
