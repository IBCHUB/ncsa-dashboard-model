# Backend Codemap

> Freshness: 2026-03-24 | Auto-generated

## Entry Point

`main.py` — FastAPI app, 83 routes, auth middleware, startup model preload

## API Endpoints (Key)

### Core AI (require auth)
| Method | Path | Purpose |
|--------|------|---------|
| POST | /classify | NLP threat classification |
| POST | /score | Multi-factor risk scoring |
| POST | /enrich | Combined classify + score |
| POST | /enrich/batch | Batch enrichment |
| POST | /translate | OpenAI-powered translation |

### Pipeline (require auth)
| Method | Path | Purpose |
|--------|------|---------|
| POST | /pipeline/run | Process unprocessed IOCs |
| GET | /pipeline/review-queue | List items needing review |
| POST | /pipeline/review/{id}/approve | Approve reviewed item |
| POST | /pipeline/review/{id}/reject | Reject reviewed item |
| GET | /pipeline/status | ES index health |

### Dashboard API (/api/v1)
| Method | Path | Purpose |
|--------|------|---------|
| POST | /api/v1/auth/login | Dashboard login |
| GET | /api/v1/executive/dashboard | Executive overview |
| GET | /api/v1/operations/dashboard | Operations overview |
| GET | /api/v1/iocs | IOC listing |
| GET | /api/v1/actions | Action center |
| GET | /api/v1/news | Threat news feed |
| GET | /api/v1/lookups/* | Reference data |
| GET | /api/v1/reports/* | Report generation |

### Compat Routes (legacy frontend)
| Method | Path | Maps To |
|--------|------|---------|
| POST | /login | /api/v1/auth/login |
| GET | /dashboard | /api/v1/operations/dashboard |
| GET | /severity | /api/v1/lookups/severities |
| GET | /threat-type | /api/v1/lookups/threat-types |

## Models Layer

### classifier.py
```
classify_threat(text, labels?, multi_label?, threshold?) → {labels, scores, threat_types, confidence, language, model_used}
extract_threat_actors(text) → List[str]
extract_mitre_techniques(text) → List[str]
models_loaded() → bool
```

### scorer.py
```
calculate_risk_score(ioc_value, ioc_type, description, sources, country_code, domain_age_days, ioc_age_days, threat_classification?) → {risk_score, severity, breakdown, top_factors}
calculate_entropy(text) → float
```

### validation.py
```
evaluate_validation_status(ioc_value, ioc_type, score_result, ai_confidence, sanitization_summary?) → {validation_status, validation_reasons, warehouse_eligible, review_required, ...}
```
Statuses: `validated_auto`, `validated_manual`, `needs_review`, `rejected`, `rejected_manual`

### sector_classifier.py
```
classify_sector(description?, title?, ioc_value?, ioc_type?, threat_actors?, tags?) → {sector, confidence, risk_bonus, weight, ...}
```
Sectors: financial(1.3x), government(1.4x), healthcare(1.3x), critical_infrastructure(1.5x), technology(1.1x), education(1.0x), general(1.0x)

### actions.py
```
derive_action_metadata(document) → {action_required, action_status, action_title, action_reason, ...}
should_open_action(document) → bool
normalize_severity(value) → str
```

## Utils Layer

### pipeline_documents.py
```
build_enriched_ioc_document(ioc_docs: List[Dict]) → Dict
```
Aggregates observations → sanitize → classify → score → validate → derive actions

### sanitizer.py
```
sanitize_text(value) → {text, redaction_counts, sanitized, flags}
sanitize_observation_fields(descriptions, references, tags) → {descriptions, references, tags, summary}
```
Redacts: emails, Thai IDs (13-digit), bearer tokens, credentials, private IPs, phones

### translator.py
```
translate_content(text, target_lang="th", context?) → str
```
OpenAI GPT-4o-mini, cybersecurity context, in-memory cache

## Services Layer

### dashboard_router.py — `/api/v1` prefix, ELK-backed analytics
### dashboard_compat_router.py — Legacy flat routes mapping to /api/v1
### dashboard_bootstrap.py — In-process admin/user store
### review_queue.py — Manual review workflow helpers

## Integrations

### helpdesk.py — THCert HelpDesk ticket creation (mock/real mode)
```
create_incident_ticket(ioc_value, ioc_type, description, risk_score, severity, ...) → TicketResponse
```
