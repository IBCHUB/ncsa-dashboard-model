# 📘 AI Service API Documentation

Complete reference for the TCTI AI Service REST API.

**Base URL:** `http://localhost:8000`

---

## Authentication

All endpoints (except `/health`) require an API Key header. The AI Service accepts one of the comma-separated keys in `AI_SERVICE_API_KEYS` (env var).

```
X-API-Key: <one-of-your-ai-service-keys>
```

---

## Endpoints

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "classifier_loaded": true
}
```

---

### Classify Threat

Classify threat text into categories using zero-shot classification. The model is configurable via `CLASSIFIER_MODEL` (env var).

```http
POST /classify
```

**Request:**
```json
{
  "text": "Ransomware attack targeting financial institutions via phishing emails",
  "threshold": 0.3
}
```

**Response:**
```json
{
  "threat_types": ["Ransomware", "Phishing"],
  "confidence": 0.87,
  "all_labels": ["Ransomware", "Phishing", "Malware", "APT"],
  "all_scores": [0.87, 0.72, 0.45, 0.12],
  "threat_actors": ["Lazarus Group"],
  "mitre_techniques": ["T1566", "T1486"]
}
```

---

### Calculate Risk Score

Score an IOC based on multiple risk factors.

```http
POST /score
```

**Request:**
```json
{
  "ioc_value": "malicious-domain.com",
  "ioc_type": "domain",
  "description": "C2 server for ransomware operation",
  "sources": ["CERT-TH", "OpenCTI", "VirusTotal"],
  "country_code": "RU",
  "domain_age_days": 7
}
```

**Response:**
```json
{
  "risk_score": 85,
  "severity": "critical",
  "breakdown": {
    "base_type_score": { "score": 35, "weight": 0.25 },
    "source_reputation": { "score": 25, "weight": 0.20 },
    "threat_classification": { "score": 30, "weight": 0.25 }
  },
  "top_factors": [
    { "factor": "Multiple sources", "impact": "+15", "reason": "Seen in 3 sources" },
    { "factor": "New domain", "impact": "+10", "reason": "Domain age < 30 days" }
  ]
}
```

---

### Full Enrichment

Combine classification and scoring in one call.

```http
POST /enrich
```

**Request:**
```json
{
  "ioc_value": "192.168.1.100",
  "ioc_type": "ip",
  "title": "Suspicious Connection",
  "description": "Outbound connection to known C2 server",
  "sources": ["Firewall", "SIEM"],
  "country_code": "CN"
}
```

**Response:**
```json
{
  "ioc_value": "192.168.1.100",
  "ioc_type": "ip",
  "ai_threat_types": ["c2", "malware"],
  "ai_threat_actors": [],
  "ai_mitre_techniques": ["T1071"],
  "ai_classification_confidence": 0.75,
  "ai_risk_score": 72,
  "ai_severity": "high",
  "ai_score_breakdown": { ... },
  "ai_top_factors": [ ... ],
  "processing_time_ms": 245
}
```

---

### Batch Enrichment

Process multiple IOCs at once.

```http
POST /enrich/batch
```

**Request:**
```json
{
  "items": [
    { "ioc_value": "8.8.8.8", "ioc_type": "ip", "description": "DNS server" },
    { "ioc_value": "evil.com", "ioc_type": "domain", "description": "Phishing site" }
  ]
}
```

---

### Translate Text

AI-powered translation with cybersecurity context.

```http
POST /translate
```

**Request:**
```json
{
  "text": "Lateral movement detected in network. C2 beacon activity observed.",
  "target_lang": "th",
  "context": "cybersecurity threat intelligence"
}
```

**Response:**
```json
{
  "original": "Lateral movement detected in network. C2 beacon activity observed.",
  "translated": "ตรวจพบการแพร่กระจายในเครือข่าย มีการสังเกตเห็นกิจกรรมสัญญาณ C2",
  "target_lang": "th",
  "cached": false
}
```

**Supported Languages:**
- `th` - Thai (default)
- `en` - English
- `ja` - Japanese
- `zh` - Chinese

---

### Run AI Pipeline

Process unprocessed IOCs from Data Lake to Data Warehouse.

```http
POST /pipeline/run
```

**Request:**
```json
{
  "limit": 50
}
```

**Response:**
```json
{
  "processed": 50,
  "failed": 0,
  "processing_time_ms": 12500,
  "message": "Pipeline completed: 50 aggregated IOCs processed, 130 observations updated, 0 failed"
}
```

---

### Pipeline Status

Get Elasticsearch health and document counts.

```http
GET /pipeline/status
```

**Response:**
```json
{
  "status": "green",
  "datalake_index": "tcti-datalake",
  "processed_index": "tcti-processed",
  "warehouse_index": "tcti-warehouse",
  "datalake_count": 353,
  "processed_count": 340,
  "warehouse_count": 353
}
```

---

### Create HelpDesk Ticket

Create incident ticket in HelpDesk system.

```http
POST /helpdesk/ticket
```

**Request:**
```json
{
  "ioc_value": "malware.exe",
  "ioc_type": "hash",
  "description": "Ransomware detected on endpoint",
  "risk_score": 95,
  "severity": "critical",
  "threat_types": ["ransomware"],
  "threat_actors": ["LockBit"]
}
```

**Response:**
```json
{
  "success": true,
  "ticket_id": "INC-2024-001234",
  "message": "Ticket created successfully",
  "mock": true
}
```

---

## Error Handling

### 401 Unauthorized
```json
{
  "detail": "Missing API Key. Include 'X-API-Key' header."
}
```

### 403 Forbidden
```json
{
  "detail": "Invalid API Key."
}
```

### 500 Internal Server Error
```json
{
  "detail": "Error message describing the issue"
}
```

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/translate` | 100 req/min (OpenAI dependent) |
| `/enrich/batch` | 10 req/min |
| Other endpoints | No limit |
