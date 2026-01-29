# Thailand Cyber Threat Intelligence - AI Service

Python-based AI service for threat classification and risk scoring using NLP.

## Features

- **Zero-shot Threat Classification**: Uses DistilBERT-MNLI for classifying threats without training data
- **Intelligent Risk Scoring**: Multi-factor scoring based on cross-source validation, keywords, entropy, and more
- **Threat Actor Extraction**: Identifies known threat actors from descriptions
- **MITRE ATT&CK Detection**: Extracts technique IDs from text
- **Trend Prediction**: Linear Regression forecasting for threat trends

## Documentation

| เอกสาร | เนื้อหา |
|--------|---------|
| [AI Scoring](docs/AI-SCORING.md) | เกณฑ์การให้คะแนน 10 ปัจจัย, น้ำหนัก, Threat Actors, MITRE |
| [Trend Prediction](docs/TREND-PREDICTION.md) | วิธีคำนวณแนวโน้มด้วย Linear Regression |


### Local Development

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run server
python main.py
```

Server will start at `http://localhost:8000`

### Docker

```bash
# Build and run
docker build -t tcti-ai-service .
docker run -p 8000:8000 tcti-ai-service

# Or use Docker Compose (from parent directory)
cd ..
docker-compose up ai-service
```

## API Endpoints

### Health Check
```bash
curl http://localhost:8000/health
```

### Classify Threat
```bash
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{"text": "Ransomware attack encrypts files and demands Bitcoin"}'
```

### Calculate Risk Score
```bash
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "malicious.domain.com",
    "ioc_type": "domain",
    "description": "Known phishing domain",
    "sources": ["VirusTotal", "AbuseIPDB"]
  }'
```

### Full Enrichment (Classification + Scoring)
```bash
curl -X POST http://localhost:8000/enrich \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "malicious.domain.com",
    "ioc_type": "domain",
    "title": "Phishing Campaign",
    "description": "Lazarus Group phishing campaign targeting banks",
    "sources": ["VirusTotal", "BleepingComputer"],
    "country_code": "KP"
  }'
```

## Response Example

```json
{
  "ioc_value": "malicious.domain.com",
  "ioc_type": "domain",
  "ai_threat_types": ["Phishing", "Credential Theft"],
  "ai_threat_actors": ["Lazarus"],
  "ai_mitre_techniques": [],
  "ai_classification_confidence": 0.95,
  "ai_risk_score": 85,
  "ai_severity": "high",
  "ai_score_breakdown": {
    "cross_source": {"score": 25, "count": 2},
    "keywords": {"score": 20, "keywords": ["phishing", "lazarus"]},
    "geo_risk": {"score": 15, "country": "KP"}
  },
  "processing_time_ms": 250
}
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_SERVICE_HOST` | 0.0.0.0 | Server host |
| `AI_SERVICE_PORT` | 8000 | Server port |
| `DEVICE` | cpu | Device for inference (cpu/cuda) |
| `CLASSIFIER_MODEL` | typeform/distilbert-base-uncased-mnli | HuggingFace model |

## Integration with Dashboard

The AI Service integrates with the Next.js dashboard through `normalize-data.ts`:

```bash
# Ensure AI Service is running, then run normalization
cd ../dashboard
npx tsx src/scripts/normalize-data.ts
```

This will:
1. Check if AI Service is healthy
2. Call `/enrich` for each IOC with sufficient description
3. Store AI-enriched fields in `normalized_iocs.json`

## Threat Categories

The classifier recognizes these threat types:
- Ransomware
- Phishing
- Malware
- Data Breach
- DDoS
- APT
- Defacement
- Vulnerability
- Botnet
- C2
- Credential Theft

## Known Threat Actors

The service can identify:
- Lazarus, APT28, APT29, Fancy Bear, Cozy Bear
- LockBit, Conti, REvil, BlackCat, ALPHV
- Emotet, TrickBot, Qakbot
- And more...

## License

Internal use only - Thailand Cyber Threat Intelligence Platform
