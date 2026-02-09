# 🛡️ Thailand Cyber Threat Intelligence (TCTI) Platform

A comprehensive cyber threat intelligence platform for monitoring, analyzing, and responding to security threats targeting Thailand.

## 📋 Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Services](#services)
- [API Documentation](#api-documentation)
- [Screenshots](#screenshots)

---

## Overview

TCTI is an enterprise-grade threat intelligence platform built with:

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Dashboard** | Next.js 14 (TypeScript) | Interactive web interface |
| **AI Service** | FastAPI (Python) | NLP classification & risk scoring |
| **Data Store** | Elasticsearch 8.12 | Data Lake & Data Warehouse |
| **Visualization** | Kibana | Data exploration |

### Key Features
- 🔍 **IOC Analysis** - IP, Domain, Hash, URL classification
- 🤖 **AI/ML Scoring** - BART-Large-powered threat classification
- 📊 **Risk Scoring** - Automated severity assessment (0-100)
- 🗺️ **Threat Map** - Geographic visualization
- 🔗 **Threat Graph** - Relationship mapping
- 🌐 **Translation** - OpenAI GPT-powered multilingual support
- 📤 **Export** - CSV, JSON, Suricata, Snort formats
- 🎫 **HelpDesk Integration** - Ticket creation API

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      TCTI Platform                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐ │
│  │  Dashboard  │───▶│  AI Service │───▶│  Elasticsearch  │ │
│  │  (Next.js)  │    │  (FastAPI)  │    │  (Data Lake)    │ │
│  │  Port 3000  │    │  Port 8000  │    │  Port 9200      │ │
│  └─────────────┘    └─────────────┘    └─────────────────┘ │
│         │                                       │          │
│         │           ┌─────────────┐              │          │
│         └──────────▶│   Kibana    │◀─────────────┘          │
│                     │  Port 5601  │                         │
│                     └─────────────┘                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Raw IOC Sources → Data Lake (tcti-datalake) 
                       ↓
              AI Processing Pipeline
                       ↓
              Data Warehouse (tcti-warehouse)
                       ↓
                   Dashboard
```

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for local development)
- Python 3.11+ (for local development)

### Option 1: Docker (Recommended)

```bash
# Clone and start all services
cd /path/to/Cyber
docker-compose up -d

# Wait for Elasticsearch to be ready (~60 seconds)
# Then access:
# - Dashboard: http://localhost:3000
# - AI Service: http://localhost:8000
# - Kibana: http://localhost:5601
```

### Option 2: Local Development

```bash
# Terminal 1: Start Elasticsearch
docker-compose up elasticsearch kibana

# Terminal 2: Start AI Service
cd ai-service
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py

# Terminal 3: Start Dashboard
cd dashboard
npm install
npm run dev
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | - | Required for translation |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Elasticsearch endpoint |
| `AI_SERVICE_URL` | `http://localhost:8000` | AI Service endpoint |

---

## Services

### 1. Dashboard (Next.js)
- **Port:** 3000
- **Path:** `/dashboard`
- **Features:**
  - IOC Explorer with search & filters
  - Real-time statistics
  - Threat map visualization
  - Relationship graph
  - Report generation & export

### 2. AI Service (FastAPI)
- **Port:** 8000
- **Path:** `/ai-service`
- **Features:**
  - Threat classification (DistilBERT)
  - Risk scoring (0-100)
  - Entity extraction (Threat Actors, MITRE)
  - Translation (OpenAI GPT)

### 3. Elasticsearch
- **Port:** 9200
- **Indexes:**
  - `tcti-datalake` - Raw IOC data
  - `tcti-warehouse` - AI-processed data

### 4. Kibana
- **Port:** 5601
- **Purpose:** Data exploration & dev tools

---

## API Documentation

### AI Service Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/classify` | Classify threat text |
| `POST` | `/score` | Calculate risk score |
| `POST` | `/enrich` | Full enrichment (classify + score) |
| `POST` | `/translate` | Translate text (OpenAI) |
| `POST` | `/pipeline/run` | Run AI processing pipeline |
| `GET` | `/pipeline/status` | Get pipeline status |
| `POST` | `/helpdesk/ticket` | Create HelpDesk ticket |

### Authentication

All API endpoints require an API Key header:

```bash
curl -H "X-API-Key: tcti-dev-key-2024" http://localhost:8000/health
```

### Example: Enrich IOC

```bash
curl -X POST http://localhost:8000/enrich \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{
    "ioc_value": "192.168.1.1",
    "ioc_type": "ip",
    "description": "Suspicious C2 communication detected",
    "sources": ["CERT-TH", "OpenCTI"]
  }'
```

### Example: Translate Text

```bash
curl -X POST http://localhost:8000/translate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{
    "text": "Lateral movement detected in network",
    "target_lang": "th"
  }'
```

---

## Data Pipeline

### Import IOCs to Data Lake

```bash
cd ai-service
source venv/bin/activate
python scripts/import_to_datalake.py
```

### Run AI Processing Pipeline

```bash
curl -X POST http://localhost:8000/pipeline/run \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{"limit": 50}'
```

### Internal Access (Dashboard + 2FA)

Set these before running dashboard:

```bash
export DASHBOARD_AUTH_USER=\"internal@tcti.local\"
export DASHBOARD_AUTH_PASSWORD=\"<strong-password>\"
export DASHBOARD_2FA_SECRET=\"<base32-totp-secret>\"
export DASHBOARD_SESSION_SECRET=\"<random-long-secret>\"
```

---

## Export Formats

The Reports page supports multiple export formats:

| Format | Extension | Use Case |
|--------|-----------|----------|
| CSV | `.csv` | Spreadsheet analysis |
| JSON | `.json` | API integration |
| Suricata | `.rules` | IDS/IPS rules |
| Snort | `.rules` | IDS/IPS rules |
| Text | `.txt` | Human-readable report |
| Blocklist | `.txt` | Firewall/proxy blocking |

---

## Project Structure

```
Cyber/
├── ai-service/           # Python AI Service
│   ├── main.py          # FastAPI application
│   ├── models/          # AI/ML models
│   ├── utils/           # Utilities (translator, etc.)
│   ├── scripts/         # Pipeline scripts
│   └── elastic_client.py # Elasticsearch client
│
├── dashboard/            # Next.js Dashboard
│   ├── src/
│   │   ├── app/         # Pages (App Router)
│   │   ├── components/  # React components
│   │   └── lib/         # Utilities & types
│   └── public/data/     # Static data files
│
├── data_lake/           # Raw IOC data (JSON)
├── docker-compose.yml   # Docker orchestration
└── README.md            # This file
```

---

## License

Proprietary - Thailand National Cyber Security Agency (NCSA)

---

## Support

For issues and queries, contact the development team.
