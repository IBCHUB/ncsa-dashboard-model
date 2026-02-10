# 🏗️ Architecture Documentation

Technical architecture of the TCTI Platform.

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                         TCTI Platform                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Presentation Layer                          │ │
│  │  ┌─────────────────────────────────────────────────────────┐  │ │
│  │  │           Next.js Dashboard (Port 3000)                  │  │ │
│  │  │  • Pages: Dashboard, IOC, Map, Graph, Reports           │  │ │
│  │  │  • Components: Charts, Tables, Maps, Graphs              │  │ │
│  │  │  • API Routes: /api/iocs, /api/stats, /api/analyze       │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Application Layer                           │ │
│  │  ┌─────────────────────────────────────────────────────────┐  │ │
│  │  │        FastAPI AI Service (Port 8000)                    │  │ │
│  │  │  • Classification: BART-Large Zero-shot                  │  │ │
│  │  │  • Scoring: Multi-factor risk calculation                │  │ │
│  │  │  • Translation: OpenAI GPT                               │  │ │
│  │  │  • Pipeline: ETL processing                              │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                              │                                       │
│                              ▼                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                      Data Layer                                │ │
│  │  ┌─────────────────┐       ┌─────────────────────────────┐   │ │
│  │  │   Data Lake     │──────▶│     Data Warehouse          │   │ │
│  │  │ (tcti-datalake) │  AI   │   (tcti-warehouse)          │   │ │
│  │  │   Raw IOCs      │Pipeline│   Enriched IOCs             │   │ │
│  │  └─────────────────┘       └─────────────────────────────┘   │ │
│  │                                                                │ │
│  │  ┌─────────────────────────────────────────────────────────┐  │ │
│  │  │              Elasticsearch 8.12                          │  │ │
│  │  └─────────────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Dashboard (Next.js 14)

**Technology Stack:**
- Framework: Next.js 14 (App Router)
- Language: TypeScript
- Styling: CSS Modules
- Charts: D3.js, Chart.js
- Maps: D3-geo
- Graphs: react-force-graph-2d

**Directory Structure:**
```
dashboard/
├── src/
│   ├── app/           # Pages (App Router)
│   │   ├── page.tsx   # Dashboard home
│   │   ├── ioc/       # IOC Explorer
│   │   ├── map/       # Threat Map
│   │   ├── graph/     # Threat Graph
│   │   ├── reports/   # Reports & Export
│   │   └── api/       # API Routes
│   ├── components/    # Reusable components
│   │   ├── layout/    # Header, Sidebar
│   │   └── widgets/   # Cards, Charts
│   └── lib/           # Utilities
│       ├── types/     # TypeScript definitions
│       └── graph/     # Graph building logic
└── public/
    └── data/          # Static data files
```

### 2. AI Service (FastAPI)

**Technology Stack:**
- Framework: FastAPI
- Language: Python 3.11+
- ML: Transformers (BART-Large)
- LLM: OpenAI GPT-4
- Database: Elasticsearch

**Directory Structure:**
```
ai-service/
├── main.py            # FastAPI application
├── config.py          # Configuration
├── elastic_client.py  # Elasticsearch client
├── config/
│   └── threat_actors.json  # Externalized threat actor list (dynamic updates)
├── models/
│   ├── classifier.py  # BART-Large classifier + threat actor extraction
│   ├── scorer.py      # Risk scoring (10 factors)
│   └── trend_predictor.py  # Facebook Prophet forecasting
├── utils/
│   ├── translator.py  # OpenAI translation
│   └── scraper.py     # URL content scraper for enrichment
├── integrations/
│   └── helpdesk.py    # HelpDesk integration
└── scripts/
    ├── ingest.py      # Data ingestion with tqdm progress
    └── import_to_datalake.py
```

### 3. Elasticsearch

**Indexes:**

#### tcti-datalake (Raw Data)
```json
{
  "mappings": {
    "properties": {
      "ioc_value": { "type": "keyword" },
      "ioc_type": { "type": "keyword" },
      "source_name": { "type": "keyword" },
      "description": { "type": "text" },
      "severity": { "type": "keyword" },
      "ai_processed": { "type": "boolean" },
      "created_at": { "type": "date" }
    }
  }
}
```

#### tcti-warehouse (Enriched Data)
```json
{
  "mappings": {
    "properties": {
      "ioc_value": { "type": "keyword" },
      "ioc_type": { "type": "keyword" },
      "ai_risk_score": { "type": "integer" },
      "ai_severity": { "type": "keyword" },
      "ai_threat_types": { "type": "keyword" },
      "ai_threat_actors": { "type": "keyword" },
      "ai_mitre_techniques": { "type": "keyword" },
      "processed_at": { "type": "date" }
    }
  }
}
```

---

## Data Flow

### 1. Ingestion Pipeline

```
External Sources → JSON Files → import_to_datalake.py → tcti-datalake
```

### 2. AI Processing Pipeline

```
tcti-datalake → /pipeline/run → AI Processing → tcti-warehouse
                                     │
                                     ├── Classification (BART-Large)
                                     ├── Scoring (Multi-factor)
                                     ├── Entity Extraction
                                     └── Trend Forecasting (Prophet)
```

### 3. Dashboard Query Flow

```
User Request → Dashboard API → Elasticsearch Query → Response
                    │
                    └── (Optional) AI Service enrichment
```

---

## AI/ML Components

### Classification (Zero-shot MNLI)

- **Model (configurable):** `CLASSIFIER_MODEL` (default: `typeform/distilbert-base-uncased-mnli`)
- **Task:** Zero-shot classification
- **Why this approach?**
  - **Zero-shot:** เริ่มใช้งานได้ทันทีโดยไม่ต้องมี labeled dataset สำหรับเทรน
  - **ปรับ label ง่าย:** เพิ่ม/ลด threat categories ได้โดยไม่ต้อง retrain
  - **เหมาะกับ production CPU:** ค่าเริ่มต้นเลือกโมเดลขนาดเล็กลงเพื่อความเร็วและต้นทุน
- **Optional (heavier):** สามารถสลับเป็น `facebook/bart-large-mnli` ได้ผ่าน env `CLASSIFIER_MODEL` หากต้องการความแม่นยำ/semantic ที่สูงขึ้นและยอมรับ latency ได้
- **Labels:** ดู `THREAT_CATEGORIES` ใน `ai-service/config.py`

### Risk Scoring

Multi-factor weighted scoring:

| Factor | Weight | Description |
|--------|--------|-------------|
| IOC Type | 25% | Base score by type |
| Source Reputation | 20% | Source credibility |
| Threat Classification | 25% | AI-detected threats |
| Geographic Risk | 15% | Country risk level |
| Temporal Factors | 15% | Age, recency |

### Translation (OpenAI GPT)

- **Model:** `gpt-4o-mini`
- **Features:** Cybersecurity context, term preservation
- **Caching:** LRU cache (1000 entries)

### Trend Forecasting (Facebook Prophet)

- **Model:** `prophet>=1.1.0` (Meta's Time Series Forecasting)
- **Why Prophet?**
  - **Handles Missing Data:** Threat logs often have gaps; Prophet handles this gracefully.
  - **Weekly Seasonality:** Cyber attacks follow weekly patterns (less activity on weekends).
  - **Confidence Intervals:** Provides uncertainty quantification for risk assessment.
  - **Explainable:** Business stakeholders can understand "why" the trend is increasing.
- **Fallback:** Automatic fallback to linear regression if Prophet is unavailable.

### URL Content Scraping

- **Purpose:** Enrich IOCs that have empty descriptions
- **Location:** `ai-service/utils/scraper.py`
- **Features:**
  - **Smart Scraping:** Only scrapes when `description < 20 chars`
  - **Rate Limiting:** 0.5s delay between requests to same domain
  - **LRU Cache:** 1000 URLs cached to avoid re-fetching
  - **Timeout:** 5 seconds per request
  - **Extracts:** Title, Meta Description, H1, first paragraph
- **Output Fields:** `scraped: true/false`, `scrape_error: string`

### Threat Actor Configuration

- **Purpose:** Externalized threat actor list for dynamic updates without code changes
- **Location:** `ai-service/config/threat_actors.json`
- **Features:**
  - **Alias Matching:** "Fancy Bear" → "APT28"
  - **Metadata:** Origin country, category (APT/Ransomware/Malware), targets
  - **Live Reload:** Updates loaded without service restart
- **Categories:** APT, Ransomware Gang, Malware Family, Hacktivist

---

## Security

### Authentication
- API Key-based authentication
- Key validation in middleware

### Network
- Internal services on private network
- Only Dashboard exposed publicly
- Elasticsearch not directly accessible

### Data
- No PII storage
- IOC data only
- Secure configuration via environment variables
