# คู่มือสำหรับนักพัฒนา (Contributing Guide)

> อัปเดตล่าสุด: 2026-03-30 (อิงตาม Source of Truth ล่าสุด)

## สิ่งที่ต้องเตรียม (Prerequisites)

- Python 3.11+
- Docker & Docker Compose (สำหรับรัน Elasticsearch ใน Local)
- *(ระบบแปลภาษาทำงานแบบ Offline ผ่าน Huggingface ไม่จำเป็นต้องใช้ OpenAI API)*

## การตั้งค่าสภาพแวดล้อม (Environment Setup)

### 1. ติดตั้ง Dependencies

```bash
cd ai-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. ตัวแปรแวดล้อม (Environment Variables)

สร้างไฟล์ `ai-service/.env` (ไฟล์นี้ถูกยกเว้นใน `.gitignore` และจะไม่ถูก Commit):

```bash
# Server
AI_SERVICE_HOST=0.0.0.0
AI_SERVICE_PORT=8000
AI_SERVICE_DEBUG=false

# Authentication
AI_SERVICE_API_KEYS=tcti-dashboard-key,dev-key
AI_SERVICE_REQUIRE_AUTH=true

# CORS (ไม่บังคับ — ค่าเริ่มต้นเป็น wildcard)
# AI_SERVICE_CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# Elasticsearch
ELASTICSEARCH_URL=http://localhost:9200
DATALAKE_INDEX=cyber-logs-datalake
WAREHOUSE_INDEX=cyber-logs-datawarehouse
# DATALAKE_API_KEY=       # ใช้เฉพาะเมื่อเชื่อมต่อ Remote ELK Cluster
# WAREHOUSE_API_KEY=      # ใช้เฉพาะเมื่อเชื่อมต่อ Remote ELK Cluster

# ML Models
DEVICE=cpu                # เปลี่ยนเป็น cuda เพื่อใช้ GPU
# MODEL_EN=               # ค่าเริ่มต้น: DeBERTa-v3-large-mnli-fever-anli-ling-wanli
# MODEL_MULTI=            # ค่าเริ่มต้น: bge-m3-zeroshot-v2.0

# Pipeline tuning
# SCORE_MODEL_VERSION=scoring-v2.0.0

# Startup
# AI_SERVICE_SKIP_STARTUP_PRELOAD=true   # ข้ามการ Preload โมเดลตอน Startup
# AI_SERVICE_AUTO_CREATE_INDEXES=true     # สร้าง ES Index อัตโนมัติ
```

### อ้างอิงตัวแปรแวดล้อมทั้งหมด

| ตัวแปร | จำเป็น | ค่าเริ่มต้น | คำอธิบาย |
|----------|----------|---------|---------| 
| `AI_SERVICE_HOST` | ไม่ | `0.0.0.0` | IP Address สำหรับ Bind |
| `AI_SERVICE_PORT` | ไม่ | `8000` | Port สำหรับ Bind |
| `AI_SERVICE_DEBUG` | ไม่ | `false` | Debug mode (เพิ่ม Log และ Auto-reload) |
| `AI_SERVICE_API_KEYS` | **จำเป็น** | `""` | API Key สำหรับ Authentication (คั่นด้วย comma หากมีหลายค่า) |
| `AI_SERVICE_REQUIRE_AUTH` | ไม่ | `true` | เปิด/ปิดการตรวจสอบ API Key (ห้ามปิดบน Production) |
| `AI_SERVICE_CORS_ORIGINS` | ไม่ | `*` | รายการ Origin ที่อนุญาต |
| `ELASTICSEARCH_URL` | ไม่ | `http://localhost:9200` | URL ของ Elasticsearch |
| `DATALAKE_INDEX` | ไม่ | `cyber-logs-datalake` | Index สำหรับ Data Lake |
| `WAREHOUSE_INDEX` | ไม่ | `cyber-logs-datawarehouse` | Index สำหรับ Data Warehouse |
| `DATALAKE_API_KEY` | ไม่ | `""` | API Key สำหรับ Data Lake Index (Remote ELK) |
| `WAREHOUSE_API_KEY` | ไม่ | `""` | API Key สำหรับ Data Warehouse Index (Remote ELK) |
| `DEVICE` | ไม่ | `cpu` | Device สำหรับประมวลผล AI: `cpu` หรือ `cuda` |
| `MODEL_EN` | ไม่ | DeBERTa-v3-large | โมเดล Zero-shot สำหรับภาษาอังกฤษ |
| `MODEL_MULTI` | ไม่ | BGE-M3 | โมเดล Zero-shot สำหรับหลายภาษา |
| `AI_SERVICE_SKIP_STARTUP_PRELOAD` | ไม่ | `""` | ข้ามการ Preload โมเดลตอน Startup เพื่อลดเวลาบูต |
| `AI_SERVICE_AUTO_CREATE_INDEXES` | ไม่ | `""` | สร้าง ES Index อัตโนมัติหากยังไม่มี |
| `SCORE_MODEL_VERSION` | ไม่ | `scoring-v2.0.0` | Version tag ของ Scoring Model |

*(หมายเหตุ: การตั้งค่า Action Threshold ถูกถอดออกจากระบบเนื่องจากการเปลี่ยนแปลงสถาปัตยกรรม)*

### 3. รัน Elasticsearch (Local)

```bash
docker-compose up -d elasticsearch 
# ตรวจสอบสถานะ
docker-compose logs -f elasticsearch
```
*(หมายเหตุ: Local setup มีเฉพาะ Elasticsearch เท่านั้น ไม่รวม Kibana เพื่อลดการใช้ทรัพยากร)*

### 4. รัน AI Service

```bash
cd ai-service
source venv/bin/activate
python main.py
# เปิดเบราว์เซอร์ที่: http://localhost:8000/docs เพื่อดู API Documentation
```

## Development Workflow

### รัน Test Suite

```bash
cd ai-service
./venv/bin/python -m pytest tests/ -v           # รัน Test ทั้งหมด
./venv/bin/python -m pytest tests/ --cov        # รัน Test พร้อมรายงาน Code Coverage
./venv/bin/python -m pytest tests/test_scorer.py # รัน Test เฉพาะไฟล์
```

### Development Scripts

| Script | คำอธิบาย | วิธีใช้ |
|--------|---------|-------| 
| `scripts/dev/verify_models.py` | ตรวจสอบว่าโหลด NLP Model ครบ | `python scripts/dev/verify_models.py` |
| `scripts/dev/simulate_attack.py` | สร้างข้อมูลจำลองเหตุการณ์ภัยคุกคาม | `python scripts/dev/simulate_attack.py` |
| `scripts/dev/seed_dashboard_fixture.py` | นำเข้า Mock Data สำหรับทดสอบ Dashboard (UAT) | `python scripts/dev/seed_dashboard_fixture.py` |
| `scripts/dev/smoke_dashboard_contract.py` | ตรวจสอบ API Contract | `python scripts/dev/smoke_dashboard_contract.py` |
| `scripts/dev/smoke_dashboard_live.py` | ทดสอบการเชื่อมต่อกับฐานข้อมูลจริง | `python scripts/dev/smoke_dashboard_live.py` |

### Ops Scripts

| Script | คำอธิบาย | วิธีใช้ |
|--------|---------|-------| 
| `scripts/ops/import_to_datalake.py` | นำเข้าข้อมูลดิบลง Data Lake | `python scripts/ops/import_to_datalake.py` |
| `scripts/ops/import_enrich.py` | นำเข้าข้อมูลและรัน AI Enrichment ทันที | `python scripts/ops/import_enrich.py` |
| `scripts/ops/rebuild_warehouse.py` | สร้าง Data Warehouse ใหม่จาก Data Lake | `python scripts/ops/rebuild_warehouse.py --limit 100` |

## Dependencies

| Package | Version ขั้นต่ำ | คำอธิบาย |
|---------|---------|---------| 
| fastapi | >= 0.109.0 | Web API Framework |
| uvicorn | >= 0.27.0 | ASGI Server |
| transformers | >= 4.37.0 | NLP Model สำหรับ Classification และ Translation |
| torch | >= 2.9.0 | Deep Learning Engine สำหรับ AI |
| sentencepiece | >= 0.1.99 | Tokenizer สำหรับโมเดลภาษา |
| lingua-language-detector | >= 2.0.0 | Language Detection |
| scikit-learn | >= 1.3.0 | HDBSCAN Clustering Algorithm |
| python-dotenv | >= 1.0.0 | โหลด Environment Variables จาก `.env` |
| httpx | >= 0.26.0 | HTTP Client |
| pydantic | >= 2.0.0 | Data Validation และ Schema |
| elasticsearch | >= 8.0.0 | Elasticsearch Client |

## Project Structure

```text
ai-service/
├── main.py                    # FastAPI Application Entry Point
├── config.py                  # Configuration, Scoring Weights และ Model Parameters
├── elastic_client.py          # Elasticsearch Dual-Index Client
├── models/
│   ├── classifier.py          # NLP Zero-Shot Classification (DeBERTa/BGE-M3)
│   ├── scorer.py              # Multi-factor Risk Scoring (8 factors)
│   ├── validation.py          # Validation Gate (validated / rejected)
│   ├── sector_classifier.py   # Target Sector Detection
│   ├── campaign_clusterer.py  # HDBSCAN Campaign Clustering
│   ├── forecaster.py          # Holt-Winters Trend Forecasting
│   └── relationship_graph.py  # Attack Relationship Graph Builder
├── services/
│   ├── dashboard_router.py    # /api/v1 Dashboard API Router
│   ├── dashboard_compat_router.py # Legacy Route Compatibility Layer
│   └── dashboard_bootstrap.py # In-process User Store และ Login
├── utils/
│   ├── pipeline_documents.py  # Pipeline Orchestration (Enrichment Core)
│   ├── sanitizer.py           # PII Sanitization และ Data Cleaning
│   └── translator.py          # Offline EN→TH Translation
├── scripts/
│   ├── dev/                   # Development และ Testing Scripts
│   └── ops/                   # Operational Scripts
├── tests/                     # Pytest Test Suite
├── test_support/              # Test Fixtures และ Helpers
├── config/threat_actors.json  # Threat Actors Configuration
├── requirements.txt           # Python Dependencies
└── Dockerfile                 # Container Build Definition
```

## Commit Convention

```text
<type>: <short description>

ประเภทที่ใช้:
  feat     — Feature ใหม่
  fix      — แก้ไข Bug
  refactor — ปรับโครงสร้างโค้ด (ไม่มีการเปลี่ยนพฤติกรรม)
  docs     — อัปเดตเอกสาร
  test     — เพิ่มหรือแก้ไข Test
  chore    — งาน Maintenance ทั่วไป
  perf     — ปรับปรุงประสิทธิภาพ
  ci       — แก้ไข CI/CD Pipeline
```

## Code Quality Checklist

- [ ] ทุกฟังก์ชั่นผ่าน `pytest tests/` สำเร็จ
- [ ] ฟังก์ชั่นที่ซับซ้อนเกินจำเป็นต้องถูก Refactor
- [ ] ไม่มี Credentials หรือ API Key ปรากฏใน Source Code
- [ ] หลีกเลี่ยง Mutation ในตัวแปรที่ไม่จำเป็นต้องเปลี่ยนค่า
- [ ] มีการจัดการ Exception เพื่อป้องกัน Unhandled Error
