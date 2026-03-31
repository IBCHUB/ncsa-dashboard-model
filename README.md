# แพลตฟอร์ม Thailand Cyber Threat Intelligence (TCTI)

> อัพเดทล่าสุด: 2026-03-27

รีโปนี้เป็นชุดงานหลักของระบบ `AI / ML` และ `Threat Data Warehouse` สำหรับโครงการ TCTI โดยรับข้อมูลดิบจาก `Threat Data Lake` ที่มาจากระบบภายนอก แล้วประมวลผลผ่าน AI Service ก่อนบันทึกลง `Threat Data Warehouse`

## ภาพรวม

องค์ประกอบหลักของรีโปนี้มีดังนี้

| องค์ประกอบ | เทคโนโลยี | หน้าที่ |
|------------|-----------|---------|
| `ai-service` | FastAPI + Python 3.11 | จัดหมวดหมู่ภัยคุกคาม, คำนวณคะแนนความเสี่ยง, ตรวจสอบความถูกต้อง, clustering, forecasting, และเปิด API |
| `Elasticsearch` | Elasticsearch 8.12 | เก็บ `Data Lake` และ `Data Warehouse` |

ความสามารถหลักในปัจจุบัน

- วิเคราะห์ IOC เช่น IP, domain, URL, hash, CVE
- จัดหมวดหมู่ภัยคุกคามด้วย hybrid zero-shot models (DeBERTa + BGE-M3)
- คำนวณคะแนนความเสี่ยงจากหลายปัจจัย (8 weighted factors + sector multiplier)
- sanitize ข้อมูลก่อนเข้า AI / Warehouse
- แยกผลลัพธ์เป็น `validated` และ `rejected` โดย news source ผ่านได้ถ้า AI confidence ≥ 0.60
- จัดกลุ่ม IOC เป็น campaign ด้วย HDBSCAN clustering
- สร้าง attack relationship graph (actors, IOCs, malware, CVEs, infrastructure)
- พยากรณ์แนวโน้มการโจมตีด้วย Holt-Winters forecasting
- เตรียม Dashboard API สำหรับ executive/operations/IOC analytics
- แปลข้อความภัยคุกคามด้วย Hugging Face (opus-mt-en-th)

## สถาปัตยกรรม

```text
External Threat Data Lake
          |
          v
  Elasticsearch Data Lake
          |
          v
      AI Service
  1. sanitize content
  2. aggregate observations
  3. classify context (threat, sector, actor, mitre)
  4. score risk (multi-factor)
  5. validation gate
          |
          v
    Data Warehouse
          |
          v
  rebuild_warehouse.py
  6. cluster campaigns (HDBSCAN)
  7. build relationship graph
  8. forecast trends (Holt-Winters)
          |
          v
  Dashboard API (/api/v1) + External Consumers
```

ลำดับการไหลของข้อมูล

1. ระบบภายนอกส่งข้อมูลดิบเข้ามาที่ `Data Lake`
2. `ai-service` อ่านเอกสารที่ยังไม่ถูกประมวลผล
3. ท่อประมวลผล **AI Service** จะทำงาน 5 ขั้นตอนอัตโนมัติ:
   - `Sanitize` (ลบข้อมูลส่วนตัว/ข้อมูลความลับ)
   - `Aggregate` (มัดรวมเบาะแสจากหลายแหล่ง)
   - `Classify Context` (จัดหมวดหมู่ภัยคุกคาม, อุตสาหกรรมเป้าหมาย, กลุ่มแฮ็กเกอร์, และเทคนิค MITRE)
   - `Score Risk` (ให้คะแนนความเสี่ยงเพื่อจัดลำดับ)
   - `Validate` (คัดกรองทิ้งข้อมูลที่ไม่ได้มาตรฐาน)
4. ผลลัพธ์บันทึกลง `Threat Data Warehouse` พร้อม metadata ของ validation
5. `rebuild_warehouse.py` รันการวิเคราะห์ขั้นสูงหลัง warehouse พร้อมแล้ว:
   - `Cluster Campaigns` (จัดกลุ่มพฤติกรรมเป็นแคมเปญด้วย HDBSCAN)
   - `Build Graph` (สร้างแผนผังความสัมพันธ์หาต้นตอ)
   - `Forecast Trends` (พยากรณ์แนวโน้มด้วย Holt-Winters)
6. Dashboard API อ่านจาก warehouse เพื่อแสดงผล executive/operations/IOC analytics

## โครงสร้างรีโป

```text
Cyber/
├── ai-service/               # โค้ด runtime หลักของระบบ AI Service
│   ├── main.py               # FastAPI application + core AI endpoints
│   ├── config.py             # ค่ากำหนดโมเดล, scoring weights, sectors, actors
│   ├── elastic_client.py     # Elasticsearch dual-index client
│   ├── models/
│   │   ├── classifier.py     # NLP zero-shot classification
│   │   ├── scorer.py         # Multi-factor risk scoring
│   │   ├── validation.py     # Validation policy (validated / rejected)
│   │   ├── sector_classifier.py  # Target sector detection
│   │   ├── campaign_clusterer.py # HDBSCAN campaign clustering
│   │   ├── forecaster.py     # Holt-Winters trend forecasting
│   │   └── relationship_graph.py # Attack relationship graph builder
│   ├── services/
│   │   ├── dashboard_router.py       # /api/v1 dashboard
│   │   ├── dashboard_compat_router.py # Legacy route compatibility
│   │   └── dashboard_bootstrap.py    # In-process admin/user store
│   ├── utils/                # sanitizer, pipeline builder, translator
│   ├── scripts/ops/          # import, backfill, rebuild
│   ├── scripts/dev/          # verification, seeding, smoke tests
│   └── tests/                # pytest test suite
├── docs/                     # เอกสารคู่มือและเอกสารอ้างอิง
├── data_lake/                # ตัวอย่างไฟล์ JSON สำหรับ import
├── docker-compose.yml        # local stack (ES + AI Service)
└── docker-compose.remote.yml # remote ELK stack (AI Service only)
```

## เริ่มต้นใช้งานเร็ว

### แบบ Docker

```bash
cd /path/to/Cyber
docker-compose up -d
```

บริการหลักที่ได้

- `AI Service` ที่ `http://localhost:8000` (API docs: `http://localhost:8000/docs`)
- `Elasticsearch` ที่ `http://localhost:9200`

### แบบ local development

```bash
cd ai-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

หมายเหตุ

- startup ครั้งแรกอาจใช้เวลานานเพราะต้องโหลดโมเดลจาก Hugging Face
- ถ้าใช้ remote ELK ให้ตั้งค่า `ELASTICSEARCH_URL`, `DATALAKE_API_KEY`, `WAREHOUSE_API_KEY` ให้ถูกต้องก่อนเริ่มระบบ

## ตัวแปรแวดล้อมสำคัญ

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|--------|-------------|-----------|
| `AI_SERVICE_API_KEYS` | ว่าง (ต้องตั้ง) | รายการ API key ที่อนุญาต (comma-separated) |
| `AI_SERVICE_REQUIRE_AUTH` | `true` | บังคับตรวจ `X-API-Key` หรือไม่ |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | URL ของ Elasticsearch |
| `DATALAKE_INDEX` | `cyber-logs-datalake` | index ข้อมูลดิบ |
| `WAREHOUSE_INDEX` | `cyber-logs-datawarehouse` | index ผลลัพธ์สำหรับใช้งานต่อ |
| `DATALAKE_API_KEY` | ว่าง | API key สำหรับอ่าน/เขียน datalake (remote ELK) |
| `WAREHOUSE_API_KEY` | ว่าง | API key สำหรับ warehouse (remote ELK) |
| `DEVICE` | `cpu` | `cpu` หรือ `cuda` |

ดูตัวแปรแวดล้อมทั้งหมดใน [docs/CONTRIB.md](docs/CONTRIB.md)

## เอกสารที่ควรอ่านต่อ

| ลำดับ | ไฟล์ | เนื้อหา |
|-------|------|---------|
| 1 | [docs/CODEMAPS/architecture.md](docs/CODEMAPS/architecture.md) | Module dependency graph, design decisions |
| 2 | [docs/CONTRIB.md](docs/CONTRIB.md) | วิธี setup, env vars, scripts, project structure |
| 3 | [docs/CODEMAPS/backend.md](docs/CODEMAPS/backend.md) | API endpoints ทั้งหมด, models/services layer |
| 4 | [docs/CODEMAPS/data.md](docs/CODEMAPS/data.md) | ES schema, scoring config, graph schema |
| 5 | [docs/RUNBOOK.md](docs/RUNBOOK.md) | Deploy, monitoring, troubleshooting, rollback |
