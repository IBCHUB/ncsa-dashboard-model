# 📂 ไฟล์สำคัญทั้งหมด - Reference Guide

คู่มืออ้างอิงไฟล์สำคัญทุกไฟล์ในโปรเจค พร้อมคำอธิบายว่าทำหน้าที่อะไร

---

## 🐍 AI Service (Python)

### ไฟล์หลัก

| ไฟล์ | หน้าที่ | Import สำคัญ |
|------|--------|-------------|
| `main.py` | FastAPI Application หลัก | FastAPI, Pydantic |
| `config.py` | ค่าตั้งต่างๆ (API key, host, port) | os, dotenv |
| `elastic_client.py` | ติดต่อ Elasticsearch | elasticsearch, httpx |

### โฟลเดอร์ `models/`

| ไฟล์ | หน้าที่ | AI/ML ที่ใช้ |
|------|--------|-------------|
| `classifier.py` | จำแนกประเภทภัยคุกคาม | BART-Large (Zero-shot) |
| `scorer.py` | คำนวณ Risk Score | Rule-based + Weighted factors |
| `trend_predictor.py` | พยากรณ์แนวโน้มภัยคุกคาม | Facebook Prophet |

### โฟลเดอร์ `utils/`

| ไฟล์ | หน้าที่ | External API |
|------|--------|-------------|
| `translator.py` | แปลภาษา | OpenAI GPT-4o-mini |

### โฟลเดอร์ `scripts/`

| ไฟล์ | หน้าที่ | เรียกใช้เมื่อไหร่ |
|------|--------|-----------------|
| `import_to_datalake.py` | นำเข้าข้อมูลจาก JSON → Elasticsearch | ครั้งแรกหลัง setup |
| `ingest.py` | Process ข้อมูลจาก source ต่างๆ | เมื่อมี data ใหม่ |

### โฟลเดอร์ `integrations/`

| ไฟล์ | หน้าที่ | สถานะ |
|------|--------|--------|
| `helpdesk.py` | สร้าง Ticket ใน HelpDesk | Mock (รอ endpoint จริง) |

---

## ⚛️ Dashboard (Next.js/TypeScript)

### ไฟล์หลัก

| ไฟล์ | หน้าที่ |
|------|--------|
| `src/app/layout.tsx` | Layout หลัก (Header) |
| `src/app/page.tsx` | หน้าแรก Dashboard |
| `src/app/globals.css` | CSS รวมทั้งหมด |

### โฟลเดอร์ `src/app/` (Pages)

| Path | ไฟล์ | หน้าที่ |
|------|------|--------|
| `/` | `page.tsx` | Dashboard หลัก |
| `/ioc` | `page.tsx` | IOC Explorer (ค้นหา/กรอง) |
| `/ioc/[type]/[value]` | `page.tsx` | IOC Detail |
| `/map` | `page.tsx` | Threat Map |
| `/graph` | `page.tsx` | Threat Graph |
| `/reports` | `page.tsx` | Reports & Export |
| `/alerts` | `page.tsx` | Alerts Center |
| `/news` | `page.tsx` | Cyber News |

### โฟลเดอร์ `src/app/api/` (API Routes)

| Path | ไฟล์ | หน้าที่ |
|------|------|--------|
| `/api/iocs` | `route.ts` | ดึงข้อมูล IOC จาก Elasticsearch |
| `/api/stats` | `route.ts` | Statistics (จำนวน, ร้อยละ) |
| `/api/analyze` | `route.ts` | วิเคราะห์ IOC ใหม่ |
| `/api/geo-threats` | `route.ts` | ข้อมูลภูมิศาสตร์ |
| `/api/helpdesk/ticket` | `route.ts` | สร้าง HelpDesk ticket |

### โฟลเดอร์ `src/components/`

| โฟลเดอร์ | หน้าที่ |
|----------|--------|
| `layout/` | Header, Sidebar |
| `widgets/` | Cards, Charts, Maps, Tables |

**Components สำคัญ:**

| Component | หน้าที่ |
|-----------|--------|
| `Header.tsx` | Navigation bar |
| `StatCard.tsx` | การ์ดแสดงสถิติ |
| `SeverityChart.tsx` | กราฟวงกลม severity |
| `ThreatMap.tsx` | แผนที่ภัยคุกคาม |
| `ThreatGraph.tsx` | กราฟความสัมพันธ์ |
| `IOCTable.tsx` | ตาราง IOC |
| `ScoreInfoTooltip.tsx` | Tooltip แสดง score breakdown |

### โฟลเดอร์ `src/lib/`

| โฟลเดอร์/ไฟล์ | หน้าที่ |
|---------------|--------|
| `types/index.ts` | TypeScript types หลัก |
| `types/graph-types.ts` | Types สำหรับ Graph |
| `graph/build-graph-data.ts` | สร้าง Graph data จาก IOC |
| `elastic.ts` | Elasticsearch client |
| `normalize-data.ts` | Normalize IOC data |

---

## 🐳 Docker

| ไฟล์ | หน้าที่ |
|------|--------|
| `docker-compose.yml` | กำหนด services ทั้งหมด |
| `ai-service/Dockerfile` | Build AI Service image |
| `dashboard/Dockerfile` | Build Dashboard image |

---

## 📊 Data Files

| Path | หน้าที่ |
|------|--------|
| `data_lake/*.json` | ข้อมูลดิบจาก sources ต่างๆ |
| `dashboard/public/data/*.json` | ข้อมูล static สำหรับ fallback |

---

## ⚙️ Configuration Files

| ไฟล์ | หน้าที่ |
|------|--------|
| `ai-service/requirements.txt` | Python dependencies |
| `dashboard/package.json` | Node.js dependencies |
| `dashboard/tsconfig.json` | TypeScript config |
| `dashboard/.env.local` | Environment variables |

---

## 🔗 การเชื่อมต่อระหว่างไฟล์

```
                        ┌─────────────────────────────────┐
                        │         User Browser            │
                        └─────────────┬───────────────────┘
                                      │
                        ┌─────────────▼───────────────────┐
                        │   Dashboard (Next.js)           │
                        │   src/app/page.tsx              │
                        └─────────────┬───────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
   ┌──────────▼──────────┐ ┌─────────▼─────────┐ ┌───────────▼──────────┐
   │ src/app/api/iocs    │ │ src/lib/elastic.ts │ │ External: AI Service │
   │ route.ts            │ │                    │ │ http://localhost:8000│
   └──────────┬──────────┘ └─────────┬─────────┘ └───────────┬──────────┘
              │                      │                       │
              │            ┌─────────▼─────────┐            │
              └───────────▶│   Elasticsearch   │◀───────────┘
                           │   localhost:9200  │
                           └───────────────────┘
```

---

## 📝 Environment Variables Reference

### AI Service

| Variable | Default | Use |
|----------|---------|-----|
| `AI_SERVICE_HOST` | `0.0.0.0` | Bind address |
| `AI_SERVICE_PORT` | `8000` | Port |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | ES connection |
| `OPENAI_API_KEY` | - | Translation |
| `REQUIRE_AUTH` | `true` | API Key enforcement |

### Dashboard

| Variable | Default | Use |
|----------|---------|-----|
| `AI_SERVICE_URL` | `http://localhost:8000` | AI Service connection |
| `ELASTICSEARCH_URL` | `http://localhost:9200` | Direct ES connection |
| `OPENAI_API_KEY` | - | (Same as AI Service) |

---

*ใช้เอกสารนี้เป็น reference เมื่อต้องการหาว่าไฟล์ไหนทำหน้าที่อะไร*
