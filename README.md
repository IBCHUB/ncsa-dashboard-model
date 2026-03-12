# แพลตฟอร์ม Thailand Cyber Threat Intelligence (TCTI)

รีโปนี้เป็นชุดงานหลักของระบบ `AI / ML` และ `Threat Data Warehouse` สำหรับโครงการ TCTI โดยรับข้อมูลดิบจาก `Threat Data Lake` ที่มาจากระบบภายนอก แล้วประมวลผลผ่าน AI Service ก่อนบันทึกลง `Processed Index` และ `Threat Data Warehouse`

ระบบ `Dashboard` และ `Threat Search` ที่ใช้งานจริงไม่ได้อยู่ในรีโปนี้ โดยในรีโปจะเก็บเพียง PoC เดิมไว้ที่ [legacy/dashboard-poc](legacy/dashboard-poc)

## ภาพรวม

องค์ประกอบหลักของรีโปนี้มีดังนี้

| องค์ประกอบ | เทคโนโลยี | หน้าที่ |
|------------|-----------|---------|
| `ai-service` | FastAPI + Python | จัดหมวดหมู่ภัยคุกคาม, คำนวณคะแนนความเสี่ยง, ตรวจสอบความถูกต้อง, และเปิด API |
| `Elasticsearch` | Elasticsearch 8.x | เก็บ `Data Lake`, `Processed`, และ `Data Warehouse` |
| `Kibana` | Kibana | ใช้ตรวจสอบข้อมูลและ debug |
| `legacy/dashboard-poc` | Next.js | PoC เดิมที่ถูก archive แล้ว |

ความสามารถหลักในปัจจุบัน

- วิเคราะห์ IOC เช่น IP, domain, URL, hash
- จัดหมวดหมู่ภัยคุกคามด้วย zero-shot models
- คำนวณคะแนนความเสี่ยงจากหลายปัจจัย
- sanitize ข้อมูลก่อนเข้า AI / Warehouse
- แยกผลลัพธ์เป็น `validated_auto`, `needs_review`, `rejected`
- เปิด review queue ภายในสำหรับอนุมัติหรือปฏิเสธรายการที่ไม่ควรเข้า warehouse อัตโนมัติ
- เตรียม API สำหรับ external consumers เช่น dashboard หรือ threat search

## สถาปัตยกรรม

```text
External Threat Data Lake
          |
          v
  Elasticsearch Data Lake
          |
          v
      AI Service
  - sanitize content
  - classify threat
  - score risk
  - validate / review gate
          |
          +--> Processed Index
          |
          +--> Data Warehouse
                    |
                    v
     External Dashboard / Threat Search
```

ลำดับการไหลของข้อมูล

1. ระบบภายนอกส่งข้อมูลดิบเข้ามาที่ `Data Lake`
2. `ai-service` อ่านเอกสารที่ยังไม่ถูกประมวลผล
3. ระบบ sanitize ข้อมูล, รวม observation ของ IOC เดียวกัน, แล้วรัน AI/ML
4. ผลลัพธ์ทุกตัวจะถูกบันทึกลง `Processed Index`
5. เฉพาะรายการที่ `validated_auto` หรือ `validated_manual` เท่านั้นที่จะถูกบันทึกลง `Threat Data Warehouse`
6. ระบบภายนอกจะเรียก API หรืออ่านข้อมูลต่อจาก warehouse

## โครงสร้างรีโป

```text
Cyber/
├── ai-service/               # โค้ด runtime หลักของระบบ AI Service
│   ├── main.py               # FastAPI application
│   ├── config.py             # ค่ากำหนดโมเดลและ auth
│   ├── elastic_client.py     # Elasticsearch access layer
│   ├── integrations/         # HelpDesk integration
│   ├── models/               # classifier, scorer, validation
│   ├── services/             # service layer เช่น review queue
│   ├── utils/                # sanitizer และ pipeline helpers
│   ├── scripts/ops/          # import, backfill, operational scripts
│   ├── scripts/dev/          # local verification scripts
│   ├── legacy/               # โค้ดเก่าที่ quarantine ไว้
│   └── tests/                # unit tests
├── docs/                     # เอกสารคู่มือและเอกสารอ้างอิง
├── legacy/dashboard-poc/     # Dashboard PoC เดิม
├── data_lake/                # ตัวอย่างไฟล์ JSON สำหรับ import/local test
├── docker-compose.yml        # local stack
└── docker-compose.remote.yml # remote ELK stack
```

## เริ่มต้นใช้งานเร็ว

### แบบ Docker

```bash
cd /path/to/Cyber
docker-compose up -d
```

บริการหลักที่ได้

- `AI Service` ที่ `http://localhost:8000`
- `Elasticsearch` ที่ `http://localhost:9200`
- `Kibana` ที่ `http://localhost:5601`

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
| `AI_SERVICE_HOST` | `0.0.0.0` | host ของ FastAPI |
| `AI_SERVICE_PORT` | `8000` | port ของ FastAPI |
| `AI_SERVICE_API_KEYS` | ว่าง | รายการ API key ที่อนุญาต |
| `AI_SERVICE_REQUIRE_AUTH` | `true` | บังคับตรวจ `X-API-Key` หรือไม่ |
| `ELASTICSEARCH_URL` | ในโค้ดชี้ remote ELK | URL ของ Elasticsearch |
| `DATALAKE_INDEX` | `cyber-logs-datalake` | index ข้อมูลดิบ |
| `PROCESSED_INDEX` | `cyber-logs-processed` | index ระหว่างทางหลัง AI |
| `WAREHOUSE_INDEX` | `cyber-logs-datawarehouse` | index ผลลัพธ์สำหรับใช้งานต่อ |
| `DATALAKE_API_KEY` | ว่าง | API key สำหรับอ่าน/เขียน datalake |
| `WAREHOUSE_API_KEY` | ว่าง | API key สำหรับ processed/warehouse |
| `OPENAI_API_KEY` | ว่าง | ใช้กับ endpoint แปลภาษา |
| `HELPDESK_MOCK_MODE` | `true` | ใช้ mock helpdesk หรือยิง API จริง |

หมายเหตุเรื่อง environment

- `docker-compose.yml` สำหรับ local dev ตั้งค่าดัชนี local ของตัวเอง
- โค้ด runtime มีค่าเริ่มต้นชี้ไป canonical remote indices ดังนั้น production ควรตั้ง env ให้ชัดเจนทุกครั้ง

## สรุป API ที่มีในปัจจุบัน

| Method | Path | หน้าที่ |
|--------|------|---------|
| `GET` | `/health` | ตรวจสถานะบริการ |
| `POST` | `/classify` | จัดหมวดหมู่ภัยคุกคามจากข้อความ |
| `POST` | `/score` | คำนวณคะแนนความเสี่ยง |
| `POST` | `/enrich` | classify + score สำหรับ IOC เดียว |
| `POST` | `/enrich/batch` | enrich หลาย IOC ในครั้งเดียว |
| `POST` | `/translate` | แปลข้อความเชิงภัยคุกคาม |
| `POST` | `/helpdesk/ticket` | สร้าง ticket ไป HelpDesk |
| `POST` | `/pipeline/run` | รัน pipeline จาก datalake ไป processed/warehouse |
| `GET` | `/pipeline/review-queue` | ดูรายการที่ต้อง review |
| `POST` | `/pipeline/review/{doc_id}/approve` | อนุมัติรายการเข้า warehouse |
| `POST` | `/pipeline/review/{doc_id}/reject` | ปฏิเสธรายการ |
| `GET` | `/pipeline/status` | ดูสถานะดัชนีและจำนวนเอกสาร |
| `POST` | `/elasticsearch/setup` | สร้าง index ตาม mapping ที่รองรับ |

## เอกสารที่ควรอ่านต่อ

- [ดัชนีเอกสารใน docs](docs/README.md)
- [คู่มือภาพรวมระบบ](docs/SYSTEM_GUIDE_TH.md)
- [คู่มือ AI Service, API และการปฏิบัติงาน](docs/AI_SERVICE_OPERATIONS_TH.md)
- [TOR AI/Warehouse Gap Checklist](docs/TOR_AI_WAREHOUSE_GAP_CHECKLIST.md)
- [TOR_สกมช.pdf](docs/TOR_สกมช.pdf)

## สถานะของ Dashboard

รีโปนี้ไม่มี dashboard runtime ที่ใช้งานจริงแล้ว

- UI ที่ใช้งานจริงจะถูกนำมารวมภายหลังจากอีกโครงการ
- dashboard เดิมในรีโปนี้ถูกย้ายไปไว้ที่ `legacy/dashboard-poc`
- การออกแบบ API สำหรับ dashboard/threat search ภายนอกจะนิยามเพิ่มเมื่อมี spec อย่างเป็นทางการ
