# คู่มือ AI Service

`ai-service` คือ service หลักของระบบสำหรับงาน `AI / ML`, `Threat Scoring`, `Validation`, และ `Threat Data Warehouse Pipeline`

## หน้าที่ของ service นี้

- จัดหมวดหมู่ภัยคุกคามจากข้อความ (`classify`)
- คำนวณคะแนนความเสี่ยง (`score`)
- รวมผลลัพธ์เป็นเอกสาร enrich (`enrich`, `enrich/batch`)
- แปลข้อความด้วย OpenAI (`translate`)
- รัน pipeline จาก `Data Lake` ไป `Warehouse`
- จัดการ review queue สำหรับรายการที่ไม่ควรเข้า warehouse อัตโนมัติ
- เชื่อมต่อ HelpDesk แบบ mock หรือ API จริง

## คุณสมบัติหลัก

- Hybrid zero-shot classification รองรับภาษาอังกฤษและหลายภาษา
- Risk scoring ตามน้ำหนักจาก source quality, cross-source, threat type, threat actor, keyword, entropy, MITRE, domain age
- Sanitization ก่อนเข้า AI และก่อน persist ลง Elasticsearch
- Validation policy แยก `validated_auto`, `validated_manual`, `needs_review`, `rejected`
- Elasticsearch client รองรับการใช้ API key แยกตาม index

## เริ่มต้นใช้งาน

### Local development

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Docker

```bash
docker build -t tcti-ai-service .
docker run -p 8000:8000 tcti-ai-service
```

หรือจาก root repo

```bash
docker-compose up ai-service
```

## ตัวแปรแวดล้อมที่ใช้บ่อย

| ตัวแปร | ค่าเริ่มต้น | ความหมาย |
|--------|-------------|-----------|
| `AI_SERVICE_HOST` | `0.0.0.0` | host ของ service |
| `AI_SERVICE_PORT` | `8000` | port ของ service |
| `AI_SERVICE_DEBUG` | `false` | เปิด log/debug mode |
| `AI_SERVICE_API_KEYS` | ว่าง | รายการ API key ที่อนุญาต |
| `AI_SERVICE_REQUIRE_AUTH` | `true` | บังคับ auth หรือไม่ |
| `AI_SERVICE_CORS_ORIGINS` | `http://localhost:3000,http://localhost:3001` | รายการ origin ที่อนุญาต |
| `AI_SERVICE_AUTO_CREATE_INDEXES` | ว่าง | ถ้า `true` จะพยายาม create index ตอน startup |
| `MODEL_EN` | `MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli` | โมเดลภาษาอังกฤษ |
| `MODEL_MULTI` | `MoritzLaurer/bge-m3-zeroshot-v2.0` | โมเดล multilingual |
| `DEVICE` | `cpu` | `cpu` หรือ `cuda` |
| `ELASTICSEARCH_URL` | ดูที่ `elastic_client.py` | URL ของ Elasticsearch |
| `DATALAKE_INDEX` | `cyber-logs-datalake` | Data Lake index |
| `WAREHOUSE_INDEX` | `cyber-logs-datawarehouse` | Warehouse index |
| `DATALAKE_API_KEY` | ว่าง | API key ฝั่ง datalake |
| `WAREHOUSE_API_KEY` | ว่าง | API key ฝั่ง warehouse |
| `OPENAI_API_KEY` | ว่าง | ใช้สำหรับ translation |
| `HELPDESK_API_URL` | `https://helpdesk.thcert.go.th/api` | URL ของ HelpDesk |
| `HELPDESK_API_KEY` | ว่าง | token ฝั่ง HelpDesk |
| `HELPDESK_MOCK_MODE` | `true` | ใช้ mock mode หรือไม่ |

## สรุป API

ทุก endpoint ที่ป้องกันไว้ต้องส่ง header

```bash
X-API-Key: <your-api-key>
```

รายการ endpoint หลัก

| Method | Path | คำอธิบาย |
|--------|------|----------|
| `GET` | `/health` | ตรวจสถานะ service |
| `POST` | `/classify` | วิเคราะห์ประเภทภัยคุกคามจากข้อความ |
| `POST` | `/score` | คำนวณความเสี่ยงของ IOC |
| `POST` | `/enrich` | classifiy + score พร้อม metadata |
| `POST` | `/enrich/batch` | enrich หลายรายการพร้อมกัน |
| `POST` | `/translate` | แปลข้อความด้วย OpenAI |
| `POST` | `/helpdesk/ticket` | เปิด ticket ไป HelpDesk |
| `POST` | `/pipeline/run` | อ่าน datalake แล้วประมวลผล |
| `GET` | `/pipeline/review-queue` | ดูรายการรอ review |
| `POST` | `/pipeline/review/{doc_id}/approve` | อนุมัติรายการ |
| `POST` | `/pipeline/review/{doc_id}/reject` | ปฏิเสธรายการ |
| `GET` | `/pipeline/status` | ดูจำนวนเอกสารในแต่ละ index |
| `POST` | `/elasticsearch/setup` | สร้าง mapping ของ index |

ตัวอย่าง enrich

```bash
curl -X POST http://localhost:8000/enrich \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{
    "ioc_value": "malicious.domain.com",
    "ioc_type": "domain",
    "title": "Phishing Campaign",
    "description": "Lazarus Group phishing campaign targeting banks",
    "sources": ["VirusTotal", "BleepingComputer"],
    "country_code": "KP"
  }'
```

ตัวอย่างเรียก pipeline

```bash
curl -X POST http://localhost:8000/pipeline/run \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{"limit": 100}'
```

ตัวอย่างอนุมัติรายการใน review queue

```bash
curl -X POST http://localhost:8000/pipeline/review/<doc_id>/approve \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{"reviewer":"analyst-01","notes":"validated by analyst"}'
```

## Validation workflow

ผลจาก pipeline จะถูกจัดสถานะดังนี้

- `validated_auto` หมายถึงผ่านเกณฑ์และสามารถบันทึกเข้า warehouse ได้ทันที
- `validated_manual` หมายถึงผ่านการอนุมัติจากผู้ตรวจ
- `needs_review` หมายถึงต้องเข้า review queue
- `rejected` หรือ `rejected_manual` หมายถึงไม่ควรเข้า warehouse

รายการทุกตัวจะถูกบันทึกลง `Warehouse` พร้อม review metadata เสมอ โดยใช้ฟิลด์ `validation_status`, `review_required`, `review_state` และ `warehouse_eligible` เพื่อแยกผลลัพธ์ที่พร้อมใช้งานออกจากรายการที่รอ review หรือถูก reject

หมายเหตุ:
- `validation_*` เป็น workflow ภายในของ AI/warehouse เพื่อให้ตรง TOR
- dashboard API ภายนอก โดยเฉพาะ `Action Center` ใช้ `action_status = open / in_progress / closed` และ `action_required` เป็นหลัก ไม่ expose คำว่า `validated_*` เป็น contract หลัก

## Script layout

- `scripts/ops/` สำหรับ import, backfill, และงานปฏิบัติการจริง
- `scripts/dev/` สำหรับ local verification

ตัวอย่างคำสั่งที่ใช้จริง

```bash
python scripts/ops/import_to_datalake.py --dry-run
python scripts/ops/rebuild_warehouse.py --limit 100
python scripts/ops/rebuild_warehouse.py --date-from 2026-02-04T00:00:00+07:00 --date-to 2026-02-05T23:59:59+07:00 --summary-file ../docs/api-spec/backfill-dry-run.json
python scripts/ops/rebuild_warehouse.py --write --date-from 2026-02-04T00:00:00+07:00 --date-to 2026-02-05T23:59:59+07:00
```

หมายเหตุ: ถ้า dry-run พบว่า `validated_auto = 0` สคริปต์จะ block การเขียนจริงไว้ก่อน เว้นแต่ใส่ `--allow-zero-eligible-write`

## เอกสารที่เกี่ยวข้อง

- [ดัชนีเอกสาร](../docs/README.md)
- [คู่มือภาพรวมระบบ](../docs/SYSTEM_GUIDE_TH.md)
- [คู่มือ AI Service และการปฏิบัติงาน](../docs/AI_SERVICE_OPERATIONS_TH.md)
- [TOR AI/Warehouse Gap Checklist](../docs/TOR_AI_WAREHOUSE_GAP_CHECKLIST.md)

## ข้อควรรู้

- startup ครั้งแรกจะ pre-load classifier และอาจใช้เวลาหลายนาที
- translation endpoint จะคืนข้อความเดิมหากไม่ได้ตั้ง `OPENAI_API_KEY`
- HelpDesk integration ทำงานแบบ mock เป็นค่าเริ่มต้น
- external dashboard/threat search ไม่ได้อยู่ใน active code path ของรีโปนี้
