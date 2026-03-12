# คู่มือ AI Service, API และการปฏิบัติงาน

เอกสารนี้ใช้เป็นคู่มือปฏิบัติการสำหรับทีมที่ต้อง run service, ใช้งาน API, import ข้อมูล, รัน pipeline, จัดการ review queue, และ backfill warehouse

## 1. การยืนยันว่า service พร้อมใช้งาน

เรียก health check

```bash
curl -H "X-API-Key: <api-key>" http://localhost:8000/health
```

ตัวอย่างผลลัพธ์

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "classifier_loaded": true
}
```

## 2. การยืนยันตัวตน

endpoint ส่วนใหญ่ต้องส่ง header นี้

```text
X-API-Key: <api-key>
```

ถ้าต้องการปิด auth ชั่วคราวใน local dev ให้ตั้ง

```bash
export AI_SERVICE_REQUIRE_AUTH=false
```

## 3. สรุป API

| Method | Path | ใช้ทำอะไร |
|--------|------|-----------|
| `GET` | `/health` | ตรวจสถานะ service |
| `POST` | `/classify` | รับข้อความและคืน threat types / actors / MITRE |
| `POST` | `/score` | คำนวณ risk score ของ IOC |
| `POST` | `/enrich` | classify + score สำหรับ IOC เดียว |
| `POST` | `/enrich/batch` | enrich หลายรายการในครั้งเดียว |
| `POST` | `/translate` | แปลข้อความที่เกี่ยวกับภัยคุกคาม |
| `POST` | `/helpdesk/ticket` | เปิด ticket ไป HelpDesk |
| `POST` | `/pipeline/run` | รัน pipeline จาก datalake |
| `GET` | `/pipeline/review-queue` | ดูรายการรอ review |
| `POST` | `/pipeline/review/{doc_id}/approve` | อนุมัติเอกสาร |
| `POST` | `/pipeline/review/{doc_id}/reject` | ปฏิเสธเอกสาร |
| `GET` | `/pipeline/status` | ดูสถานะ index |
| `POST` | `/elasticsearch/setup` | สร้าง index ตาม mapping |

## 4. ตัวอย่าง API ที่ใช้บ่อย

### 4.1 classify

```bash
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{
    "text": "Ransomware attack encrypts files and demands Bitcoin",
    "threshold": 0.3
  }'
```

### 4.2 score

```bash
curl -X POST http://localhost:8000/score \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{
    "ioc_value": "malicious.domain.com",
    "ioc_type": "domain",
    "description": "Known phishing domain",
    "sources": ["VirusTotal", "AbuseIPDB"]
  }'
```

### 4.3 enrich

```bash
curl -X POST http://localhost:8000/enrich \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{
    "ioc_value": "192.168.1.10",
    "ioc_type": "ip",
    "description": "Suspicious C2 communication detected",
    "sources": ["CERT-TH", "OpenCTI"]
  }'
```

### 4.4 translate

```bash
curl -X POST http://localhost:8000/translate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{
    "text": "Lateral movement detected in network",
    "target_lang": "th",
    "context": "cybersecurity threat intelligence"
  }'
```

### 4.5 pipeline run

```bash
curl -X POST http://localhost:8000/pipeline/run \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{"limit": 100}'
```

### 4.6 review queue

```bash
curl -H "X-API-Key: tcti-dev-key-2024" \
  "http://localhost:8000/pipeline/review-queue?limit=20&offset=0&validation_status=needs_review&review_state=pending"
```

### 4.7 approve / reject

```bash
curl -X POST http://localhost:8000/pipeline/review/<doc_id>/approve \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{"reviewer":"analyst-01","notes":"validated by analyst"}'
```

```bash
curl -X POST http://localhost:8000/pipeline/review/<doc_id>/reject \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tcti-dev-key-2024" \
  -d '{"reviewer":"analyst-01","notes":"false positive"}'
```

### 4.8 pipeline status

```bash
curl -H "X-API-Key: tcti-dev-key-2024" http://localhost:8000/pipeline/status
```

## 5. ลำดับการทำงานของ pipeline

### 5.1 ขั้น sanitize

ระบบจะตรวจและ redaction ข้อมูลประเภทต่อไปนี้ก่อนเข้า AI และก่อน persist

- email
- เบอร์โทรศัพท์
- เลขบัตรประชาชนไทย
- bearer token
- secret / password / api key ที่ถูกส่งมาตรง ๆ
- private IP บางกรณี

ผลลัพธ์จากขั้นนี้จะถูกเก็บใน

- `cleaning_flags`
- `sanitization_summary`

### 5.2 ขั้น aggregate

pipeline จะรวมหลาย observation ของ IOC เดียวกันเข้าด้วยกัน โดยใช้คู่ของ

- `ioc_type`
- `ioc_value`

จากนั้นจึงค่อยคำนวณ `first_seen`, `last_seen`, `source_count`, `source_types` และรวมข้อความที่ sanitize แล้ว

### 5.3 ขั้น classify / score

ระบบจะคำนวณอย่างน้อย

- `ai_threat_types`
- `ai_threat_actors`
- `ai_mitre_techniques`
- `ai_classification_confidence`
- `ai_risk_score`
- `ai_severity`
- `ai_score_breakdown`
- `ai_top_factors`

### 5.4 ขั้น validation

policy จะพิจารณาจาก

- จำนวนและความน่าเชื่อถือของแหล่งข้อมูล
- AI confidence
- source diversity
- policy gates
- การเป็น private IP
- การมีข้อมูลอ่อนไหวที่ถูก redaction

ผลลัพธ์ที่เป็นไปได้

- `validated_auto`
- `needs_review`
- `rejected`

### 5.5 ขั้น persist

- ทุกเอกสารที่ประมวลผลแล้วจะเข้า `Warehouse`
- ใช้ฟิลด์ `validation_status`, `review_required`, `review_state`, และ `warehouse_eligible` เพื่อแยกว่าเอกสารใดพร้อมใช้งาน, รอ review, หรือถูก reject
- ถ้าต้องใช้ข้อมูลกับ dashboard ภายนอก ให้ map ไปยัง `action_status` และ `action_required` แทน ไม่ควรผูก UI กับคำว่า `validated_*`

## 6. งานปฏิบัติการที่ใช้จริง

### 6.1 import ไฟล์ JSON เข้า datalake

```bash
cd ai-service
python scripts/ops/import_to_datalake.py --dry-run
python scripts/ops/import_to_datalake.py
```

flags ที่มี

- `--data-dir`
- `--elasticsearch-url`
- `--index`
- `--dry-run`

### 6.2 rebuild warehouse จาก datalake

```bash
cd ai-service
python scripts/ops/rebuild_warehouse.py --limit 100
python scripts/ops/rebuild_warehouse.py --date-from 2026-02-04T00:00:00+07:00 --date-to 2026-02-05T23:59:59+07:00 --summary-file ../docs/api-spec/backfill-dry-run.json
python scripts/ops/rebuild_warehouse.py --write --date-from 2026-02-04T00:00:00+07:00 --date-to 2026-02-05T23:59:59+07:00
```

flags ที่มี

- `--date-from`
- `--date-to`
- `--limit`
- `--dry-run`
- `--write`
- `--summary-file`
- `--sample-size`
- `--include-synthetic`
- `--overwrite-existing-review-metadata`
- `--allow-zero-eligible-write`

ข้อควรรู้

- ถ้าไม่ใส่ `--write` สคริปต์จะทำงานแบบ dry-run โดยปริยาย
- โหมด `--write` ต้องใส่ทั้ง `--date-from` และ `--date-to`
- โดยปริยายสคริปต์จะข้าม synthetic fixture และจะไม่ overwrite เอกสารที่มี review metadata อยู่แล้ว
- ถ้า dry-run เจอว่า `validated_auto = 0` สคริปต์จะ block การเขียนจริง เว้นแต่ใส่ `--allow-zero-eligible-write`

### 6.3 ตรวจ schema/index

```bash
curl -X POST http://localhost:8000/elasticsearch/setup \
  -H "X-API-Key: tcti-dev-key-2024"
```

## 7. ตัวแปรแวดล้อมแบบละเอียด

### 7.1 Runtime

- `AI_SERVICE_HOST`
- `AI_SERVICE_PORT`
- `AI_SERVICE_DEBUG`
- `AI_SERVICE_API_KEYS`
- `AI_SERVICE_REQUIRE_AUTH`
- `AI_SERVICE_CORS_ORIGINS`
- `AI_SERVICE_AUTO_CREATE_INDEXES`

### 7.2 Elasticsearch

- `ELASTICSEARCH_URL`
- `DATALAKE_INDEX`
- `WAREHOUSE_INDEX`
- `DATALAKE_API_KEY`
- `WAREHOUSE_API_KEY`

### 7.3 โมเดลและการแปล

- `MODEL_EN`
- `MODEL_MULTI`
- `DEVICE`
- `OPENAI_API_KEY`

### 7.4 HelpDesk

- `HELPDESK_API_URL`
- `HELPDESK_API_KEY`
- `HELPDESK_MOCK_MODE`
- `HELPDESK_LOG_FILE`

## 8. แนวทางตรวจปัญหาเบื้องต้น

### 8.1 health ผ่าน แต่ `classifier_loaded = false`

สาเหตุที่เป็นไปได้

- startup ยังโหลดโมเดลไม่เสร็จ
- เครื่องไม่สามารถดึงโมเดลจาก Hugging Face ได้
- dependency ของ transformer model ไม่ครบ

### 8.2 pipeline ไม่เขียนเข้า warehouse

ให้ตรวจตามลำดับนี้

1. `GET /pipeline/status`
2. มีข้อมูลใน `Warehouse` หรือไม่
3. ค่า `validation_status`
4. ค่า `warehouse_eligible`
5. ค่า `review_state` และ `validation_reasons`

### 8.3 translation ไม่แปล

ตรวจว่าได้ตั้ง `OPENAI_API_KEY` แล้วหรือไม่ เพราะถ้าไม่ตั้ง ระบบจะคืนข้อความเดิม

### 8.4 HelpDesk ไม่ยิง API จริง

ตรวจว่า

- `HELPDESK_MOCK_MODE=false`
- `HELPDESK_API_KEY` ถูกต้อง
- ปลายทาง `HELPDESK_API_URL` เข้าถึงได้

### 8.5 review queue ว่าง

อาจเกิดจาก

- pipeline ยังไม่ได้รัน
- เอกสารถูก `validated_auto` ทั้งหมด
- filter ที่ส่งเข้ามาไม่ตรง เช่น `review_state=pending`

## 9. เอกสารอ้างอิง

- [SYSTEM_GUIDE_TH.md](SYSTEM_GUIDE_TH.md)
- [TOR_AI_WAREHOUSE_GAP_CHECKLIST.md](TOR_AI_WAREHOUSE_GAP_CHECKLIST.md)
- PDF specs ในโฟลเดอร์ `docs/`
