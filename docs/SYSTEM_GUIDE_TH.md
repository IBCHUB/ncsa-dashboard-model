# คู่มือภาพรวมระบบ TCTI

## 1. วัตถุประสงค์ของระบบ

ระบบในรีโปนี้รับผิดชอบงานหลัก 2 ส่วน

- `AI / ML` สำหรับวิเคราะห์ภัยคุกคามและคำนวณคะแนนความเสี่ยง
- `Threat Data Warehouse` สำหรับเก็บผลลัพธ์ที่ผ่านการประมวลผลและพร้อมส่งต่อให้ระบบอื่นใช้

สิ่งที่รีโปนี้ไม่ได้เป็นเจ้าของโดยตรง

- `Threat Data Lake` ต้นทางที่รับข้อมูลจาก vendor/ระบบภายนอก
- `Dashboard` และ `Threat Search` ที่ใช้งานจริง

หมายความว่า pipeline ในรีโปนี้ทำหน้าที่รับข้อมูลจาก datalake ที่มีอยู่แล้ว, ประมวลผลด้วย AI, ทำ validation/review, แล้วบันทึกผลไปยัง warehouse

## 2. ขอบเขตของข้อมูล

ระบบใช้ดัชนีหลัก 2 ตัว

| ดัชนี | หน้าที่ |
|------|---------|
| `DATALAKE_INDEX` | เก็บข้อมูล IOC ดิบจากหลายแหล่ง |
| `WAREHOUSE_INDEX` | เก็บผลลัพธ์หลังผ่าน AI/validation พร้อม review metadata |

หลักการสำคัญ

- เอกสารทุกตัวที่ pipeline ประมวลผลจะถูกบันทึกลง `Warehouse`
- ใช้ฟิลด์ `validation_status`, `review_required`, `review_state`, `warehouse_eligible` เพื่อแยกเอกสารที่พร้อมใช้งานออกจากรายการที่รอ review หรือถูก reject
- `Warehouse` ใช้เป็นแหล่งข้อมูลที่ external consumers ควรอ่านต่อเป็นหลัก

## 3. สถาปัตยกรรม

```text
External Threat Sources
        |
        v
Threat Data Lake
        |
        v
AI Service
  1. sanitize
  2. aggregate observations
  3. classify
  4. score
  5. validate
        |
        +--> Threat Data Warehouse
                    |
                    v
      External Dashboard / Threat Search
```

## 4. บทบาทของแต่ละส่วน

### 4.1 AI Service

หน้าที่ของ service นี้คือ

- รับข้อความหรือ IOC ผ่าน API
- ใช้ model เพื่อจัดหมวดหมู่ภัยคุกคาม
- คำนวณความเสี่ยงตาม scoring model
- sanitize ข้อมูลที่อาจมี PII หรือข้อมูลลับ
- ประเมินว่าจะ auto-validate, ส่ง review, หรือ reject
- จัดการ pipeline และ review queue

### 4.2 Elasticsearch

ใช้เป็นทั้งแหล่งข้อมูลต้นทางและปลายทาง

- `Data Lake` คือข้อมูลดิบ
- `Warehouse` คือผลลัพธ์หลัง AI ทุกตัว พร้อมสถานะ review/action

### 4.3 Kibana

ใช้สำหรับ

- ตรวจสอบเอกสารในแต่ละ index
- ดูสถานะข้อมูลระหว่างทดสอบ
- ตรวจสอบผลจาก import / pipeline / backfill

## 5. การไหลของงานตามปกติ

### 5.1 งาน ingest/import

1. เตรียมไฟล์ JSON ใน `data_lake/` หรือ datalake ภายนอก
2. รัน `scripts/ops/import_to_datalake.py`
3. ตรวจสอบว่าเอกสารถูกเขียนเข้า `DATALAKE_INDEX`

### 5.2 งาน pipeline

1. เรียก `POST /pipeline/run`
2. ระบบอ่าน IOC ที่ `ai_processed = false`
3. ระบบ aggregate observation ของ IOC เดียวกัน
4. ระบบ sanitize และ enrich ด้วย AI
5. ระบบเขียนผลลง `Warehouse`
6. ถ้าต้อง review หรือ reject จะเก็บสถานะไว้ใน document เดียวกัน
7. เอกสารต้นทางใน datalake จะถูก mark ว่าประมวลผลแล้ว

### 5.3 งาน manual review

1. เรียก `GET /pipeline/review-queue`
2. เลือกรายการที่ `needs_review`
3. เรียก `approve` หรือ `reject`
4. ระบบอัปเดตสถานะบน document ใน `Warehouse` เดิม

### 5.4 งาน backfill

ใช้เมื่อมีการเปลี่ยน scoring/validation logic แล้วต้อง rebuild warehouse ใหม่จาก datalake

คำสั่งหลัก

```bash
python ai-service/scripts/ops/rebuild_warehouse.py --dry-run --limit 100
```

## 6. การติดตั้งแบบย่อ

### แบบ Docker

```bash
docker-compose up -d
```

### แบบ local

```bash
cd ai-service
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

## 7. ตัวแปรแวดล้อมที่ควรตั้ง

### 7.1 กลุ่ม service runtime

- `AI_SERVICE_HOST`
- `AI_SERVICE_PORT`
- `AI_SERVICE_API_KEYS`
- `AI_SERVICE_REQUIRE_AUTH`
- `AI_SERVICE_CORS_ORIGINS`

### 7.2 กลุ่ม model / AI

- `MODEL_EN`
- `MODEL_MULTI`
- `DEVICE`
- `OPENAI_API_KEY`

### 7.3 กลุ่ม Elasticsearch

- `ELASTICSEARCH_URL`
- `DATALAKE_INDEX`
- `WAREHOUSE_INDEX`
- `DATALAKE_API_KEY`
- `WAREHOUSE_API_KEY`
- `AI_SERVICE_AUTO_CREATE_INDEXES`

### 7.4 กลุ่ม HelpDesk

- `HELPDESK_API_URL`
- `HELPDESK_API_KEY`
- `HELPDESK_MOCK_MODE`
- `HELPDESK_LOG_FILE`

## 8. สถานะ validation

| สถานะ | ความหมาย |
|------|-----------|
| `validated_auto` | ระบบเชื่อมั่นพอและเขียนเข้า warehouse ได้ทันที |
| `validated_manual` | ผู้ตรวจอนุมัติแล้ว |
| `needs_review` | ต้องมีคนตรวจสอบก่อน |
| `rejected` | ระบบปฏิเสธไม่ให้เข้า warehouse |
| `rejected_manual` | ผู้ตรวจปฏิเสธแล้ว |

ปัจจัยที่ทำให้ต้อง review หรือ reject เช่น

- IOC ไม่ครบ
- มีแหล่งข้อมูลไม่พอ
- confidence ต่ำ
- policy gate ถูก trigger
- เป็น private IP
- มีข้อมูลอ่อนไหวที่ถูก redaction

หมายเหตุ:
- สถานะกลุ่มนี้เป็น internal workflow ของ AI/warehouse
- ฝั่ง dashboard/action API ใช้ภาษางานปฏิบัติการคือ `action_status` เช่น `open`, `in_progress`, `closed`

## 9. โครงสร้างเอกสารที่ควรอ้างอิง

- [AI_SERVICE_OPERATIONS_TH.md](AI_SERVICE_OPERATIONS_TH.md) สำหรับ API และ runbook
- [TOR_AI_WAREHOUSE_GAP_CHECKLIST.md](TOR_AI_WAREHOUSE_GAP_CHECKLIST.md) สำหรับติดตาม gap เทียบ TOR
- PDF ในโฟลเดอร์ `docs/` สำหรับอ้างอิง requirement ต้นทาง

## 10. ข้อควรรู้เชิงปฏิบัติการ

- startup ครั้งแรกของ AI Service อาจใช้เวลานาน เพราะต้องโหลดโมเดล
- translation endpoint จะไม่แปลถ้าไม่มี `OPENAI_API_KEY`
- HelpDesk ใช้ mock mode เป็นค่าเริ่มต้น
- Dashboard ที่ใช้งานจริงยังไม่ถูกรวมเข้ามาในรีโปนี้
