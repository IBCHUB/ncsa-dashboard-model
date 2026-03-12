# Backend Readiness & Gap Note สำหรับ `ncsa-dashboard-web`

เอกสารนี้ใช้เป็น handoff note ฝั่ง backend หลังปิดงาน API รอบปัจจุบัน โดยสรุปว่า endpoint กลุ่มใดพร้อมใช้งาน, กลุ่มใดยังเป็น bootstrap/in-memory, และกลุ่มใดมี upstream gap ที่ต้องแก้ก่อน production เต็มรูปแบบ

อ้างอิงผลตรวจล่าสุดวันที่ `2026-03-11` จาก:

- contract tests ใน `ai-service/tests/test_dashboard_api.py`
- live smoke กับ ELK จริงผ่าน [smoke_dashboard_live.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/scripts/dev/smoke_dashboard_live.py)
- artifact ผลรันจริงที่ [live-smoke-results.json](/Users/mm/Desktop/ibusiness/Cyber/docs/api-spec/live-smoke-results.json)

## 1. สถานะรวม

| กลุ่มงาน | สถานะ | หมายเหตุ |
|----------|-------|----------|
| Canonical API `/api/v1` | `พร้อมใช้งาน` | route หลักครบตามหน้าที่มีข้อมูลใน `ncsa-dashboard-web` |
| Flat compat routes | `พร้อมใช้งานบางส่วน` | คงไว้เฉพาะ `login`, `operations dashboard`, และ lookup paths ที่ frontend เดิมเรียกอยู่ |
| OpenAPI | `พร้อมใช้งาน` | ไฟล์หลักอยู่ที่ [ncsa-dashboard-openapi.yaml](/Users/mm/Desktop/ibusiness/Cyber/docs/api-spec/ncsa-dashboard-openapi.yaml) |
| Postman handoff | `พร้อมใช้งาน` | collection/environment อยู่ใต้ [postman](/Users/mm/Desktop/ibusiness/Cyber/docs/api-spec/postman) |
| Live ELK validation | `ผ่าน` | warehouse + datalake query ผ่าน; action/review flows ไม่พึ่ง processed index แล้ว |

## 2. Readiness Matrix

### 2.1 ELK-backed และผ่าน live smoke

| กลุ่ม API | สถานะ | หมายเหตุ |
|----------|-------|----------|
| `GET /api/v1/executive/dashboard` | `smoke-live` | ตอบ `200`; shape ครบ `threat_level`, `exposure_today`, `severity_distribution`, `attack_volume_trend`, `attack_origin_map` |
| `GET /api/v1/operations/dashboard` | `smoke-live` | ตอบ `200`; shape ครบ KPI, heatmap, top lists |
| `GET /api/v1/operations/reports/{report_key}` | `smoke-live` | ตอบ `200`; รองรับ `attack-origin` alias และคืน `summary`, `filters`, `ranking`, `trend_comparison` |
| `GET /api/v1/operations/attack-time-report` | `smoke-live` | ตอบ `200`; heatmap ผ่านและคืน event table ได้ |
| `GET /api/v1/actions` | `smoke-live` | ตอบ `200`; query จาก warehouse โดยตรงแล้ว ไม่มี `403` จาก processed index อีก และไม่พึ่ง review metadata โดยเปิด action จาก `action_status` หรือกติกา risk/multi-source ที่ derive on read |
| `GET /api/v1/ioc-analytics` | `smoke-live` | อย่างน้อย `tab=statistics-import` คืน cards/charts จริง |
| `GET /api/v1/news` | `smoke-live` | ตอบ `200`; พบรายการจริงจาก datalake/news source |

### 2.2 Contract-complete แต่ผลข้อมูลขึ้นกับ data window / upstream content

| กลุ่ม API | สถานะ | หมายเหตุ |
|----------|-------|----------|
| `GET /api/v1/iocs` | `smoke-live` | route ตอบ `200`; smoke ล่าสุดช่วง `2026-02-04` ถึง `2026-02-05` ได้ `391` รายการ |
| `POST /api/v1/reports/ioc/preview` | `contract-tested` | ผ่าน test suite; live data ต้องเลือกช่วงเวลาที่ warehouse มีข้อมูลจริง |
| `POST /api/v1/reports/most-frequent-threats/preview` | `contract-tested` | ใช้ datalake aggregation ได้แล้ว; ยังไม่ได้แยก smoke sample ใน artifact ปัจจุบัน |
| `GET /api/v1/news/{article_id}` | `contract-tested` | ผ่าน test suite; ใช้ article id จาก list response |
| `GET /api/v1/iocs/{ioc_id}` / `/events` | `contract-tested` | ผ่าน test suite ด้วย warehouse+datalake join; live sample ต้องอาศัย IOC id จริงจาก query ก่อน |

### 2.3 Bootstrap / In-memory backend ชั่วคราว

| กลุ่ม API | สถานะ | หมายเหตุ |
|----------|-------|----------|
| Auth / Session | `bootstrap` | token/session ออกโดย in-process store ใน `dashboard_bootstrap.py` |
| Account / Profile | `bootstrap` | ใช้ in-memory profile store |
| Users / User Groups | `bootstrap` | CRUD และ pagination/search ทำงานได้ แต่ยังไม่ผูก external IAM |
| Notifications | `bootstrap` | read/unread state อยู่ใน memory |
| Export Jobs | `bootstrap` | คืน job/status ได้ แต่ยังไม่มี object storage หรือ async worker จริง |
| Assignees / Enforcement Points | `bootstrap` | lookup ใช้ข้อมูลภายใน service |

### 2.4 Gap ที่ยังเหลือ

| กลุ่ม API | สถานะ | ปัญหา |
|----------|-------|--------|
| User/Auth productionization | `bootstrap-gap` | ถ้าจะขึ้น production จริงต้องเปลี่ยนจาก in-memory auth ไปยัง auth store ที่ยืนยันแล้ว |

## 3. ผล live smoke ล่าสุด

ใช้ config:

- `ELASTICSEARCH_URL=https://pluto-elk.ibusiness.co.th`
- `DATALAKE_INDEX=cyber-logs-datalake`
- `WAREHOUSE_INDEX=cyber-logs-datawarehouse`
- `start_date=2026-02-04`
- `end_date=2026-02-05`

ผลสรุป:

- warehouse queries ผ่าน
- datalake queries ผ่าน
- action query ใช้ warehouse โดยตรง
- `attack-time-report` ได้ `463` events
- `actions` ได้ `43` รายการจากข้อมูลจริง
- `iocs` ได้ `391` รายการ
- `news` ได้ `62` รายการ
- `action_detail` ของ `domain:783668eb25290a4f6db25e27` ผ่าน `200`

ข้อสังเกตจาก artifact [live-smoke-results.json](/Users/mm/Desktop/ibusiness/Cyber/docs/api-spec/live-smoke-results.json):

- date preset ที่ใช้งานได้จริงตอนนี้คือ `2026-02-04 .. 2026-02-05`
- `Action Center` ไม่ได้ติดเรื่อง `validated/review metadata` แล้ว และตอนนี้มีรายการจากข้อมูลจริงด้วย action rule ปัจจุบัน
- action rule ที่เปิด ticket ตอนนี้พิจารณา `risk score`, `multi-source corroboration`, และ `defacement/editorial IOC`

## 4. สิ่งที่ต้องทำต่อก่อน production เต็มรูปแบบ

1. ถ้าจะใช้ `Action Center` ระยะยาว ให้ตรึง action rule เป็น policy กลาง และถ้าต้องการให้เสถียรกว่า derive-on-read ให้ persist `action_status` จาก pipeline/backfill
2. ถ้าจะใช้ settings/auth จริง ให้แทน bootstrap state ด้วย persistent backend
3. ถ้าจะให้ frontend ตัวใหม่ใช้ canonical path ทั้งหมด ให้ทยอยเลิก flat compat routes หลัง wiring เสร็จ

## 5. Handoff Checklist สำหรับทีม `ncsa-dashboard-web`

- ใช้ canonical spec ที่ [ncsa-dashboard-openapi.yaml](/Users/mm/Desktop/ibusiness/Cyber/docs/api-spec/ncsa-dashboard-openapi.yaml)
- ใช้ Postman collection/environment ใต้ [postman](/Users/mm/Desktop/ibusiness/Cyber/docs/api-spec/postman)
- ถ้ายังต้องรองรับ frontend PoC เดิม ให้ใช้ compat routes เฉพาะ login/operations/lookups เท่านั้น
- ใช้ date preset `2026-02-04` ถึง `2026-02-05` สำหรับ UAT รอบแรก
- `Action Center` ใช้ sample `action_id=domain:783668eb25290a4f6db25e27` สำหรับ UAT รอบแรกได้ทันที
- อย่าผูก dashboard contract กับ `validated` terminology ของ pipeline; ให้ใช้ `action status` เป็นภาษาภายนอก
