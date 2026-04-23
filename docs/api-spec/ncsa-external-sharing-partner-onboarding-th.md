# คู่มือ Onboarding สำหรับองค์กรภายนอก

คู่มือนี้ใช้สำหรับเริ่มต้นเชื่อมต่อกับ `External Threat Sharing API` ของระบบ TCTI อย่างรวดเร็ว โดยอ้างอิง implementation ปัจจุบันของ backend

## 1. ภาพรวม

- Base URL: `http://<host>:8000`
- Namespace หลัก: `/api/v1/external/...`
- Authentication: `X-API-Key`
- Response format: envelope มาตรฐาน `data`, `meta`, `error`
- Indicator ID มาตรฐาน: `<ioc_type>::<ioc_value>`

ไฟล์อ้างอิงที่ควรส่งให้ partner พร้อมกัน:

- OpenAPI: [ncsa-external-sharing-openapi.yaml](/Users/m/Desktop/ibusiness/cyber-workspace/ncsa-dashboard-model/docs/api-spec/ncsa-external-sharing-openapi.yaml)
- Postman Collection: [ncsa-external-sharing.postman_collection.json](/Users/m/Desktop/ibusiness/cyber-workspace/ncsa-dashboard-model/docs/api-spec/postman/ncsa-external-sharing.postman_collection.json)
- Postman Environment: [ncsa-external-sharing.local.postman_environment.json](/Users/m/Desktop/ibusiness/cyber-workspace/ncsa-dashboard-model/docs/api-spec/postman/ncsa-external-sharing.local.postman_environment.json)

## 2. สิ่งที่ต้องได้รับก่อนเริ่ม

องค์กรภายนอกแต่ละรายควรได้รับข้อมูลอย่างน้อยดังนี้

| รายการ | ตัวอย่าง |
|--------|----------|
| Base URL | `https://tcti.example.go.th` |
| API Key | `partner-abc-prod-key` |
| Partner ID | `partner-abc` |
| Permissions | `read_feed`, `submit_data`, `export_feed` |
| Max TLP | `amber` |
| Allowed IOC Types | `domain`, `ip`, `url`, `hash`, `cve` |
| Allowed Formats | `json`, `csv`, `plain_text`, `suricata`, `snort` |

หมายเหตุ:

- partner จะเห็นเฉพาะข้อมูลที่ไม่เกิน `max_tlp` ของตัวเอง
- ข้อมูล outbound ถูกคัดจาก record ที่ `validation_status=validated` เท่านั้น
- ข้อมูล sensitive หรือ field ภายในจะไม่ถูกส่งออกใน external payload

## 3. สิทธิ์การใช้งาน

| Permission | ใช้กับ |
|------------|--------|
| `read_feed` | `GET /profile`, `GET /lookups/ioc-types`, `GET /lookups/threat-types`, `GET /lookups/severities`, `GET /lookups/tlp-levels`, `GET /changes`, `GET /indicators`, detail, observations, relationships |
| `submit_data` | `POST /indicators`, `POST /events`, `POST /bulk`, `POST /submissions/{id}/revoke` |
| `export_feed` | `GET /lookups/export-formats`, `POST /exports`, `GET /exports/{id}`, `GET /exports/{id}/download` |

## 4. Flow ที่แนะนำ

### 4.1 เริ่มต้นเชื่อมต่อ

1. เรียก `GET /api/v1/external/profile`
2. ตรวจว่า permissions และ `max_tlp` ตรงกับที่ตกลงไว้
3. เรียก lookups ที่ต้องใช้ เช่น IOC types, threat types, severities, export formats

### 4.2 ดึง feed ออกไปใช้

1. เรียก `GET /api/v1/external/changes` โดยยังไม่ส่ง `cursor`
2. เก็บ `meta.next_cursor` หรือ `data.next_cursor`
3. รอบถัดไปส่ง `cursor` เดิมกลับมาเพื่อ incremental sync
4. ถ้าต้องการค้นหาเฉพาะเจาะจง ใช้ `GET /api/v1/external/indicators`

### 4.3 ส่งข้อมูลกลับเข้าระบบ

1. IOC เดี่ยว ใช้ `POST /api/v1/external/indicators`
2. เหตุการณ์ที่มีหลาย IOC ใช้ `POST /api/v1/external/events`
3. Batch import ใช้ `POST /api/v1/external/bulk`
4. ตรวจสถานะด้วย `GET /api/v1/external/submissions/{submission_id}`

### 4.4 ขอ export machine-readable

1. สร้าง job ด้วย `POST /api/v1/external/exports`
2. ตรวจสถานะด้วย `GET /api/v1/external/exports/{export_id}`
3. ดาวน์โหลดด้วย `GET /api/v1/external/exports/{export_id}/download`

## 5. Endpoint สำคัญ

| หมวด | Endpoint |
|------|----------|
| Partner | `GET /api/v1/external/profile` |
| Lookups | `GET /api/v1/external/lookups/ioc-types` |
| Lookups | `GET /api/v1/external/lookups/threat-types` |
| Lookups | `GET /api/v1/external/lookups/severities` |
| Lookups | `GET /api/v1/external/lookups/tlp-levels` |
| Lookups | `GET /api/v1/external/lookups/export-formats` |
| Feed | `GET /api/v1/external/changes` |
| Feed | `GET /api/v1/external/indicators` |
| Feed | `GET /api/v1/external/indicators/{indicator_id}` |
| Feed | `GET /api/v1/external/indicators/{indicator_id}/observations` |
| Feed | `GET /api/v1/external/indicators/{indicator_id}/relationships` |
| Submission | `POST /api/v1/external/indicators` |
| Submission | `POST /api/v1/external/events` |
| Submission | `POST /api/v1/external/bulk` |
| Submission | `GET /api/v1/external/submissions/{submission_id}` |
| Submission | `POST /api/v1/external/submissions/{submission_id}/revoke` |
| Export | `POST /api/v1/external/exports` |
| Export | `GET /api/v1/external/exports/{export_id}` |
| Export | `GET /api/v1/external/exports/{export_id}/download` |

## 6. ตัวอย่างใช้งานอย่างเร็ว

### ตรวจ profile

```bash
curl -s \
  -H "X-API-Key: partner-abc-prod-key" \
  "https://tcti.example.go.th/api/v1/external/profile"
```

### ดึง incremental changes

```bash
curl -s \
  -H "X-API-Key: partner-abc-prod-key" \
  "https://tcti.example.go.th/api/v1/external/changes?page_size=100&tlp=amber"
```

### ส่ง IOC เดี่ยว

```bash
curl -s \
  -X POST \
  -H "X-API-Key: partner-abc-prod-key" \
  -H "Content-Type: application/json" \
  -d '{
    "ioc_value": "new-submit.example",
    "ioc_type": "domain",
    "title": "Partner phishing domain",
    "description": "Phishing infrastructure shared by partner",
    "threat_types": ["Phishing"],
    "severity": "high",
    "confidence": 85,
    "tlp": "green",
    "references": ["https://partner.example/report/1"],
    "observed_at": "2026-03-12T01:00:00Z"
  }' \
  "https://tcti.example.go.th/api/v1/external/indicators"
```

### ขอ export

```bash
curl -s \
  -X POST \
  -H "X-API-Key: partner-abc-prod-key" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "suricata",
    "tlp": "amber",
    "ioc_types": ["domain", "ip"],
    "threat_types": ["Phishing"],
    "severities": ["critical", "high"],
    "min_risk_score": 80
  }' \
  "https://tcti.example.go.th/api/v1/external/exports"
```

## 7. Error ที่ควรรู้

| HTTP Status | ความหมาย |
|-------------|-----------|
| `401` | ไม่มี `X-API-Key` หรือ header ไม่ถูกต้อง |
| `403` | partner ไม่มีสิทธิ์เรียก endpoint นี้ |
| `404` | ไม่พบ indicator, submission หรือ export job |
| `400` | รูปแบบ input ไม่ถูกต้อง เช่น `indicator_id` ไม่ตรง format |

ให้ partner ตรวจ `error.message` และ `error.details` ทุกครั้งเมื่อไม่ใช่ `2xx`

## 8. Checklist ก่อน Go-Live

- ยืนยันว่า API key แยกต่อองค์กร ไม่ใช้ key ร่วม
- ยืนยัน permissions และ `max_tlp` ของแต่ละ partner
- ทดสอบ `GET /profile` ผ่านจาก network จริงของ partner
- ทดสอบ `GET /changes` และบันทึก `next_cursor` ได้
- ทดสอบ submission อย่างน้อย 1 IOC และตรวจ `submission_id`
- ทดสอบ export format ที่ตกลงกันจริง
- ทดสอบกรณี revoke ถ้ามีการส่งข้อมูลกลับเข้าระบบ
- ยืนยันว่า partner อ่าน OpenAPI และลอง import Postman collection แล้ว

## 9. สำหรับทีมระบบฝั่งเรา

ฝั่ง backend สามารถตั้ง partner registry สำหรับ local/test ได้จากไฟล์ตัวอย่างนี้:

- Env example: [.env.external-sharing.example](/Users/m/Desktop/ibusiness/cyber-workspace/ncsa-dashboard-model/ai-service/.env.external-sharing.example)

ตัวแปรสำคัญ:

- `EXTERNAL_PARTNER_REGISTRY_JSON`

สำหรับ production ควรเก็บ API key ใน secret manager หรือ configuration store ที่ปลอดภัย ไม่ควร hardcode ลงไฟล์จริง
