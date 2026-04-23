# External Sharing Validation Matrix

เอกสารนี้สรุปการตรวจสอบ endpoint ของ `External Threat Sharing API` แบบ endpoint-by-endpoint โดยแยกเป็น

- coverage ใน `pytest` ด้วย fake backend/contract tests
- coverage ใน live smoke script สำหรับยิงกับ server/ELK จริง
- ช่องว่างที่ยังเหลือและควรตรวจด้วย UAT หรือ partner certification

อ้างอิง implementation:

- Router: [external_sharing_router.py](/Users/m/Desktop/ibusiness/cyber-workspace/ncsa-dashboard-model/ai-service/services/external_sharing_router.py)
- Tests: [test_external_api.py](/Users/m/Desktop/ibusiness/cyber-workspace/ncsa-dashboard-model/ai-service/tests/test_external_api.py)
- Live smoke: [smoke_external_sharing_live.py](/Users/m/Desktop/ibusiness/cyber-workspace/ncsa-dashboard-model/ai-service/scripts/dev/smoke_external_sharing_live.py)

## สถานะรวม

| หมวด | สถานะ |
|------|-------|
| Auth / permission gating | `covered in pytest` |
| Read feed main flow | `covered in pytest + live smoke` |
| Submission main flow | `covered in pytest + live smoke` |
| Export main flow | `covered in pytest + live smoke` |
| ทุก query param แบบ combinational ครบทุกชุด | `partial` |
| ทุก error response ใน environment จริง | `not fully covered` |
| Payload semantics กับข้อมูล production จริงทั้งหมด | `requires live/UAT verification` |

## Endpoint Matrix

| Endpoint | Method | Auth/Permission | Params/Body ที่ตรวจใน pytest | Response ที่ตรวจใน pytest | Negative cases ใน pytest | Live smoke |
|----------|--------|-----------------|-------------------------------|---------------------------|--------------------------|------------|
| `/api/v1/external/profile` | `GET` | `X-API-Key` | ไม่มี | envelope, `partner_id`, ไม่ expose `api_key` | missing key `401`, invalid key `403` | เรียกจริง |
| `/api/v1/external/lookups/ioc-types` | `GET` | `read_feed` | ไม่มี | `items[].value` มี `domain/ip/url` | ใช้ permission gate รวม | เรียกจริง |
| `/api/v1/external/lookups/threat-types` | `GET` | `read_feed` | ไม่มี | มี `Phishing`, `Malware` | ใช้ permission gate รวม | เรียกจริง |
| `/api/v1/external/lookups/severities` | `GET` | `read_feed` | ไม่มี | มี severity หลักครบ | ใช้ permission gate รวม | เรียกจริง |
| `/api/v1/external/lookups/tlp-levels` | `GET` | `read_feed` | ไม่มี | มี `clear/green/amber/red` | ใช้ permission gate รวม | เรียกจริง |
| `/api/v1/external/lookups/export-formats` | `GET` | `export_feed` | ไม่มี | มี format ที่ partner ใช้ได้ | reader key ได้ `403` | เรียกจริง |
| `/api/v1/external/changes` | `GET` | `read_feed` | `page_size`, `tlp`, `ioc_types`, `threat_types`, `severities`, `since`, `updated_after` | แยก `created/updated/revoked`, `meta.next_cursor`, TLP filtering | `page_size=0 -> 422` | เรียกจริง |
| `/api/v1/external/indicators` | `GET` | `read_feed` | `page`, `page_size`, `query`, `ioc_types`, `threat_types`, `severities`, `min_risk_score`, `tlp` | paged meta, indicator list, filtering ตาม query/risk/type/threat/severity | `page=0 -> 422` | เรียกจริง |
| `/api/v1/external/indicators/{indicator_id}` | `GET` | `read_feed` | path param | indicator detail, `sharing_status` | invalid id `400`, hidden/missing `404` | เรียกจริง |
| `/api/v1/external/indicators/{indicator_id}/observations` | `GET` | `read_feed` | `page`, `page_size` | paged meta, sanitized observations, no PII leak ใน fields ที่ test จับไว้ | invalid id `400` | เรียกจริง |
| `/api/v1/external/indicators/{indicator_id}/relationships` | `GET` | `read_feed` | path param | `graph_summary`, `related_indicators` | invalid id `400` | เรียกจริง |
| `/api/v1/external/indicators` | `POST` | `submit_data` | indicator payload หลัก, `severity`, `confidence`, `tlp` | accepted receipt, `normalized_indicator_ids` | reader key `403`, bad ioc type/value -> rejected receipt, confidence > 100 -> `422` | เรียกจริง |
| `/api/v1/external/events` | `POST` | `submit_data` | event payload, `indicators[]`, `severity`, `confidence`, `tlp` | accepted receipt, `accepted_count` | empty indicators -> rejected receipt | เรียกจริง |
| `/api/v1/external/bulk` | `POST` | `submit_data` | `default_tlp`, `dedupe_strategy`, mixed items | accepted receipt, dedupe by `indicator_id` | invalid indicator / empty event indicators -> rejected receipt | เรียกจริง |
| `/api/v1/external/submissions/{submission_id}` | `GET` | `submit_data` | path param | receipt shape, `submission_type` | missing submission `404`, wrong-permission partner `403` | เรียกจริง |
| `/api/v1/external/submissions/{submission_id}/revoke` | `POST` | `submit_data` | path param | revoke payload, `updated_count`, `revoked_at`, idempotent revoke | missing submission `404` | เรียกจริง |
| `/api/v1/external/exports` | `POST` | `export_feed` | `format`, `ioc_types`, `threat_types`, `severities`, `min_risk_score`, `tlp`, `start_date`, `end_date` | job payload, `record_count`, `download_url` | reader key `403`, disallowed format `400` | เรียกจริง |
| `/api/v1/external/exports/{export_id}` | `GET` | `export_feed` | path param | job status payload | missing job `404`, wrong-permission partner `403` | เรียกจริง |
| `/api/v1/external/exports/{export_id}/download` | `GET` | `export_feed` | path param | binary/text download not empty | missing job `404` | เรียกจริง |

## Parameter Coverage Notes

สิ่งที่ครอบแล้วใน `pytest`

- pagination bounds ที่เกิดจาก FastAPI validation เช่น `page=0`, `page_size=0`
- primary filter params ของ `/changes` และ `/indicators`
- request body validation หลักของ submission/export endpoints
- permission boundary ระหว่าง `read_feed`, `submit_data`, `export_feed`

สิ่งที่ยังไม่ครอบแบบ exhaustive

- ทุก combination ของ array params พร้อมกันใน request เดียว
- date filter เชิง semantic กับหลายช่วงเวลาในข้อมูลจริง
- cursor sequencing หลายหน้าเกิน 1 page และ stability เมื่อมีข้อมูลเปลี่ยนระหว่างรอบ
- payload semantics เชิงลึกสำหรับทุก field ในทุก export format

## Live Smoke Coverage

live smoke script ถูกออกแบบให้ครอบทุก endpoint ใน onboarding doc และ flow หลักดังนี้

1. ใช้ reader key สำหรับ read-only endpoints
2. ใช้ writer key สำหรับ submit/export endpoints
3. สร้าง unique IOC/event/bulk submissions
4. อ่าน submission status
5. revoke submission ที่สร้างขึ้นเพื่อ cleanup
6. สร้าง export job แล้วตามอ่าน status และ download

## สิ่งที่ยังต้องพึ่ง UAT / Partner Certification

- volume test และ rate limiting จริง
- latency และ timeout กับ ELK จริง
- ความถูกต้องของข้อมูลแต่ละองค์กรตาม `max_tlp` และ permission policy จริง
- interoperability กับระบบปลายทาง เช่น SIEM/SOAR/Ticketing ของ partner
- การอ่านไฟล์ export format ไปใช้จริง เช่น Suricata/Snort parser ฝั่ง partner
