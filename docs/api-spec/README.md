# ชุดเอกสาร API Spec สำหรับ `ncsa-dashboard-web`

เอกสารในโฟลเดอร์นี้ใช้เป็น source of truth สำหรับออกแบบ API ของ dashboard ตัวใหม่ โดยอ้างอิงจาก UI ที่มีอยู่จริงในรีโป `ncsa-dashboard-web`

## ไฟล์หลัก

| เอกสาร | ใช้เมื่อ |
|--------|----------|
| [ncsa-dashboard-api-inventory-th.md](ncsa-dashboard-api-inventory-th.md) | ต้องการดู mapping `หน้า -> ฟังก์ชัน -> endpoint -> schema` แบบภาษาไทย |
| [ncsa-dashboard-openapi.yaml](ncsa-dashboard-openapi.yaml) | ต้องการ OpenAPI 3.x สำหรับ import เข้า Postman หรือใช้เป็น contract หลัก |
| [ncsa-dashboard-compat-map-th.md](ncsa-dashboard-compat-map-th.md) | ต้องการดู mapping จาก flat endpoint ของ PoC ไปยัง canonical `/api/v1/...` |
| [ncsa-dashboard-backend-gap-map-th.md](ncsa-dashboard-backend-gap-map-th.md) | ต้องการดูว่า backend ปัจจุบัน reuse ได้ตรงไหน และยังขาด endpoint อะไร |
| [postman/ncsa-dashboard.postman_collection.json](postman/ncsa-dashboard.postman_collection.json) | ต้องการ Postman collection ที่ generate จาก OpenAPI เพื่อส่งต่อทีม frontend หรือ QA |
| [postman/ncsa-dashboard.local.postman_environment.json](postman/ncsa-dashboard.local.postman_environment.json) | ต้องการ Postman environment ตัวอย่างสำหรับ local/base URL และ bearer token |
| [live-smoke-results.json](live-smoke-results.json) | ต้องการดูผล smoke test ล่าสุดกับ endpoint จริงและ remote ELK |
| [full-contract-smoke-results.json](full-contract-smoke-results.json) | ต้องการดูผล smoke test ครบทุก route ด้วย fake backend เพื่อยืนยัน contract และ response shape |

## ขอบเขตของเอกสารชุดนี้

- ครอบเฉพาะหน้าที่มี UI, field, modal, filter, หรือ interaction ชัดเจนแล้วใน `ncsa-dashboard-web`
- ใช้ `OpenAPI-first` และออกแบบ canonical path เป็น `/api/v1/...`
- เอกสารนี้ไม่ลงลึกหน้า placeholder ล้วน เช่น `Threat Landscape`, `CVE Intelligence`, `News Feed`
- alias flat path ของ PoC จะถูกรวบรวมในเอกสาร compat mapping ไม่ใช้เป็น canonical contract หลัก

## ลำดับการใช้งานที่แนะนำ

1. อ่าน `ncsa-dashboard-api-inventory-th.md` เพื่อเข้าใจภาพรวม
2. เปิด `ncsa-dashboard-openapi.yaml` เพื่อดู schema และตัวอย่าง payload
3. ใช้ `ncsa-dashboard-compat-map-th.md` ตอนต้องเชื่อมกับ path เดิมของ PoC
4. ใช้ `ncsa-dashboard-backend-gap-map-th.md` เพื่อวางแผน map Python/ELK ของระบบปัจจุบัน
5. ส่งมอบ `postman/ncsa-dashboard.postman_collection.json` และ `postman/ncsa-dashboard.local.postman_environment.json` ให้ทีม dev หรือ QA
6. เปิด `live-smoke-results.json` เพื่อยืนยันผลทดสอบล่าสุดกับ remote ELK
7. เปิด `full-contract-smoke-results.json` เพื่อเช็กว่า route ทั้งหมดตอบกลับได้ครบและ response shape ไม่พัง
8. ถ้าต้องการจำลอง `Action Center` สำหรับ QA/UAT แบบบังคับมีรายการ สามารถใช้ [seed_dashboard_fixture.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/scripts/dev/seed_dashboard_fixture.py) ได้ แต่ไม่ใช่ dependency ของ API หลักแล้ว

## สถานะ handoff ปัจจุบัน

- canonical API หลักอยู่ใต้ `/api/v1/...`
- flat compat routes คงไว้เฉพาะหน้าเดิมที่ `ncsa-dashboard-web` เรียกอยู่แล้ว
- Postman artifacts ถูก generate จาก OpenAPI ฉบับเดียวกับที่ใช้เป็น contract
- live smoke กับ remote ELK ผ่านสำหรับ endpoint หลักฝั่ง warehouse และ datalake
- full contract smoke ผ่านครบ `67/67` routes ด้วย fake backend และ bootstrap state
- live smoke ล่าสุดไม่ต้องพึ่ง `processed index` แล้ว และ `Action Center` ใช้ `action_status`/action rule แทน review metadata
- date preset ที่แนะนำสำหรับ UAT ตอนนี้คือ `2026-02-04` ถึง `2026-02-05`
- ช่วงข้อมูลจริงดังกล่าวตอนนี้ `Action Center` ได้ `43` รายการจาก action rule ที่อิง `risk score`, `multi-source corroboration`, และ `defacement/editorial IOC`
