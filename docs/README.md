# ดัชนีเอกสาร

โฟลเดอร์ `docs/` ใช้เก็บทั้งเอกสารคู่มือสำหรับใช้งานจริง และเอกสารอ้างอิงจาก TOR/PDF

## คู่มือที่ควรอ่านก่อน

| เอกสาร | ใช้เมื่อ |
|--------|----------|
| [SYSTEM_GUIDE_TH.md](SYSTEM_GUIDE_TH.md) | ต้องการเข้าใจภาพรวมระบบ, ขอบเขตงาน, และสถาปัตยกรรม |
| [AI_SERVICE_OPERATIONS_TH.md](AI_SERVICE_OPERATIONS_TH.md) | ต้องการใช้งาน API, pipeline, review queue, และงานปฏิบัติการ |
| [TOR_AI_WAREHOUSE_GAP_CHECKLIST.md](TOR_AI_WAREHOUSE_GAP_CHECKLIST.md) | ต้องการดูช่องว่างเทียบ TOR และสถานะ implementation |
| [api-spec/README.md](api-spec/README.md) | ต้องการ API contract สำหรับ `ncsa-dashboard-web` และเอกสาร mapping ระหว่าง frontend กับ backend |

## เอกสารส่งมอบ API

| เอกสาร | ใช้เมื่อ |
|--------|----------|
| [api-spec/ncsa-dashboard-openapi.yaml](api-spec/ncsa-dashboard-openapi.yaml) | ต้องการ canonical OpenAPI สำหรับทีม backend, frontend, หรือ QA |
| [api-spec/postman/ncsa-dashboard.postman_collection.json](api-spec/postman/ncsa-dashboard.postman_collection.json) | ต้องการ Postman collection สำหรับทดสอบหรือส่งต่อทีมพัฒนา |
| [api-spec/postman/ncsa-dashboard.local.postman_environment.json](api-spec/postman/ncsa-dashboard.local.postman_environment.json) | ต้องการ environment ตัวอย่างสำหรับ local run |
| [api-spec/live-smoke-results.json](api-spec/live-smoke-results.json) | ต้องการผล smoke test ล่าสุดกับ remote ELK และ sample readiness |

## เอกสารอ้างอิงจาก TOR / PDF

| เอกสาร | เนื้อหา |
|--------|---------|
| [TOR_สกมช.pdf](TOR_สกมช.pdf) | TOR หลักของโครงการ |
| [01AI-Scopring-pdf.pdf](01AI-Scopring-pdf.pdf) | เอกสารอ้างอิง AI Scoring |
| [02Threat-Level-pdf.pdf](02Threat-Level-pdf.pdf) | เอกสารอ้างอิง Threat Level |
| [03Attack-relationship-pdf.pdf](03Attack-relationship-pdf.pdf) | เอกสารอ้างอิง Attack Relationship |
| [04Trend-Prediction-pdf.pdf](04Trend-Prediction-pdf.pdf) | เอกสารอ้างอิง Trend Prediction |

## คำแนะนำในการใช้งานเอกสาร

- ถ้าจะอธิบายระบบให้ทีมใหม่ เริ่มที่ `SYSTEM_GUIDE_TH.md`
- ถ้าจะ run service, import ข้อมูล, backfill หรือใช้งาน review queue ให้เปิด `AI_SERVICE_OPERATIONS_TH.md`
- ถ้าจะเทียบกับ TOR หรือเตรียมรายการงานถัดไป ให้เปิด `TOR_AI_WAREHOUSE_GAP_CHECKLIST.md`
