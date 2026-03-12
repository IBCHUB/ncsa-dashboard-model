# TOR Gap-Closure Checklist: AI/ML + Threat Data Warehouse

> Scope note  
> เอกสารนี้ประเมินเฉพาะขอบเขตที่ทีมเรารับผิดชอบ:
> - `AI / ML`
> - `Threat Data Warehouse`
>
> ไม่นับเป็น gap ของทีมเราในรอบนี้:
> - `Threat Data-Lake core implementation`
> - `Dashboard / Threat Search UI`
> - `THCert HelpDesk integration UI`
> - `Threat Intelligence SaaS platform`
> - `Platform exchange / MISP / external sharing platform`

## Source TOR Sections Used
- `TOR_สกมช.pdf` หน้า 21: ภาคผนวก 2 ข้อ 1 `Big Data / Data Analytic`
- `TOR_สกมช.pdf` หน้า 22: ภาคผนวก 2 ข้อ 2 `ระบบศูนย์รวบรวม จัดเก็บข้อมูล เพื่อการตรวจสอบ`
- `TOR_สกมช.pdf` หน้า 26-27: ภาคผนวก 5 ข้อ 2 `Validation`
- `TOR_สกมช.pdf` หน้า 27-28: ภาคผนวก 5 ข้อ 4 `Threat Data-Lake`
- `TOR_สกมช.pdf` หน้า 10-12: งวดส่งมอบงานที่เกี่ยวกับ Big Data, Data Analytic, Data-Lake, คู่มือ, source code

## Status Legend
- `[Done]` มีในระบบแล้วหรือใกล้ครบ
- `[Partial]` มีบางส่วน แต่ยังไม่พอจะ claim ว่าปิด TOR
- `[Missing]` ยังไม่มีใน implementation ปัจจุบัน
- `[Out]` นอกขอบเขตทีมเรา

## A. Ingest -> AI/ML -> Warehouse Pipeline

### A1. รับข้อมูลจาก upstream Threat Data-Lake มา aggregate แล้วเขียน Warehouse
- TOR ref: หน้า 21 ข้อ 1.1, หน้า 22 ข้อ 2.1-2.5
- Status: `[Done]`
- Current implementation:
  - `ai-service/main.py` รวม source-level observations เป็น IOC เดียว
  - คำนวณ `first_seen`, `last_seen`, `source_count`
  - enrich `risk_score`, `severity`, `threat_actor`, `MITRE`, `sector`
  - persist เข้า `cyber-logs-datawarehouse`
- Evidence:
  - [main.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/main.py#L569)
  - [elastic_client.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/elastic_client.py#L430)
  - [rebuild_warehouse.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/scripts/ops/rebuild_warehouse.py#L61)
- Close-out action:
  - ไม่มี blocker เชิงฟังก์ชัน
  - ต้องมี operational runbook สำหรับ scheduled/backfill รอบ production

### A2. ETL / data preparation / data cleansing ก่อนเข้า AI และ Warehouse
- TOR ref: หน้า 21 ข้อ 1.1-1.3
- Status: `[Partial]`
- Current implementation:
  - มี ETL เชิงโครงสร้าง เช่นรวมหลาย records, dedupe sources, parse timestamps
  - มี explicit `sanitization` stage แล้วสำหรับ `description`, `reference`, `tags`
  - มี summary metadata เช่น `cleaning_flags`, `sanitization_summary`
- Gap:
  - ไม่มีกติกา normalize schema ระดับ field อย่างเป็นระบบ
  - ไม่มี quality flags เช่น invalid timestamp, malformed IOC, dropped fields
  - ไม่มี reject/dead-letter path สำหรับข้อมูลเสีย
- Required closure:
  - เพิ่ม pre-processing layer เช่น `normalize_record()` / `clean_record()`
  - ออก `cleaning_report` หรือ `ingestion_flags`
  - เก็บ reason เมื่อ record ถูก drop / degrade

### A3. ลบข้อมูลลับ / PII ก่อน validation และก่อนเก็บต่อ
- TOR ref: หน้า 26 ข้อ 2.2
- Status: `[Done]`
- Current implementation:
  - sanitize ก่อน `classify_threat()` / `calculate_risk_score()` และก่อน persist
  - redact email, phone, bearer token, credential secret, Thai national ID, private IP
  - เก็บ `cleaning_flags` และ `sanitization_summary` ใน processed/warehouse metadata
- Evidence:
  - [sanitizer.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/utils/sanitizer.py#L46)
  - [pipeline_documents.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/utils/pipeline_documents.py#L154)
  - [main.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/main.py#L217)
  - [test_sanitizer.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/tests/test_sanitizer.py#L9)

## B. Validation Workflow

### B1. เชื่อมโยงแหล่งข้อมูลภัยคุกคามเพื่อใช้ตรวจสอบ / วิเคราะห์ / ยืนยัน
- TOR ref: หน้า 26 ข้อ 2.1-2.3
- Status: `[Partial]`
- Current implementation:
  - มีการใช้ source weighting, cross-source, reliability gates, MITRE, actor extraction
  - รองรับรวมข้อมูลจากหลาย source ใน scorer
- มี explicit `validation_status`, `validation_reasons`, `warehouse_eligible`, `review_required`
- Gap:
  - ยังไม่มี provenance graph/trace สำหรับอธิบายว่า validation ผ่านเพราะ source ไหนแบบละเอียดระดับ operator UI
- Required closure:
  - เพิ่ม `validation_sources` หรือ source trace ที่ใช้ใน decision
  - ถ้าต้องมี review UI จริง ต้องมี queue/query contract เพิ่ม

### B2. Auto validation + manual path เมื่อไม่เข้าเงื่อนไขอัตโนมัติ
- TOR ref: หน้า 26 ข้อ 2.4, หน้า 27 ข้อ 2.5
- Status: `[Done]`
- Current implementation:
  - pipeline แยก `validated_auto`, `needs_review`, `rejected`
  - เขียนทุกผลลัพธ์ลง warehouse พร้อม review metadata
  - `needs_review` ใช้ warehouse document เดิมเป็น review queue
  - มี internal API สำหรับ list/approve/reject review queue ฝั่ง service แล้ว
- Evidence:
  - [validation.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/models/validation.py#L24)
  - [main.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/main.py#L487)
  - [main.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/main.py#L685)
  - [review_queue.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/services/review_queue.py#L46)
  - [rebuild_warehouse.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/scripts/ops/rebuild_warehouse.py#L61)
- Gap:
  - ยังไม่มี SLA/ownership สำหรับคนที่จะปิด review queue
- Required closure:
  - map internal review API เข้ากับ external API contract เมื่อ dashboard/search team ส่ง spec
  - เพิ่ม audit trail ของผู้อนุมัติ/เวลาที่อนุมัติ

## C. AI / ML Analytics

### C1. Threat classification / actor extraction / MITRE mapping
- TOR ref: หน้า 21 ข้อ 1.7, หน้า 26 ข้อ 2.2
- Status: `[Done]`
- Current implementation:
  - Hybrid language detection + zero-shot classification
  - threat actors from config
  - MITRE technique extraction
- Evidence:
  - [classifier.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/models/classifier.py#L1)
  - [scorer.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/models/scorer.py#L653)

### C2. Prioritization / risk ranking by severity and impact
- TOR ref: หน้า 22 ข้อ 2.4
- Status: `[Done]`
- Current implementation:
  - weighted scoring
  - reliability gates
  - sector multiplier
  - severity bands
- Evidence:
  - [scorer.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/models/scorer.py#L995)

### C3. Correlation analysis across multiple data sources
- TOR ref: หน้า 21 ข้อ 1.8
- Status: `[Partial]`
- Current implementation:
  - เรามี relation/fallback logic ฝั่ง API สำหรับ graph
  - แต่ยังไม่ใช่ persisted warehouse correlation model
- Gap:
  - ไม่มี correlation result ที่ถูกคำนวณแล้วเก็บเป็น warehouse artifact
  - ไม่มี correlation confidence / cluster / relationship summary ใน schema
- Required closure:
  - กำหนด correlation job ระดับ warehouse
  - persist เช่น `related_iocs`, `correlation_reason`, `relationship_strength`
  - แยกจาก graph API ชั่วคราวที่ currently build on read

### C4. Predictive model / forecasting
- TOR ref: หน้า 21 ข้อ 1.6-1.7, หน้า 27 ข้อ 4.3
- Status: `[Partial]`
- Current implementation:
  - มี forecasting modules และ dashboard analytics endpoint
  - ยังไม่เป็นส่วนหนึ่งของ production warehouse pipeline
- Evidence:
  - [trend_predictor.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/legacy/trend_predictor.py#L1)
- Gap:
  - `pipeline/run` ไม่เรียก forecasting
  - ไม่มี persisted prediction outputs ใน warehouse
  - ไม่มี periodic prediction job ชัดเจน
- Required closure:
  - ตัดสินว่า prediction เป็น:
    - batch analytics artifact
    - หรือ warehouse materialized dataset
  - เพิ่ม scheduled prediction run
  - versioning model + forecast metadata

### C5. Rule-based / ML / clustering support
- TOR ref: หน้า 21 ข้อ 1.7
- Status: `[Partial]`
- Current implementation:
  - มี AI classification + scoring rules
  - มี relationship fallback API
- Gap:
  - ยังไม่มี clustering/materialized grouping ใน production flow
  - campaign clustering ยังไม่ถูก implement จริง
- Required closure:
  - เพิ่ม optional clustering stage
  - เก็บ `cluster_label`, `campaign_guess`, `cluster_confidence`
  - ถ้ายังไม่ทำใน phase นี้ ต้องระบุเป็น deferred item ใน delivery note

### C6. Real-time processing
- TOR ref: หน้า 21 ข้อ 1.9
- Status: `[Missing]`
- Current implementation:
  - ปัจจุบันเป็น on-demand pipeline run
- Gap:
  - ไม่มี stream consumer / scheduler / event-driven worker
  - ยังพูดได้แค่ว่า `batch-capable`, ไม่ใช่ `real-time`
- Required closure:
  - เพิ่ม scheduler หรือ queue consumer
  - วัด latency SLA จาก datalake ingest -> warehouse availability

## D. Threat Data Warehouse Contract

### D1. Warehouse schema สำหรับ AI-enriched IOC
- TOR ref: หน้า 22 ข้อ 2.1-2.5
- Status: `[Done]`
- Current implementation:
  - schema รองรับ IOC identity, source metadata, timestamps, AI fields
- Evidence:
  - [elastic_client.py](/Users/mm/Desktop/ibusiness/Cyber/ai-service/elastic_client.py#L258)

### D2. Warehouse schema สำหรับ validation / cleansing / prediction metadata
- TOR ref: หน้า 21 ข้อ 1.3-1.9, หน้า 26 ข้อ 2
- Status: `[Partial]`
- Gap:
  - ตอนนี้มีแล้วสำหรับ:
    - `validation_status`
    - `validation_reasons`
    - `warehouse_eligible`
    - `review_required`
    - `sanitization_summary`
    - `cleaning_flags`
  - ยังไม่มี:
    - `correlation_summary`
    - `prediction_summary`
- Required closure:
  - เพิ่ม metadata ของ correlation/prediction ใน phase ถัดไป

### D3. Warehouse search/API readiness
- TOR ref: หน้า 27-28 ข้อ 4.4 และ 4.7
- Status: `[Partial]`
- Current implementation:
  - มี internal API ใช้งานจาก dashboard proof path แล้ว
- Gap:
  - ยังไม่มี final external API spec จาก dashboard/threat search team
- Required closure:
  - รอ API contract อย่างเป็นทางการ
  - ระหว่างนี้ lock internal response shape และ field naming ให้เสถียร

## E. Security / Governance Within Our Scope

### E1. Secure access / RBAC / HTTPS / 2FA / SSO
- TOR ref: หน้า 21 ข้อ 1.12-1.15, หน้า 22 ข้อ 2.6-2.8
- Status: `[Out]` สำหรับ UI/platform layer
- Note:
  - ในขอบเขตทีมเรา ควรรับผิดชอบอย่างน้อยเรื่อง API auth และ service-to-service auth
  - แต่ MFA/SSO/interactive access ไม่ใช่ส่วน AI/ML + Warehouse โดยตรง

### E2. Auditability ของ scoring/model versions
- TOR ref: สอดคล้องกับ TOR ด้านการวิเคราะห์/ตรวจสอบย้อนหลัง
- Status: `[Done]`
- Current implementation:
  - เก็บ `score_model_version`, `score_config_version`, breakdown

### E3. Long-term retention / forensic support
- TOR ref: หน้า 28 ข้อ 10
- Status: `[Partial]`
- Note:
  - ฝั่ง storage policy หลักเป็น data-lake/platform concern
  - แต่ warehouse ควรมี retention strategy / archive policy / replay capability สำหรับ backfill

## F. Deliverables We Should Prepare Even If Platform Team Owns UI

### F1. Technical design document: AI/ML pipeline + Warehouse schema
- TOR ref: หน้า 10 ข้อ 10.2, หน้า 11 ข้อ 10.4
- Status: `[Missing as repo artifact]`
- Required closure:
  - เอกสาร architecture flow
  - field dictionary
  - validation rules
  - model/risk methodology

### F2. Runbook / operations guide
- TOR ref: หน้า 11 ข้อ 10.4
- Status: `[Missing as repo artifact]`
- Required closure:
  - pipeline run
  - backfill
  - failure handling
  - key rotation
  - index migration

### F3. Source code handover completeness
- TOR ref: หน้า 12 ข้อ 10.5(6)
- Status: `[Partial]`
- Note:
  - source code มี
  - แต่ยังควรแยกให้ชัดว่าอะไรเป็นของเราและอะไรเป็นของ third party
  - ต้องแนบ dependency/setup instructions ให้ deploy ซ้ำได้

## Recommended Closure Order

### Phase 1: Must close before claiming TOR compliance in our scope
- เพิ่ม `validation workflow` แบบ auto/manual review
- เพิ่ม `PII/confidential data sanitization`
- ขยาย warehouse schema สำหรับ validation + cleansing metadata
- ออกเอกสาร AI/ML + Warehouse design/runbook

### Phase 2: Close to reduce compliance risk
- materialize `correlation analysis` ลง warehouse
- ทำ `prediction job` ให้เป็น production path
- เพิ่ม scheduled/near-real-time execution

### Phase 3: Nice-to-have / depends on upstream-downstream contracts
- final API contract สำหรับ Dashboard / Threat Search
- handoff docs ระหว่าง Data-Lake supplier -> AI/ML supplier -> UI supplier

## Bottom Line

ถ้าประเมินเฉพาะขอบเขตทีมเรา:
- ส่วน `classification + scoring + warehouse enrichment` อยู่ระดับ `ใช้งานได้`
- แต่ส่วน `validation`, `data cleansing / PII removal`, และ `production-grade prediction/correlation workflow` ยังไม่ปิด TOR

ดังนั้นสถานะโดยรวมควรสื่อสารว่า:
- `AI enrichment and warehouse persistence: mostly ready`
- `TOR compliance for AI/ML + Warehouse: partial, not yet complete`
