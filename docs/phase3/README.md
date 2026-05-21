# Phase 3 — ตรวจสอบความถูกต้องเชิงความหมายของข้อมูล (Semantic Data Correctness Audit)

ตรวจสอบว่า **ทุก label/ตัวเลขที่แสดงบนหน้า dashboard** ตรงกับข้อมูลที่ดึงมาจาก data warehouse (`.43`) ผ่าน ES query ที่ถูกต้องจริงๆ

**ขอบเขต:** แก้เฉพาะ backend (`ai-service`) — **ห้ามแก้ frontend (`ncsa-dashboard-web`) ใดๆ ทุกหน้า**
ถ้า label บนหน้าเว็บไม่ชัดเจน → ถามผู้ใช้ก่อน อย่าตัดสินใจเอง

**Branch:** `audit/phase3-semantic-data`

**Ground truth fixtures (ดึงจาก ES จริง):** `ai-service/tests/semantic/fixtures/`

| ไฟล์ | คำอธิบาย |
|------|---------|
| `es_mapping_warehouse.json` | Field types ของ warehouse (.43) |
| `es_mapping_datalake.json` | Field types ของ datalake (.41) |
| `sample_warehouse.json` | ตัวอย่าง 5 documents ล่าสุดจาก warehouse |
| `sample_datalake.json` | ตัวอย่าง 5 documents ล่าสุดจาก datalake |
| `warehouse_field_distribution.json` | การกระจายค่าของ field สำคัญ จากข้อมูล 11.09M docs |

## ความคืบหน้า

| Sub | หน้า | สถานะ | เอกสาร | Bugs ที่แก้ |
|-----|------|--------|--------|------------|
| 3.0 | Cross-cutting helpers | ✅ เสร็จ | [3.0-cross-cutting-helpers.md](./3.0-cross-cutting-helpers.md) | 3 (1 CRITICAL, 1 HIGH, 1 MED) |
| 3.1 | Executive Dashboard | ⏳ รอ | — | — |
| 3.2 | Operations Dashboard | ⏳ รอ | — | — |
| 3.3 | TI Overview + IOC Summary | ⏳ รอ | — | — |
| 3.4 | Threat Landscape | ⏳ รอ | — | — |
| 3.5 | IOC Datalake / Analytics / Threat Hunting | ⏳ รอ | — | — |
| 3.6 | TI sub-pages (×6) | ⏳ รอ | — | — |
| 3.7 | Action Center / Reports / News / CVE | ⏳ รอ | — | — |
| 3.8 | Settings / lookups / auth | ⏳ รอ | — | — |

## รูปแบบเอกสารต่อหน้า (per-page document format)

ทุกไฟล์ `3.X-<page>.md` มีโครงสร้างเดียวกัน:

```
# 3.X — <ชื่อหน้า>

## หน้า/Routes ที่ตรวจ
- Frontend: <path ของไฟล์ .tsx>
- API endpoints: <list>

## ตารางตรวจ label (semantic map)

| Label ที่หน้าเว็บ | Response path | Backend function | ES field | ES agg | สูตรคำนวณ / ความหมาย | Verified | Bug? |
|------------------|---------------|------------------|----------|--------|---------------------|----------|------|

## Bugs ที่พบ
- <severity> · <สรุปสั้น> · <commit hash ของ fix>

## เลื่อนทำ / Data quality notes
- ...
```

## Baseline ของข้อมูลจริง (จาก `warehouse_field_distribution.json` — 11.09M docs)

ค่าจริงในตอนนี้บนระบบ — ใช้เป็นจุดอ้างอิงเวลา trace label ↔ query

- **severity** (และ `ai_severity`): `low` 11M / `medium` 40K / `critical` 8.6K / `high` **มีแค่ 1 doc**
- **ioc_type**: `sha256` 90% / `url` 6% / `ip` 2.6% / `domain` 1.4% / md5+sha1 รวม 4 docs
- **source_name**: `cyberint_iocs` 99.99% (แทบเป็น single-source)
- **validation_status**: `validated` 96.6% / `rejected` 3.4%
- **review_state**: `not_required` 99.99% / `pending_review` 1 doc
- **action_status**: `open` 96.7% / MISSING 3.3% (ไม่มี `closed`/`in_progress` — workflow ไม่ถูกใช้)
- **tlp**: `amber` 100% (ระบบ TLP gating ที่ Phase 2 อุดไว้ — ยังไม่เคยมีข้อมูล non-amber)
- **warehouse_eligible**: `true` 96.6% / `false` 3.4% (= 1:1 กับ `validation_status`)
- **geo_country**: ค่า `"None"` (string) 97.3% / MISSING 2.0% / ISO codes จริง **เพียง 0.4%**
- **target_sector**: MISSING 97.9% / `general` 1.9% / อื่นๆ <0.1%
- **target_sector_name**: MISSING 97.9% / `Other` 1.9% / อื่นๆ <0.1%
- **ai_threat_types**: `Malware` 96.7% / `Phishing` 3.3% / smaller types ปนกัน case
- **threat_type**: snake_case ครอง (`malware_payload` 94%) แต่ปนกับ Title Case (`Phishing` 894, `Malware` 61) — **data inconsistency จาก ingestion**

⚠️ **ผลกระทบ:** chart ที่แสดง "Top Attack Origins" หรือ "Target Sectors" จริงๆ จะเห็นข้อมูลจาก doc ส่วนน้อยมาก (0.4% และ 2%) — UI สวยแต่ representativeness ต่ำ

## Time fields ที่มีจริงในระบบ (เช็ค existence จาก 11.09M docs)

| Field | จำนวน docs ที่มีค่า | Mode | สถานะ |
|-------|---------------------|------|------|
| `event_time` | 11,094,748 (100%) | observed | ✅ ใช้ได้ |
| `first_seen` | 11,094,748 (100%) | observed | ✅ ใช้ได้ |
| `last_seen` | 11,094,748 (100%) | observed | ✅ ใช้ได้ |
| `last_shared_at` | 11,094,748 (100%) | changed | ✅ ใช้ได้ |
| `action_updated_at` | 10,725,075 (96.7%) | changed | ✅ ใช้ได้ |
| `reviewed_at` | 0 (ไม่มีค่าเลยสักตัว!) | — | ❌ field ว่างเสมอ |
| `revoked_at` | **ไม่อยู่ใน mapping** | — | ❌ ไม่มี field |
| `updated_at` | **ไม่อยู่ใน mapping** | — | ❌ ไม่มี field |
