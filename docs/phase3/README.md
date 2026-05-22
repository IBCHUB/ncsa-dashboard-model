# Phase 3 — ตรวจสอบความถูกต้องของตัวเลขบน Dashboard

ตรวจสอบว่า **ตัวเลข/chart/list ที่แสดงบนหน้าเว็บ ตรงกับสูตรที่ควรเป็น** หรือไม่ —
ดึงข้อมูลถูก field ไหม นับถูกหลักเกณฑ์ไหม

**ขอบเขต:** แก้ backend (`ai-service`) เท่านั้น — **ห้ามแก้ frontend ใดๆ**

**Branch:** `audit/phase3-semantic-data`

## ความคืบหน้า

| Sub | หน้า / สิ่งที่ตรวจ | สถานะ | เอกสาร | Bugs ที่แก้ |
|-----|-------------------|--------|--------|------------|
| 3.0 | สูตรกลาง / helper ที่หลายหน้าใช้ร่วมกัน | ✅ เสร็จ | [3.0-cross-cutting-helpers.md](./3.0-cross-cutting-helpers.md) | 3 (CRITICAL 1, HIGH 1, MED 1) |
| 3.1 | Executive Dashboard (`/admin/executive`) | ✅ เสร็จ (audit only, ไม่มี bug ใหม่) | [3.1-executive-dashboard.md](./3.1-executive-dashboard.md) | 0 (Phase 3.0 ครอบคลุมแล้ว) |
| 3.2 | Operations Dashboard (`/admin/operations`) | ⏳ รอ | — | — |
| 3.3 | Threat Intelligence — Overview + IOC Summary (`/admin/threatintelligence`) | ⏳ รอ | — | — |
| 3.4 | Threat Landscape (`/admin/threatlandscape`) | ⏳ รอ | — | — |
| 3.5 | IOC Datalake / Analytics / Threat Hunting | ⏳ รอ | — | — |
| 3.6 | TI sub-pages (×6) | ⏳ รอ | — | — |
| 3.7 | Action Center / Reports / News / CVE | ⏳ รอ | — | — |
| 3.8 | Settings / lookups / auth | ⏳ รอ | — | — |

## รูปแบบเอกสารต่อหน้า (per-page document format)

ทุกไฟล์ `3.X-<page>.md` ใช้โครงสร้างเดียวกัน — มุมมอง **product/QA** ไม่ใช่ dev:

```
# 3.X — <ชื่อหน้า>

## หน้าเว็บที่ตรวจ
- ชื่อหน้า: <ชื่อตรงตามที่แสดงบน UI>
- URL: /admin/...

## API endpoints ที่หน้านี้เรียก (checklist)
- [x] GET /api/v1/...  ← ใช้แสดง: <label / chart ไหน>
- [x] POST /api/v1/...
- [ ] GET /api/v1/... ← ยังไม่ตรวจ
รวม N เส้น, ตรวจแล้ว M/N

## รายการตัวเลข/chart ที่ตรวจ

| Label บนหน้าเว็บ | ที่แสดงเป็นอะไร | API endpoint | สูตรคำนวณ (ภาษาคน) | แหล่งข้อมูล | ถูกไหม | หมายเหตุ |
|----------------|----------------|--------------|--------------------|-------------|--------|---------|

## Bugs ที่พบ
| # | Severity | Label ที่กระทบ | API endpoint | ปัญหา | สถานะ |

## ข้อสังเกต / Data quality
| # | ประเด็น | ผลต่อหน้าเว็บ |
```

### หลักการใส่ API endpoint

- ใช้ path + method ตามที่เห็นใน frontend (`lib/api/*.ts`) เช่น `GET /api/v1/operations/dashboard`
- ถ้า endpoint หนึ่งให้ข้อมูลหลาย label — ใส่ endpoint ซ้ำในหลายแถว
- ถ้า label หนึ่งคำนวณจากหลาย endpoint — รวมในช่องเดียวด้วย `+` เช่น `GET /a + GET /b`
- ใน checklist รายการ endpoint ใช้ `[x]` = ตรวจแล้ว / `[ ]` = ยังไม่ตรวจ — บอก progress รวมไว้ท้าย

### หลักการเขียน "สูตรคำนวณ (ภาษาคน)"

เขียนให้คน non-dev อ่านเข้าใจ — เช่น:
- ✅ **ดี**: "นับ IOC ที่ AI ประเมินว่าเป็น Critical และยังไม่ถูกปิด"
- ❌ **ไม่ดี**: "count(docs WHERE ai_severity='critical' AND action_status='open')"

ถ้าจำเป็นต้องใช้ field name ให้ใส่ในวงเล็บท้าย เช่น
"นับ IOC severity = Critical ที่ status ยังเปิดอยู่ *(severity=critical, action_status=open)*"

### หลักการเขียน "ถูกไหม"

- ✅ ตรงตามที่ label หน้าเว็บสื่อความหมาย
- ⚠️ ตรงแต่มี caveat (เช่น nullable field → coverage ต่ำ)
- ❌ ผิด — ดู Bugs ที่พบ

## ข้อจำกัดของข้อมูลจริงในปัจจุบัน (ใช้อ้างอิงตอนตรวจทุกหน้า)

ข้อมูลใน warehouse 11.09M docs ปัจจุบัน:

| เรื่อง | สิ่งที่เห็น | ผลต่อ dashboard |
|------|-----------|----------------|
| **severity** | low 11M / medium 40K / critical 8.6K / high **มีแค่ 1 doc** | บัตเชอวร์ "High" บนหน้าเว็บจะแสดงตัวเลขใกล้ศูนย์เสมอ |
| **TLP** | amber 100% | ระบบ TLP gating ที่ Phase 2 อุดไว้ — ยังไม่เคย filter ข้อมูลจริง |
| **ประเทศ (geo_country)** | 99.4% เป็น "None"/MISSING — ค่าจริงแค่ 0.4% | "Top Attack Origins" แสดงจาก doc 0.4% ของทั้งหมด |
| **Sector** | 97.9% MISSING — มีค่าจริงแค่ 2% | "Target Sectors" แสดงจาก doc 2% ของทั้งหมด |
| **Source** | cyberint_iocs 99.99% | "Top Intelligence Sources" = Cyberint แทบจะอย่างเดียว |
| **Action status** | open 96.7% / MISSING 3.3% (ไม่มี closed/in_progress) | workflow "Action Center" ไม่ถูกใช้งานจริง |

## Ground truth fixtures ที่ใช้อ้างอิง

`ai-service/tests/semantic/fixtures/`
- `es_mapping_warehouse.json` — โครงสร้าง field warehouse จริง
- `es_mapping_datalake.json` — โครงสร้าง field datalake จริง
- `sample_warehouse.json` — 5 documents ล่าสุด
- `warehouse_field_distribution.json` — จำนวนค่าแต่ละ field
