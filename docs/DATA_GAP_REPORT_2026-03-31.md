# รายงานช่องว่างข้อมูล (Data Gap Analysis)

## 1. การกระจายแหล่งข้อมูล (Data Source Distribution)

**จำนวนข้อมูลทั้งหมด: 2,006 records**

| แหล่งข้อมูล | จำนวน | % | ประเภท | สถานะ |
|-------------|-------|---|--------|-------|
| TheHackerNews | 1,065 | **53.1%** | news | ⚠️ อยู่ใน NEWS_SOURCES — CVE ผ่าน, non-CVE ไม่มี description ถูก Reject |
| Zone-H | 561 | **28.0%** | feed | ❌ ไม่อยู่ใน Trusted/News Sources → ถูก Reject ทั้งหมด |
| DarkReading | 312 | **15.6%** | news | ⚠️ อยู่ใน NEWS_SOURCES — CVE ผ่าน, non-CVE ไม่มี description ถูก Reject |
| ไม่ระบุ (empty) | 35 | 1.7% | - | ❌ Invalid — จะถูก Reject ทันที |
| Suricata IDS | 22 | 1.1% | suricata | ✅ อยู่ใน Trusted Sources |
| Sandbox | 6 | 0.3% | sandbox | ✅ อยู่ใน Trusted Sources |
| BleepingComputer | 5 | 0.2% | news | ⚠️ อยู่ใน NEWS_SOURCES — CVE ผ่าน (ถ้ามี), non-CVE ไม่มี description ถูก Reject |

**ปัญหาหลัก:** ระบบนิยาม "Trusted Sources" ไว้ใน `config.py` (VirusTotal, AbuseIPDB, AlienVault, ThreatFox, URLhaus, MalwareBazaar ฯลฯ) **ข้อมูลที่ได้รับมาไม่มี external Trusted Sources เลย** (Suricata/Sandbox เป็น internal sensor 28 records คิดเป็น 1.4% เท่านั้น) ส่งผลโดยตรงต่อ Validation Policy

**วิธีคิด Validated / Rejected (`validation.py`):**

record จะได้สถานะ `validated` ต่อเมื่อผ่านเงื่อนไขใดเงื่อนไขหนึ่งต่อไปนี้:

- **เส้นทาง A — Trusted Source:** ต้องครบทุกข้อ:
  - มาจาก TRUSTED_SOURCES ≥ 1 แหล่ง
  - NLP confidence ≥ 0.45
  - อย่างน้อยหนึ่งข้อ: risk score ≥ 25 **หรือ** source ≥ 2 แหล่ง **หรือ** source diversity ≥ 2

- **เส้นทาง B — Editorial/CVE:** ต้องครบทุกข้อ:
  - มาจาก NEWS_SOURCES เท่านั้น (ไม่มี Other source ปน)
  - อย่างน้อยหนึ่งข้อ: IOC type เป็น `cve` **หรือ** source ≥ 2 แหล่ง **หรือ** NLP confidence ≥ 0.60

record จะได้สถานะ `rejected` ทันทีหาก:
- ไม่มี IOC value หรือไม่มี source
- ไม่ผ่านทั้งสองเส้นทางข้างต้น

---

## 2. การกระจายประเภท IOC (IOC Type Distribution)

| ประเภท IOC | จำนวน | % | หมายเหตุ |
|-----------|-------|---|---------|
| CVE | 1,090 | **54.3%** | Auto-validated แต่ไม่มี NLP context |
| URL | 340 | 16.9% | Zone-H defacement URLs |
| Domain | 284 | 14.2% | มี WHOIS บางส่วน |
| IP | 247 | 12.3% | มี IP enrichment บางส่วน |
| ไม่ระบุ (empty) | 35 | 1.7% | ❌ Invalid |
| Hash (MD5/SHA1/SHA256) | 10 | 0.5% | จาก Sandbox และ Suricata |

**ข้อสังเกต:** CVE ครอง 54% ของข้อมูล — CVE มีกฎ Auto-validate จึงผ่านได้ แต่คุณภาพ classification ต่ำมากเนื่องจากไม่มี description text

---

## 3. โมเดล AI/ML ที่ได้รับผลกระทบ

| โมเดล / อัลกอริทึม | ผลกระทบ | ระดับ |
|------------------|---------|-------|
| **DeBERTa NLP Classifier** | ทำงานไม่ได้ 100% ของข้อมูล (description ว่างทุก record) | 🔴 Critical |
| **BGE-M3 Multilingual Classifier** | เช่นเดียวกัน (ใช้ description เดียวกัน) | 🔴 Critical |
| **Risk Scorer (8 factors)** | 5 ใน 8 factors ทำงานได้บางส่วนหรือไม่ได้เลย | 🔴 Critical |
| **Validation Model** | Zone-H ถูก Reject ทั้งหมด, news non-CVE ถูก Reject เนื่องจาก NLP confidence = 0 | 🔴 Critical |
| **HDBSCAN Clusterer** | Feature vectors เป็น near-zero → clustering ไม่มีความหมาย | 🟠 High |
| **Relationship Graph** | Graph จะ sparse ไม่มี actor/technique links | 🟠 High |
| **Holt-Winters Forecaster** | ถ้า validated records ต่ำ → ไม่มีข้อมูลพอสำหรับ forecast | 🟡 Medium |

### รายละเอียด Risk Scorer (8 factors)

| Factor | Weight | สถานะกับข้อมูลปัจจุบัน |
|--------|--------|----------------------|
| cross_source | 0.25 | ⚠️ ส่วนใหญ่ single source → score ต่ำ |
| threat_type_severity | 0.20 | ❌ 95.6% ไม่มี threat_type |
| threat_intel_source | 0.15 | ⚠️ ทุก source เป็น news (ความน่าเชื่อถือต่ำ) |
| high_risk_keywords | 0.10 | ❌ 95.6% ไม่มี description → keyword matching ไม่ทำงาน |
| domain_age | 0.10 | ❌ 72% ไม่มี enrichment → age = None |
| threat_actor | 0.10 | ❌ ขึ้นอยู่กับ NLP → ทำงานไม่ได้ |
| entropy | 0.05 | ✅ ทำงานได้สำหรับ domain/url (31.1%) |
| mitre_techniques | 0.05 | ❌ ขึ้นอยู่กับ NLP → ทำงานไม่ได้ |

**สรุป:** ระบบ scoring ทำได้สูงสุดแค่ ~45% ของ capacity จริง (เฉพาะ cross_source + threat_intel_source + entropy รวมกัน = 0.25 + 0.15 + 0.05)

---

## 4. API Endpoints ที่ได้รับผลกระทบ

### Dashboard API (`/api/v1/`)

| Endpoint | ผลกระทบ |
|---------|---------|
| `GET /api/v1/executive/dashboard` | ⚠️ KPI ต่ำผิดปกติ, ไม่มี threat actor breakdown, trend ไม่แม่นยำ |
| `GET /api/v1/operations/dashboard` | ⚠️ severity distribution บิดเบือน (ส่วนใหญ่ rejected), sector ว่าง |
| `GET /api/v1/iocs` | ⚠️ filter by threat_type/severity/sector คืนผลน้อยมาก |
| `GET /api/v1/ioc-analytics` | ⚠️ aggregate stats ไม่สะท้อนความจริง |
| `GET /api/v1/operations/reports/{key}` | ⚠️ ข้อมูลใน report ไม่ครบ |
| `POST /api/v1/reports/executive/preview` | ⚠️ executive report ขาดข้อมูล AI-classified |
| `POST /api/v1/reports/executive/export` | ⚠️ executive report ขาดข้อมูล AI-classified |
| `POST /api/v1/reports/operations/*/preview` | ⚠️ ข้อมูลใน report ไม่ครบ |

### AI Service API (port 8000)

| Endpoint | ผลกระทบ |
|---------|---------|
| `POST /classify` | ⚠️ คืนผลว่างสำหรับ records ที่ไม่มี description |
| `POST /score` | ⚠️ คะแนนต่ำกว่าความเป็นจริง |
| `POST /enrich` | ⚠️ คุณภาพต่ำ (รวมผลกระทบจากทุกปัญหาข้างต้น) |
| `POST /enrich/batch` | ⚠️ คุณภาพต่ำ (รวมผลกระทบจากทุกปัญหาข้างต้น) |
| `POST /pipeline/run` | ⚠️ รันได้ แต่ warehouse ที่ได้มีคุณภาพต่ำ |


---

## 5. สรุปและข้อเสนอแนะสำหรับผู้บริหาร

**ระบบ TCTI พร้อมทำงานในเชิงเทคนิค** — AI pipeline, scoring, validation, clustering, dashboard ทุกอย่างสร้างเสร็จแล้ว อุปสรรคหลักคือคุณภาพข้อมูลที่ได้รับ ระบบจะทำงานได้เต็มประสิทธิภาพเมื่อได้รับข้อมูลตามข้อกำหนดต่อไปนี้

---

| # | สิ่งที่ขาด | ผลกระทบ | สิ่งที่ต้องการ |
|---|-----------|---------|--------------|
| 1 | `description` ว่างทุก record (100%) | NLP ทำงานไม่ได้ทั้งหมด — ai_threat_types, ai_threat_actors, ai_mitre_techniques = ว่าง | ส่ง description ที่มีความหมายทุก record |
| 2 | Enrichment ขาดหาย 72% | domain_age, geo_country, NLP context ว่าง | ส่ง WHOIS + IP geolocation ครบสำหรับทุก IOC ประเภท domain/ip |
| 3 | `confidence` ว่าง 70.2% | validation signal หาย — ระบบถือเป็น 0 | ส่งค่าตัวเลข 0–100 ทุก record |
| 4 | ไม่มี external Trusted Sources เลย | records ที่ผ่านได้มีเฉพาะ CVE, risk score ต่ำกว่าความเป็นจริง | เพิ่ม feeds: VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar, PhishTank |
| 5 | IOC types ไม่หลากหลาย — มีเฉพาะ CVE และ defacement | ไม่สะท้อน threat landscape จริง | เพิ่มข้อมูล malware hash, phishing URL, C2 IP/domain, APT indicators |
| 6 | `related_hash` / `related_domain` ว่างทุก record | Relationship Graph ไม่มี link ใดๆ | ระบุ hash/domain ที่เชื่อมโยงกับ IOC ถ้ามี |
| 7 | Zone-H ไม่อยู่ใน Trusted/News Sources | ถูก Reject ทั้งหมด 561 records (28%) | ต้องตกลงร่วมกันว่าจะจัด Zone-H อยู่ใน group ใด หรือยอมรับว่าข้อมูลส่วนนี้จะไม่เข้า warehouse |

---

*รายงานนี้จัดทำจากการวิเคราะห์ไฟล์ `source-enrichment-23032026.json.bak` (2,006 records) และซอร์สโค้ดระบบ TCTI ทั้งหมด*
*วันที่: 31 มีนาคม 2026*
