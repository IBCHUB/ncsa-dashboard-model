# TOR/MOM Compliance Review + AI Scoring Logic Assessment

**Project:** Thailand Cyber Threat Intelligence (TCTI)  
**Date:** 2026-02-08  
**Scope:** ตรวจ TOR/MOM ใน `tor/doc1.txt`, `tor/doc2.txt`, `tor/doc3.txt` เทียบ implementation ทั้ง Python (`ai-service`) และ Next.js (`dashboard`) + วิเคราะห์ logic risk score จาก `ai-service/docs/AI-SCORING.md`

---

## 1) Executive Summary

ภาพรวมระบบมีองค์ประกอบหลักครบ (IOC explorer, map, graph, export, AI service, ETL) แต่ยังมี gap สำคัญที่กระทบความถูกต้องและความพร้อมใช้งานระดับหน่วยงานรัฐ:

- พบ **P0** 2 ประเด็น: คะแนน AI เขียนเข้า warehouse ผิด key และ cross-source pipeline ไม่เป็นไปตาม requirement
- พบ **P1** หลายจุด: auth/2FA, public/internal split, real-time data consistency, alerts persistence
- logic risk score มีจุดดีด้าน explainability แต่ยังมีความเสี่ยงด้าน calibration, double-counting, false-positive และ governance

---

## 2) TOR/MOM Compliance Matrix (ย่อ)

| Requirement | Status | Evidence | Impact |
|---|---|---|---|
| Cross-check IOC กับทุกแหล่งข้อมูลภายในทั้งหมด | Not Met | `tor/doc2.txt:52`, `ai-service/main.py:494`, `ai-service/elastic_client.py:247`, `ai-service/scripts/import_to_datalake.py:176` | คะแนนความน่าเชื่อถือบิดเบือน |
| Raw / Processed / Warehouse 3 ชั้น (ELK) | Partially Met | `tor/doc2.txt:44`, `ai-service/elastic_client.py:18` | ขาด processed layer ที่เป็นจุด validate/backup |
| Dashboard filter ช่วงเวลา + Top 10 + Drill-down | Partially Met | `tor/doc2.txt:67`, `tor/doc2.txt:69`, `dashboard/src/app/reports/page.tsx:17`, `dashboard/src/app/api/iocs/route.ts:219` | รายงาน/filter ไม่ตรง requirement |
| Public/Internal split + login + 2FA | Not Met | `tor/doc1.txt:25`, `tor/doc3.txt:45`, `dashboard/src/components/layout/Sidebar.tsx:149` | ไม่ผ่าน requirement สิทธิ์เข้าถึง |
| Arc map โจมตีเข้าไทย | Met | `tor/doc3.txt:40`, `dashboard/src/components/widgets/ThreatMap.tsx:94` | ตรง requirement |
| Export Suricata/Snort/CSV/JSON | Met | `tor/doc1.txt:24`, `dashboard/src/app/reports/page.tsx:304` | ตรง requirement |
| HelpDesk integration | Partially Met | `ai-service/main.py:395`, `ai-service/integrations/helpdesk.py:23` | มี flow แต่ default เป็น mock |

---

## 3) Findings (เรียงตามความรุนแรง)

###[P0] AI risk score เขียนเข้า warehouse ผิด key
- `ai-service/main.py:533` ใช้ `score_result.get("total_score", 0)`
- scorer คืน key เป็น `risk_score` (`ai-service/models/scorer.py:865`)
- ผล: `ai_risk_score` ใน warehouse เสี่ยงเป็น `0` ทั้งที่ model คำนวณแล้ว

###[P0] Cross-source validation ไม่ทำงานจริงตาม MOM
- ใน pipeline ส่ง sources แค่ source เดียว (`ai-service/main.py:494`)
- import ลง datalake ใช้ `ioc_value` เป็น document id (`ai-service/scripts/import_to_datalake.py:176`)
- index datalake/warehouse ก็ dedupe ด้วย `ioc_value` (`ai-service/elastic_client.py:247`, `ai-service/elastic_client.py:216`)
- ผล: IOC เดียวที่พบหลาย source ถูกทับ/สูญข้อมูล source-level

###[P1] Reports filter หลายค่าและช่วงเวลาไม่ทำงานครบ
- UI ส่ง `type=a,b` และ `severity=x,y` (`dashboard/src/app/reports/page.tsx:45`, `dashboard/src/app/reports/page.tsx:48`)
- API filter แบบค่าเดียว (`dashboard/src/app/api/iocs/route.ts:219`, `dashboard/src/app/api/iocs/route.ts:224`)
- `dateFrom/dateTo/reportType` ยังไม่ถูกนำไปใช้จริง (`dashboard/src/app/reports/page.tsx:17`, `dashboard/src/app/reports/page.tsx:22`, `dashboard/src/app/reports/page.tsx:122`)

###[P1] AuthN/AuthZ ตาม TOR ยังไม่ครบ
- TOR ต้อง Two-Factor Authentication (`tor/doc1.txt:25`)
- ปัจจุบัน AI service ใช้ API key (`ai-service/main.py:50`)
- Dashboard role/login ยังเป็น type + mock UI (`dashboard/src/lib/types/index.ts:373`, `dashboard/src/components/layout/Sidebar.tsx:149`)
- ไม่พบ enforcement route-level public/internal จริง

###[P1] ข้อมูลหลายหน้าไม่ real-time จาก warehouse เดียวกัน
- Threat level อ่าน static `/data/sectors.json` (`dashboard/src/components/widgets/ThreatLevel.tsx:49`)
- trend widgets อ่าน static `/data/predictions.json` (`dashboard/src/components/widgets/TrendPrediction.tsx:42`, `dashboard/src/components/widgets/TrendChart.tsx:53`)
- หลาย API route อ่านไฟล์ `public/data` เป็นหลัก

###[P1] Alerts lifecycle ไม่ persist
- `dashboard/src/app/alerts/page.tsx:53` เปลี่ยนสถานะใน local state เท่านั้น
- ไม่มี backend state machine, assignment, audit, SLA tracking

###[P1] Security hardening ยังไม่พอ
- CORS ใช้ `"*"` พร้อม `allow_credentials=True` (`ai-service/main.py:41`, `ai-service/main.py:42`)
- มี default API keys ในโค้ด (`ai-service/config.py:18`)

###[P2] Severity/ThreatType ใน dashboard บางหน้าไม่ใช้ AI field
- CVE page filter/render ใช้ `cve.severity` ไม่ใช่ `aiSeverity` (`dashboard/src/app/threats/cve/page.tsx:37`, `dashboard/src/app/threats/cve/page.tsx:139`)
- stats threat categories ใช้ `event.threat_type` ไม่ใช่ `aiThreatTypes` (`dashboard/src/app/api/stats/route.ts:136`)

###[P2] เอกสารกับ API จริงไม่ตรงกัน
- docs/README เรียก `/pipeline/run` ด้วย `batch_size` (`docs/API.md:212`, `README.md:222`)
- API จริงใช้ `limit` (`ai-service/main.py:438`)

---

## 4) Risk Score Logic Review (จาก AI-SCORING.md + scorer.py)

## 4.1 จุดที่ทำได้ดี

- มี breakdown รายปัจจัยและ reason/methodology ชัดเจน (audit ได้ง่าย)
- มีการใช้หลายมิติ (source, keyword, threat type, actor, MITRE, entropy, domain age)
- มี decay factor ลดคะแนน IOC เก่า (`ai-service/models/scorer.py:757`)
- มี sector-aware bonus (`ai-service/models/scorer.py:844`)

## 4.2 จุดที่ควรปรับปรุงเชิง logic

1. **Document vs Code ไม่ sync**
- `AI-SCORING.md` ระบุ Cross-Source max 25 (`ai-service/docs/AI-SCORING.md:29`) แต่โค้ด max 40 (`ai-service/models/scorer.py:145`)
- `AI-SCORING.md` ระบุ Source Quality max 15 (`ai-service/docs/AI-SCORING.md:43`) แต่โค้ด max 40 (`ai-service/models/scorer.py:122`)
- `AI-SCORING.md` ระบุ Keywords max 20 (`ai-service/docs/AI-SCORING.md:138`) แต่โค้ด max 25 (`ai-service/models/scorer.py:88`)
- `AI-SCORING.md` สูตรรวมไม่ครอบคลุม normalization + sector bonus (`ai-service/docs/AI-SCORING.md:14`, เทียบ `ai-service/models/scorer.py:752`, `ai-service/models/scorer.py:844`)

2. **`SCORING_WEIGHTS` มีแต่ไม่ถูกใช้จริง**
- มีใน config (`ai-service/config.py:54`) และ import (`ai-service/models/scorer.py:20`) แต่ไม่ได้ถูกนำมาคำนวณ
- ผล: governance บอกว่า “ปรับน้ำหนักได้” แต่พฤติกรรมจริงไม่เปลี่ยน

3. **Potential double-counting ระหว่าง Cross-Source กับ Source Quality**
- สองปัจจัยต่างก็ให้คะแนนจาก source set เดียวกัน (`ai-service/models/scorer.py:530`, `ai-service/models/scorer.py:548`)
- เสี่ยง overweight “จำนวนแหล่ง” มากเกินไป

4. **Keyword matching เป็น substring ตรงๆ**
- ใช้ `if keyword.lower() in text_lower` (`ai-service/models/scorer.py:84`)
- เสี่ยง false positive จาก token ที่ซ้อนกัน

5. **Confidence bonus อาจขยาย model bias**
- threshold ค่อนข้างใจดี (>=0.6 ก็ได้โบนัส) (`ai-service/models/scorer.py:474`)
- ถ้า classifier overconfident จะลาก score สูง

6. **Decay factor ใช้ไม่สม่ำเสมอทุก flow**
- scorer รองรับ `ioc_age_days` (`ai-service/models/scorer.py:500`) แต่ `/enrich` และ `/pipeline/run` ไม่ส่งค่าอายุ IOC
- decay ถูกใช้ใน ingestion script แต่ไม่ทั่วถึง runtime path

7. **MITRE extraction coverage จำกัด**
- extractor ดึงเฉพาะ pattern `Txxxx` (`ai-service/models/classifier.py:270`)
- ถ้า source มีแต่ tactic names โดยไม่ใส่ ID อาจพลาดคะแนน MITRE

8. **Severity mapping ไม่แยก “clean” ชัดในเอกสาร**
- code มี `clean` เมื่อคะแนน = 0 (`ai-service/models/scorer.py:789`)
- เอกสาร severity table ระบุ 0-24 เป็น low (`ai-service/docs/AI-SCORING.md:209`)

9. **Sector bonus ควรถูกกำกับเชิงนโยบาย**
- บวก 0-15 แบบเด็ดขาด (`ai-service/models/scorer.py:845`)
- ถ้า sector classifier ผิด อาจเร่ง escalation เกินจริง

10. **Pipeline bug ทำให้ review scoring ในภาพรวมผิดจากความจริง**
- ประเด็น key ผิด (`ai-service/main.py:533`) ทำให้ AI score ใน warehouse ไม่สะท้อน logic จริง

---

## 5) ถ้าผมเป็น สกมช. จะเห็นอย่างไร

มุมมอง “หน่วยงานกำกับ + ผู้ใช้งานปฏิบัติการ”:

1. **รับแนวคิดได้** เพราะระบบมี explainability สูงและรองรับการตรวจสอบย้อนหลัง
2. **ยังไม่ควรรับ production acceptance** จนกว่า P0/P1 จะปิด โดยเฉพาะ cross-source, auth/2FA, data consistency
3. **ต้องบังคับ Score Governance**
- ต้องมี score versioning (เช่น `score_model_version`, `score_config_version`)
- ทุก score ต้อง trace กลับไปยัง source evidence จริงได้
- เปลี่ยน threshold/logic ต้องผ่าน change control
4. **ต้องมี model/rule calibration บนข้อมูล incident จริงของประเทศ**
- รายงาน precision/recall หรืออย่างน้อย confusion matrix ต่อ severity bucket
- รีวิว false positive/false negative เป็นรอบ (รายเดือน/รายไตรมาส)
5. **ต้องมี policy ลด false escalation**
- ห้ามขึ้น High/Critical หากมาจาก news-only โดยไม่มี internal corroboration
- ใช้ rule gate ก่อนส่ง HelpDesk/ticket อัตโนมัติ

---

## 6) ข้อเสนอปรับปรุง Risk Score (เชิงปฏิบัติ)

1. **Fix consistency ก่อน**
- แก้ key `total_score` -> `risk_score`
- ทำ source-level storage ไม่ทับกัน (event-level id)

2. **ทำ scoring ให้ deterministic และ governance-friendly**
- ใช้ `SCORING_WEIGHTS` จริง หรือเอาออกจากเอกสารให้ตรงโค้ด
- แยกคะแนนเป็น 2 มิติ:
  - `credibility_score` (evidence confidence)
  - `impact_score` (potential damage)
- คำนวณ `operational_risk_score` จาก 2 มิติด้วยสูตรคงที่

3. **ลด double-counting**
- รวม Cross-Source + Source Quality ให้เป็น component เดียว หรือทำ orthogonal definition ให้ชัด

4. **ปรับ keyword/actor extraction**
- เปลี่ยนจาก substring เป็น token/regex boundary
- ทำ denylist คำที่ noisy

5. **ทำ threshold policy แบบ operations-driven**
- ตัวอย่าง:
  - `Critical`: score >= 80 และต้องมี trusted internal corroboration >= 2 แหล่ง
  - `High`: score >= 60 และมี trusted>=1 + non-news corroboration
  - `Medium`: score >= 35
  - `Low/Clean`: ต่ำกว่านั้น

6. **ทำ monitoring + drift detection**
- เก็บ metric ต่อสัปดาห์: `%critical`, ticket conversion rate, analyst override rate, mean-time-to-ack

---

## 7) Suggested Acceptance Criteria (สำหรับ สกมช.)

- ผ่าน unit/integration tests สำหรับ scoring pipeline และ cross-source aggregation
- เอกสาร `AI-SCORING.md` ต้องตรงโค้ด 100%
- มี role-based access control + login + 2FA สำหรับ internal
- public view ไม่เห็น drill-down/report export ตาม policy
- มี audit log สำหรับ score generation, ticket creation, status change
- มี baseline performance report (precision/recall หรือ proxy metric ที่ตกลงร่วมกัน)

---

## 8) Quick Action Plan (ลำดับทำงาน)

1. Hotfix P0 (`main.py` score key + source dedupe model)
2. แก้ reports filter/time range ให้ตรง MOM
3. รวม data source ของ dashboard ให้ยึด warehouse เป็นหลัก
4. ทำ auth/authz/2FA + public/internal split
5. refactor scoring governance (weights, thresholds, calibration, monitoring)

---

## 9) File References

- `/Users/mm/Desktop/Cyber/tor/doc1.txt`
- `/Users/mm/Desktop/Cyber/tor/doc2.txt`
- `/Users/mm/Desktop/Cyber/tor/doc3.txt`
- `/Users/mm/Desktop/Cyber/ai-service/main.py`
- `/Users/mm/Desktop/Cyber/ai-service/models/scorer.py`
- `/Users/mm/Desktop/Cyber/ai-service/models/classifier.py`
- `/Users/mm/Desktop/Cyber/ai-service/config.py`
- `/Users/mm/Desktop/Cyber/ai-service/elastic_client.py`
- `/Users/mm/Desktop/Cyber/ai-service/docs/AI-SCORING.md`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/iocs/route.ts`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/reports/page.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/components/widgets/ThreatLevel.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/components/widgets/TrendPrediction.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/components/widgets/TrendChart.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/alerts/page.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/threats/cve/page.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/stats/route.ts`

