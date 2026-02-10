# AI Scoring System Documentation

> **Last Updated:** 2026-02-08  
> **Source of Truth:** `/Users/mm/Desktop/Cyber/ai-service/models/scorer.py`, `/Users/mm/Desktop/Cyber/ai-service/config.py`

## ภาพรวม

ระบบให้คะแนนความเสี่ยง IOC ใช้แนวทาง **Weighted Scoring (0-100)** พร้อม governance และ policy gates:

1. คำนวณคะแนนดิบรายปัจจัย (raw score)
2. แปลงเป็นคะแนนถ่วงน้ำหนักตาม `SCORING_WEIGHTS`
3. รวมเป็น `weighted_total` (0-100)
4. ใช้ `decay_factor` ลดคะแนนตามอายุ IOC
5. บวก `sector_bonus` (มี guardrail)
6. ใช้ policy gates เพื่อลด false escalation

ผลลัพธ์หลัก:
- `risk_score` / `operational_risk_score`
- `credibility_score`
- `impact_score`
- `score_model_version`
- `score_config_version`

---

## สูตรการคำนวณ

```text
weighted_points(factor) = (raw_score / max_score) * weight * 100
weighted_total = Σ weighted_points(ทุก factor ที่เปิดใช้)

score_after_decay = round(weighted_total) * decay_multiplier
operational_risk = score_after_decay + sector_bonus (capped + policy-gated)
```

หมายเหตุ:
- `geo_risk` ถูกปิดใช้งาน (score = 0)
- มี policy gate ลดคะแนนกรณี evidence ไม่พอ (เช่น news-only)

---

## น้ำหนักที่ใช้จริง (`SCORING_WEIGHTS`)

| Factor key | Weight |
|---|---:|
| `cross_source` | 0.25 |
| `threat_intel_source` | 0.15 |
| `high_risk_keywords` | 0.10 |
| `domain_age` | 0.10 |
| `entropy` | 0.05 |
| `threat_type_severity` | 0.15 |
| `threat_actor` | 0.10 |
| `mitre_techniques` | 0.05 |
| `ai_confidence` | 0.05 |

---

## ปัจจัยการให้คะแนน (Raw Score)

### 1) Cross-Source Validation (max 30)
- 1 แหล่ง = 5
- 2 แหล่ง = 10
- 3 แหล่ง = 15
- 4+ แหล่ง = 20..30 (diminishing returns)
- มี bonus ตามความหลากหลายของประเภทแหล่ง (`trusted/news/other`)

### 2) Source Quality (max 40)
- Trusted source = 15
- News source = 8
- Other source = 5
- cap สูงสุด 40

### 3) High-Risk Keywords (max 25)
- 5 คะแนนต่อ keyword
- cap สูงสุด 25
- ใช้ regex boundary-aware เพื่อลด false positive จาก substring

### 4) Entropy (max 15)
ใช้กับ domain/url/hostname
- > 4.0 = 15
- > 3.5 = 10
- > 3.0 = 5
- อื่นๆ = 0

### 5) Domain Age (max 20)
ใช้กับ domain/url/hostname
- < 30 วัน = 20
- < 90 วัน = 15
- < 180 วัน = 10
- < 365 วัน = 5
- >= 365 วัน = 0

### 6) Threat Type Severity (AI) (max 35)
- อิงจาก `THREAT_TYPE_SEVERITY`
- นับสูงสุด 2 threat types
- มี multi-threat bonus เมื่อพบ >=3 types

### 7) Threat Actor Attribution (AI) (max 30)
- แมป actor กับ `KNOWN_THREAT_ACTORS`
- เลือก score สูงสุดของ actor ที่พบ

### 8) MITRE ATT&CK (AI) (max 20)
- คิดคะแนนจาก tactic/ID ที่พบ
- extractor รองรับทั้งรูปแบบ `Txxxx(.xxx)` และ tactic names ที่อยู่ใน config

### 9) AI Confidence Bonus (max 10 raw input)
Threshold จาก `CONFIDENCE_THRESHOLDS`:
- `>= 0.93` => +8
- `>= 0.85` => +5
- `>= 0.70` => +2
- ต่ำกว่า => 0

### 10) Geo Risk
- ปิดใช้งาน (`score = 0`)

---

## Decay Factor

ลดคะแนนตามอายุ IOC (`ioc_age_days`):

| อายุ IOC | Multiplier |
|---|---:|
| <= 7 วัน | 1.00 |
| 8-30 วัน | 0.90 |
| 31-90 วัน | 0.75 |
| 91-180 วัน | 0.60 |
| > 180 วัน | 0.50 |

---

## Sector Bonus และ Guardrails

- คำนวณ sector จาก classifier แล้วบวก `risk_bonus` ตาม `SECTOR_RISK_BONUS`
- มี guardrail:
  - หาก confidence sector ต่ำ (`< 0.45`) จำกัด bonus สูงสุด 5
  - หากเป็นข่าวล้วน (news-only) จำกัด bonus สูงสุด 3

---

## Policy Gates (ลด False Escalation)

1. **Critical escalation gate (trusted corroboration)**
- ถ้าคะแนนหลัง decay + sector bonus **>= 80** แต่ `trusted` corroboration **< 2** แหล่ง
- cap เป็น **74 (High)** เพื่อกัน false critical จาก evidence ที่ยังไม่แข็งแรง

2. **News-only gate**
- ถ้าเป็นข่าวล้วน (news-only: `trusted==0 && news>0 && other==0`) และคะแนน **>= 50**
- cap เป็น **49 (Medium)** จนกว่าจะมี non-news corroboration

policy ที่ trigger จะบันทึกใน `breakdown.policy_gate` (เช่น `triggered`, `adjustments`)

---

## Severity Mapping

| คะแนน | Severity |
|---|---|
| >= 75 | critical |
| 50-74 | high |
| 25-49 | medium |
| 1-24 | low |
| 0 | clean |

---

## Threat Type Severity (สรุป)

| Level | ประเภทภัย | คะแนน |
|---|---|---:|
| 🔴 Critical | Ransomware, APT, C2, Wiper, Botnet | 22-25 |
| 🟠 High | Malware, Credential Theft, Backdoor, Exploit, Trojan, Data Breach | 15-18 |
| 🟡 Medium | Phishing, DDoS, Spam, Scanning | 6-12 |
| 🟢 Low | Vulnerability, Defacement, Other | 3-8 |

> รายละเอียดเต็มอยู่ใน `config.py` → `THREAT_TYPE_SEVERITY`

---

## Output ที่สำคัญ

- `risk_score`: คะแนนสุดท้าย 0-100
- `operational_risk_score`: alias ของคะแนนสุดท้าย
- `credibility_score`: สัดส่วนด้านความน่าเชื่อถือของ evidence
- `impact_score`: สัดส่วนด้านผลกระทบ
- `breakdown`: รายปัจจัย + weighted score + governance + policy gates
- `top_factors`: ปัจจัยที่ contribute สูงสุด
- `target_sector`: ผล sector classification เต็มรูปแบบ
- `score_model_version`, `score_config_version`: สำหรับ audit / change control

---

## ตัวอย่างการคำนวณ

**IOC:** `malware-c2.evil-domain[.]net`  
**แหล่งที่พบ:** VirusTotal, ThreatFox, BleepingComputer (3 แหล่ง)  
**ประเภท:** C2, Malware  
**Threat Actor:** Lazarus  
**Keywords:** c2, backdoor  
**Domain Age:** 15 วัน  
**IOC Age:** 3 วัน  

```text
Factor              Raw Score    Max    Weight    Weighted Points
─────────────────────────────────────────────────────────────────
Cross-Source        15           30     0.25      12.5
Source Quality      38           40     0.15      14.25
Keywords            10           25     0.10      4.0
Domain Age          20           20     0.10      10.0
Entropy             10           15     0.05      3.33
Threat Type         43 (cap 35)  35     0.15      15.0
Threat Actor        30           30     0.10      10.0
MITRE               8            20     0.05      2.0
AI Confidence       8            10     0.05      4.0
─────────────────────────────────────────────────────────────────
                               weighted_total = 75.08 → round = 75

Decay Factor:       1.00 (IOC age 3 วัน)
Sector Bonus:       +10 (financial sector, high confidence)
─────────────────────────────────────────────────────────────────
Final Score:        85 → Critical

Policy Gate Check:
- trusted sources = 2 (VirusTotal, ThreatFox) ✓ ≥ 2 required
- non-news corroboration = yes ✓
→ No cap applied, severity = Critical
```

### ตัวอย่าง 2: News-Only Evidence (Policy Gate Triggered)

**IOC:** `suspicious-phish[.]com`  
**แหล่งที่พบ:** BleepingComputer, DarkReading (2 แหล่ง — ทั้งหมดเป็น news)  
**ประเภท:** Phishing  
**Keywords:** phishing  
**Domain Age:** 45 วัน  

```text
Factor              Raw Score    Max    Weight    Weighted Points
─────────────────────────────────────────────────────────────────
Cross-Source        10           30     0.25      8.33
Source Quality      16           40     0.15      6.0
Keywords            5            25     0.10      2.0
Domain Age          15           20     0.10      7.5
Entropy             5            15     0.05      1.67
Threat Type         12           35     0.15      5.14
Threat Actor        0            30     0.10      0.0
MITRE               0            20     0.05      0.0
AI Confidence       5            10     0.05      2.5
─────────────────────────────────────────────────────────────────
                               weighted_total = 33.14 → round = 33

Decay Factor:       1.00 (IOC age 2 วัน)
Sector Bonus:       +3 (general sector, news-only capped)
─────────────────────────────────────────────────────────────────
Raw Score:          36 → Medium

Policy Gate Check:
- trusted sources = 0 ⚠️ (news-only)
- non-news corroboration = no ⚠️
→ ❌ Policy gate triggered: cap below High until trusted corroboration

breakdown.policy_gate: "news_only_cap"
```

> **หมายเหตุ:** แม้คะแนนจะสูงพอเป็น Medium แต่หากต้องการขึ้น High/Critical จะต้องมี trusted source อย่างน้อย 1 แหล่ง

---

## หมายเหตุ Governance

- ค่าใน `SCORING_WEIGHTS` ถูกใช้จริงในการคำนวณ
- ทุก score ต้อง trace ได้จาก breakdown และ source evidence
- ควรทำ calibration ต่อเนื่องกับ incident จริง (false positive / false negative review)
