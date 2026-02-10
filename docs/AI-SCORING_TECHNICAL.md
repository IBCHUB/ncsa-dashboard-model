# AI Scoring Spec (0-100)

> Last Updated: 2026-02-10

เอกสารนี้อธิบาย “คะแนนความเสี่ยง (risk score) 0-100” ของ IOC แบบเปิดเอกสารแล้วคุยได้เลย ทั้งฝั่งลูกค้าและฝั่ง dev partner โดยระบุชัดว่า **ข้อมูลมาจากฟิลด์ไหน** และ **ขั้นตอน/โมเดลไหนสร้างคะแนนนั้น**

อ้างอิงโค้ด:
- `ai-service/main.py` (API `/enrich` และ pipeline aggregation จาก Data Lake)
- `ai-service/models/classifier.py` (Threat Types model + actor/mitre extraction)
- `ai-service/models/scorer.py` (สูตรคะแนนและ policy gates)
- `ai-service/config.py` (weights, threat severity, MITRE weights)
- `ai-service/config/threat_actors.json` (รายชื่อ actor + alias สำหรับตรวจจับ)

---

## 1) ข้อมูลเข้ามาจากไหน (Data Lineage)

ระบบรองรับ 2 ทางหลักที่ข้อมูลเข้ามาเหมือนกันในแก่น:

### A) ผ่าน Data Lake (pipeline aggregation)
ฟิลด์ที่ถูกใช้จริงใน pipeline (ดู `ai-service/main.py`):
| Data Lake field | เอาไปทำอะไร |
|---|---|
| `ioc_value`, `ioc_type` | ใช้กับ Entropy (เฉพาะ domain/url/hostname) และเป็นคีย์รวมข้อมูลหลายแหล่ง |
| `source_name` | สร้างรายการ `sources[]` สำหรับ Cross-Source, Source Quality, และ Policy Gates |
| `description` | ข้อความหลักสำหรับ Keywords, Threat Type, Threat Actor, MITRE, Sector |
| `reference` | เก็บเพื่อ traceability/ที่มา (pipeline ปัจจุบันไม่ได้ป้อนให้ classifier/scorer โดยตรง) |
| `event_time`, `collect_time` | คำนวณ `ioc_age_days` สำหรับ Time Decay |
| `tags` | ช่วย context (ปัจจุบันไม่ใช้เป็นคะแนนโดยตรงใน scorer) |

### B) ผ่าน API `/enrich` (เรียกตรงจากระบบอื่น)
ฟิลด์ใน request (ดู `ai-service/main.py`):
| API field | เอาไปทำอะไร |
|---|---|
| `title`, `description` | รวมเป็น `full_text = title + description` สำหรับ Threat Type, Threat Actor, MITRE, Keywords, Sector |
| `sources[]` | Cross-Source, Source Quality, Policy Gates |
| `domain_age_days` | Domain Age (ถ้ามี) |
| `ioc_age_days` | Time Decay (ถ้ามี) |

### C) ข้อมูลที่ “AI/Extractor” สร้างเพิ่มจากข้อความ
ระบบสร้างฟิลด์เสริมจาก `full_text`:
| Output field | วิธีได้มา | อยู่ที่ |
|---|---|---|
| `threat_types[]`, `confidence` | Zero-shot classification (`CLASSIFIER_MODEL`) เลือก label จาก `THREAT_CATEGORIES` | `ai-service/models/classifier.py` |
| `threat_actors[]` | ตรวจจับชื่อ actor/alias ด้วย string match จาก `ai-service/config/threat_actors.json` | `ai-service/models/classifier.py` |
| `mitre_techniques[]` | Regex หา `Txxxx(.xxx)` และ match tactic names/IDs จาก `MITRE_TACTICS` | `ai-service/models/classifier.py` |

หมายเหตุเรื่องข้อความที่ใช้วิเคราะห์:
- Data Lake pipeline: ใช้ข้อความจาก `description` ที่ถูก merge จากหลาย observation
- API `/enrich`: ใช้ `full_text = title + description`

---

## 2) คะแนนรวมคำนวณอย่างไร (สูตรเดียวจบ)

คะแนนรวมถูกสร้างจาก 2 ชั้น:
1. **Base score (0-100):** รวมแต้มจาก 9 หมวด (แต่ละหมวดมีคะแนน 0-100 และมี “งบแต้ม” ของตัวเอง)
2. **Operational adjustments:** Time decay, sector bonus, policy gates

### 2.1 งบแต้มของ 9 หมวด (รวม = 100)
| Factor (breakdown key) | Max points (budget) |
|---|---:|
| `cross_source` | 25 |
| `source_quality` | 15 |
| `threat_type_severity` | 15 |
| `threat_actor` | 10 |
| `domain_age` | 10 |
| `keywords` | 10 |
| `entropy` | 5 |
| `mitre_techniques` | 5 |
| `ai_confidence` | 5 |

### 2.2 สูตรรวม
ให้ `factor_score` อยู่ในช่วง 0-100 และ `budget` คือแต้มสูงสุดของหมวดนั้น:

```text
factor_points = (factor_score / 100) * budget
base_score    = Σ factor_points(ทั้ง 9 หมวด)                  // 0..100

base_int      = round(base_score)                              // ใช้เป็นคะแนนฐาน
after_decay   = int(base_int * decay_multiplier)               // ลดตามอายุ IOC
after_sector  = min(after_decay + sector_bonus, 100)           // มี guardrails
final_score   = apply_policy_gates(after_sector)               // กัน false escalation
```

หมายเหตุการแสดงผล:
- `final_score` เป็นจำนวนเต็ม
- factor_score ใน `breakdown` อาจเป็นทศนิยม (เพื่อความละเอียด) แต่สามารถปัดเป็นจำนวนเต็มใน UI ได้

---

## 3) รายละเอียดการคิดคะแนนรายหมวด (0-100) พร้อมที่มาข้อมูล

### 3.1 Cross-Source Validation (`cross_source`) (0-100)
ที่มาข้อมูล:
- Data Lake: `source_name` (รวมเป็น `sources[]` และตัดซ้ำ)
- API: `sources[]`

แนวคิด:
- วัด “การยืนยันข้ามแหล่ง” (มีหลายแหล่งพูดเรื่องเดียวกันไหม) และให้ผลเพิ่มแบบ diminishing returns

กติกาคิดคะแนน (สรุปเป็น 0-100):
- นับจำนวนแหล่งแบบไม่ซ้ำ (unique sources)
- เพิ่มคะแนนตามจำนวนแหล่ง
- ได้โบนัสเมื่อมีความหลากหลายของประเภทแหล่ง (trusted/news/other)
- คะแนนไม่เกิน 100

ตารางคะแนนตามจำนวนแหล่ง (ปัดเศษเพื่อจำง่าย):
| แหล่งที่ไม่ซ้ำ | factor_score (โดยประมาณ) |
|---:|---:|
| 1 | 17 |
| 2 | 33 |
| 3 | 50 |
| 4 | 67 |
| 5 | 77 |
| 6 | 87 |
| 7+ | 93 |

โบนัสความหลากหลายประเภทแหล่ง:
- ถ้ามีอย่างน้อย 2 ประเภทแหล่ง (เช่น trusted+news): เพิ่มประมาณ +7
- ถ้ามีครบ 3 ประเภทแหล่ง (trusted+news+other): เพิ่มประมาณ +13

หมายเหตุ:
- “trusted/news/other” ถูกจัดกลุ่มด้วยรายการ `TRUSTED_SOURCES` และ `NEWS_SOURCES` ใน `ai-service/config.py`

### 3.2 Source Quality (`source_quality`) (0-100)
ที่มาข้อมูล:
- Data Lake: `source_name` (รวมเป็น `sources[]`)
- API: `sources[]`

แนวคิด:
- วัด “ความน่าเชื่อถือของแหล่ง” (คุณภาพของ evidence) ไม่ใช่จำนวนแหล่ง

กติกาคิดคะแนน (สรุปเป็น 0-100, ปัดเศษเพื่อจำง่าย):
- Trusted source เพิ่มประมาณ +38 ต่อแหล่ง
- News source เพิ่มประมาณ +20 ต่อแหล่ง
- Other source เพิ่มประมาณ +13 ต่อแหล่ง
- คะแนนรวมหมวดนี้ไม่เกิน 100

หมายเหตุ:
- การจัดกลุ่ม trusted/news/other ใช้รายการใน `ai-service/config.py` (substring match)

### 3.3 Threat Type Severity (`threat_type_severity`) (0-100)
ที่มาข้อมูล:
- Data Lake: `description`
- API: `title` + `description`

วิธีได้ `threat_types[]`:
- ใช้ Zero-shot classification (`transformers` pipeline: `zero-shot-classification`)
- โมเดล: `CLASSIFIER_MODEL` (ค่าเริ่มต้น `typeform/distilbert-base-uncased-mnli`, ดู `ai-service/config.py`)
- label ที่เลือกได้: `THREAT_CATEGORIES` (เช่น Ransomware, Phishing, Malware, APT, C2)
- เก็บเฉพาะ label ที่คะแนน >= 0.3 (default threshold)

กติกาคิดคะแนน (0-100):
1. แต่ละ threat type มี “ความรุนแรง” ตามตารางใน `THREAT_TYPE_SEVERITY` (`ai-service/config.py`)
2. นับคะแนนจาก threat type ที่รุนแรงที่สุด **สูงสุด 2 ประเภท** (กันการบวกทับซ้อน)
3. ถ้าพบ threat type ตั้งแต่ 3 ประเภทขึ้นไป: เพิ่มโบนัส “multi-vector”
4. normalize ให้อยู่ในสเกล 0-100 และ cap ไม่เกิน 100

คะแนนพื้นฐานเมื่อพบ “เพียง 1 ประเภท” (ปัดเศษเพื่อจำง่าย):
| Threat type | factor_score (โดยประมาณ) |
|---|---:|
| Ransomware | 71 |
| APT | 71 |
| C2 | 71 |
| Botnet | 63 |
| Malware | 51 |
| Credential Theft | 51 |
| Data Breach | 43 |
| Phishing | 34 |
| DDoS | 29 |
| Vulnerability | 23 |
| Defacement | 14 |
| Other | 9 |

ตัวอย่างการรวมหลายประเภท:
| threat_types ที่ตรวจพบ | factor_score (โดยประมาณ) | เหตุผลสั้น |
|---|---:|---|
| `[Ransomware]` | 71 | ประเภทเดียวระดับ critical |
| `[Phishing, DDoS]` | 63 | สองประเภทระดับ medium รวมกัน |
| `[Ransomware, Phishing]` | 86 | มี 2 ประเภทและมี cap กัน over-score |
| `[Ransomware, APT, C2]` | 100 | หลายประเภทระดับ critical + multi-vector bonus |

### 3.4 Threat Actor (`threat_actor`) (0-100)
ที่มาข้อมูล:
- Data Lake: `description`
- API: `title` + `description`

วิธีได้ `threat_actors[]`:
- ไม่ใช่ generative AI และไม่ใช่การเดา
- ใช้วิธี “ค้นหาชื่อ actor/alias ในข้อความ” (string match) จากรายการ `ai-service/config/threat_actors.json`
- ถ้าพบ alias จะ map กลับเป็นชื่อหลัก (canonical name)

กติกาคิดคะแนน (0-100):
- ถ้าพบหลาย actor: ใช้ actor ที่ “เสี่ยงสูงสุด” เป็นตัวแทน (max)
- คะแนนของ actor ถูกกำหนดจากรายการใน `KNOWN_THREAT_ACTORS` (`ai-service/config.py`)
- ถ้าพบชื่อ actor แต่ไม่อยู่ในรายการ known: ให้คะแนนระดับกลาง (ระบุชื่อได้ แต่ความเชื่อมั่น/บริบทอาจยังไม่พอ)
- normalize ให้อยู่ในสเกล 0-100 และ cap ไม่เกิน 100

ตัวอย่างคะแนน (โดยประมาณ):
| ตรวจพบ actor | factor_score (โดยประมาณ) |
|---|---:|
| Lazarus, APT28, APT29, APT41 | 100 |
| Charming Kitten, MuddyWater | 93 |
| LockBit, BlackCat, Conti | 80-83 |
| FIN7, Qakbot, Emotet | 67-73 |
| Anonymous | 50 |
| พบชื่อแต่ไม่อยู่ใน known list | 50 |
| ไม่พบชื่อ | 0 |

### 3.5 AI Confidence (`ai_confidence`) (0-100)
ที่มาข้อมูล:
- มาจากคะแนนของ label อันดับ 1 ของ zero-shot model (`confidence`)

กติกาคิดคะแนน (แสดงเป็นเปอร์เซ็นต์):
| Confidence | factor_score |
|---:|---:|
| >= 93% | 80 |
| >= 85% | 50 |
| >= 70% | 20 |
| < 70% | 0 |

### 3.6 High-Risk Keywords (`keywords`) (0-100)
ที่มาข้อมูล:
- Data Lake: `description`
- API: `title` + `description`

กติกาคิดคะแนน (0-100):
- ระบบค้นหา keyword เสี่ยงจากรายการ `HIGH_RISK_KEYWORDS` (`ai-service/config.py`)
- ให้คะแนนตามจำนวน keyword ที่พบ และ cap ไม่เกิน 100

ตารางคะแนน:
| จำนวน keyword ที่พบ | factor_score |
|---:|---:|
| 0 | 0 |
| 1 | 20 |
| 2 | 40 |
| 3 | 60 |
| 4 | 80 |
| 5+ | 100 |

### 3.7 Entropy / DGA heuristic (`entropy`) (0-100)
ที่มาข้อมูล:
- Data Lake / API: `ioc_value`, `ioc_type`

ใช้เฉพาะเมื่อ `ioc_type` เป็น domain/url/hostname:
- คำนวณ Shannon entropy ของชื่อโดเมน (ตัด TLD ออกก่อน)
- เกณฑ์คะแนน:
| Entropy | factor_score |
|---|---:|
| > 4.0 | 100 |
| 3.5-4.0 | 67 |
| 3.0-3.5 | 33 |
| <= 3.0 | 0 |

### 3.8 Domain Age (`domain_age`) (0-100)
ที่มาข้อมูล:
- API: `domain_age_days` (ส่งเข้ามา)
- Data Lake: ถ้ามี field อายุโดเมนจาก enrichment upstream ให้นำมาส่งเป็น `domain_age_days`

ใช้เฉพาะเมื่อ `ioc_type` เป็น domain/url/hostname (ถ้าเป็น IP/hash จะไม่คิดหมวดนี้และได้ 0)

กติกาคิดคะแนน (0-100):
| อายุโดเมน | factor_score |
|---|---:|
| < 30 วัน | 100 |
| 30-89 วัน | 75 |
| 90-179 วัน | 50 |
| 180-364 วัน | 25 |
| >= 365 วัน | 0 |

### 3.9 MITRE ATT&CK (`mitre_techniques`) (0-100)
ที่มาข้อมูล:
- Data Lake: `description`
- API: `title` + `description`

วิธีได้ `mitre_techniques[]`:
- ตรวจจับ Technique ID รูปแบบ `Txxxx` หรือ `Txxxx.xxx`
- ตรวจจับ tactic names/IDs จาก `MITRE_TACTICS` (`ai-service/config.py`) เช่น `TA0001 (Initial Access)`

กติกาคิดคะแนน (0-100):
- แต่ละ tactic มีค่าน้ำหนักของตัวเอง (เช่น Command and Control สูงกว่า Discovery)
- รวมคะแนนแล้ว cap ไม่เกิน 100

---

## 4) Modifiers และ Governance

### 4.1 Time Decay (ลดตามอายุ IOC)
ใช้ `ioc_age_days` (คำนวณจาก `event_time/collect_time` หรือส่งมาตรงผ่าน API)
| อายุ IOC | decay_multiplier |
|---|---:|
| <= 7 วัน | 1.00 |
| 8-30 วัน | 0.90 |
| 31-90 วัน | 0.75 |
| 91-180 วัน | 0.60 |
| > 180 วัน | 0.50 |

### 4.2 Sector Bonus (เพิ่มตามผลกระทบของเซกเตอร์)
ระบบพยายามระบุ “เซกเตอร์เป้าหมาย” จากข้อความ และให้โบนัสตามความเสี่ยงของเซกเตอร์ (ดู `ai-service/models/sector_classifier.py`)

กติกาคุมเพดาน:
- ถ้า sector confidence < 0.45: โบนัสไม่เกิน +5
- ถ้า evidence เป็น news-only: โบนัสไม่เกิน +3

### 4.3 Policy Gates (กัน false escalation)
- Critical gate: ถ้าคะแนนหลังปรับต่างๆ >= 80 แต่ trusted corroboration < 2 แหล่ง จะ cap คะแนนไว้ที่ 74 (High)
- News-only gate: ถ้าเป็น news-only และคะแนน >= 50 จะ cap คะแนนไว้ที่ 49 (Medium)

---

## 5) Severity Mapping
| Final score | Severity |
|---:|---|
| >= 75 | critical |
| 50-74 | high |
| 25-49 | medium |
| 1-24 | low |
| 0 | clean |
