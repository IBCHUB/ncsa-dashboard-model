# TCTI AI Pipeline — เอกสารส่งมอบงาน

> เอกสารนี้อธิบาย AI Pipeline ของระบบ Thailand Cyber Threat Intelligence (TCTI) แบบ end-to-end ตั้งแต่ดึงข้อมูลจาก datalake → ผ่าน enrichment + scoring → เก็บลง warehouse → เสิร์ฟให้ Dashboard
>
> อัพเดตล่าสุด: 2026-05-21 (Phase 1.17)

---

## 📋 สารบัญ

1. [สรุปสั้นๆ ว่า Pipeline ทำอะไร](#1-สรุปสั้นๆ-ว่า-pipeline-ทำอะไร)
2. [ภาพรวมการไหลของข้อมูล](#2-ภาพรวมการไหลของข้อมูล)
3. [แต่ละ Component ทำอะไร](#3-แต่ละ-component-ทำอะไร)
4. [Scoring Model — คะแนนความเสี่ยง](#4-scoring-model--คะแนนความเสี่ยง)
5. [Configuration — Environment Variables](#5-configuration--environment-variables)
6. [การ Deploy + การรัน Pipeline](#6-การ-deploy--การรัน-pipeline)
7. [ข้อมูลต้นทาง (Data Sources)](#7-ข้อมูลต้นทาง-data-sources)
8. [Known Limitations — ข้อจำกัดที่ต้องรู้](#8-known-limitations--ข้อจำกัดที่ต้องรู้)
9. [Troubleshooting + วิธีตรวจสอบ](#9-troubleshooting--วิธีตรวจสอบ)
10. [ภาคผนวก: ไฟล์สำคัญที่ควรรู้](#10-ภาคผนวก-ไฟล์สำคัญที่ควรรู้)

---

## 1. สรุปสั้นๆ ว่า Pipeline ทำอะไร

**TCTI AI Pipeline** = ระบบประมวลผล Indicator of Compromise (IOC) อัตโนมัติ

**Input:** IOC ดิบจาก datalake (cyberint feed) — IP, domain, URL, file hash (sha256/md5/sha1)

**Process:** เพิ่ม context ให้ IOC แต่ละตัว (enrichment) → จัดประเภทภัยคุกคาม (classification) → คำนวณคะแนนความเสี่ยง 0-100 (scoring)

**Output:** เอกสารพร้อมใช้ใน warehouse → Dashboard ดึงไปแสดงให้ SOC analyst

**ทำไมต้องมี?** เพราะ datalake มีข้อมูลดิบเป็นล้านๆ รายการ — SOC ดูเองไม่ไหว ต้องมี AI ช่วย:
- บอกว่า IOC ไหนสำคัญก่อน (ranking by risk_score)
- บอกว่าเป็นภัยประเภทไหน (Ransomware/Phishing/Malware/etc.)
- บอกว่าเล็งเป้าหมายภาคใด (Banking/Government/Healthcare/etc.)
- บอกว่าเชื่อมโยงกับ APT group ใด

---

## 2. ภาพรวมการไหลของข้อมูล

```
┌──────────────────────┐
│  Datalake (.41)      │  Cyberint IOC feed
│  tcti-feeds-*        │  (sha256 90% / url 6% / ip 2.6% / domain 1.4%)
└──────────┬───────────┘
           │ ดึงผ่าน HTTP query
           ▼
┌──────────────────────────────────────────────────────────────────┐
│  AI Service (.44) — main.py /pipeline/run                        │
│                                                                  │
│  Step 1: ดึง unprocessed IOCs                                    │
│     └─ elastic_client.py: get_unprocessed_iocs()                 │
│        - ใช้ cyber-logs-processed เป็น state index               │
│        - skip docs ที่ process แล้ว                              │
│                                                                  │
│  Step 2: normalize raw datalake hits                             │
│     └─ datalake_adapters.py                                      │
│        - แปลง schema ต่างกันให้เป็น format เดียว                  │
│        - extract source/evidence/geo info                        │
│                                                                  │
│  Step 3: group + enrich docs (per IOC)                           │
│     └─ utils/pipeline_documents.py: build_enriched_ioc_document()│
│        ├─ merge multi-source observations                        │
│        ├─ sanitize sensitive fields                              │
│        ├─ classify threat (rule หรือ ML)                          │
│        │   └─ pipeline_classification_policy.py                  │
│        │   └─ models/classifier.py (NLP zero-shot)               │
│        ├─ classify sector                                        │
│        │   └─ models/sector_classifier.py                        │
│        ├─ WHOIS lookup (domain age)                              │
│        │   └─ utils/whois_enrichment.py                          │
│        ├─ GeoIP lookup (country)                                 │
│        │   └─ utils/geoip_enrichment.py                          │
│        ├─ Threat actor extraction (malware family → actor)       │
│        │   └─ utils/threat_actor_enrichment.py                   │
│        ├─ calculate risk_score (6 factors)                       │
│        │   └─ models/scorer.py                                   │
│        ├─ derive recommended actions                             │
│        │   └─ models/actions.py                                  │
│        └─ build relationship graph                               │
│            └─ models/relationship_graph.py                       │
│                                                                  │
│  Step 4: validate + write                                        │
│     └─ models/validation.py: warehouse_eligible check            │
│     └─ elastic_client.py: bulk_index to warehouse                │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────┐
│  Warehouse (.43)                     │
│  cyber-logs-datawarehouse            │  ← Dashboard reads from here
│                                      │  ← Sector Report, Threat Map, etc.
└──────────────────────────────────────┘
```

**Trigger:** Scheduler ใน main.py เรียก `/pipeline/run` ทุกชั่วโมง (อัตโนมัติ) ผ่าน `PIPELINE_SCHEDULER_ENABLED=true`

---

## 3. แต่ละ Component ทำอะไร

### 3.1 `datalake_adapters.py` — แปลงข้อมูลดิบให้เป็น format มาตรฐาน

**บทบาท:** datalake อาจมี schema หลายแบบ (cyberint, MISP, news, sandbox) — adapter แปลงทุกอันให้เป็น dict format เดียวที่ pipeline เข้าใจ

**ตัวอย่าง field ที่ extract:**
- `ioc_value`, `ioc_type`
- `source_name`, `source_type`, `source_url`
- `detected_activity` (จาก cyberint: malware_payload, phishing_website, cnc_server, etc.)
- `geo_country` (ถ้าเป็น IP)
- `description`, `tags`, `confidence`, `severity`

**Phase 1.10 (สำคัญ):** mapping `detected_activity` → MITRE ATT&CK technique
- `malware_payload` → T1587.001 (Malware)
- `phishing_website` → T1566.002 (Spearphishing Link)
- `cnc_server` → T1102 + T1071 (Command & Control)
- `infecting_url` → T1189 (Drive-by Compromise)

→ ทำให้ MITRE coverage จาก 0% → 98.29%

---

### 3.2 `elastic_client.py` — สื่อสารกับ Elasticsearch

**บทบาท:** wrapper รอบ ES สำหรับอ่าน datalake / เขียน warehouse / track processed state

**สามารถ:**
- `get_unprocessed_iocs(limit)` — ดึง IOC ใหม่ที่ยังไม่ได้ process
- `bulk_index_warehouse(docs)` — เขียน batch ลง warehouse
- `bulk_index_datalake(docs)` — สำหรับ writable datalake (ตอนนี้ readonly)
- `get_processed_state(ioc_id)` — เช็คว่า IOC นี้เคย process หรือยัง

**Important env vars:**
- `DATALAKE_ELASTICSEARCH_URL` (เช่น http://192.168.100.41:9201)
- `DATALAKE_INDEX` (เช่น tcti-feeds)
- `WAREHOUSE_ELASTICSEARCH_URL` (เช่น http://192.168.100.43:9200)
- `WAREHOUSE_INDEX` (เช่น cyber-logs-datawarehouse)
- `PROCESSED_INDEX` (state tracking)

---

### 3.3 `main.py` — Service entry point + scheduler

**บทบาท:** FastAPI app + background scheduler

**Endpoints หลัก:**
- `POST /pipeline/run` — รัน pipeline batch หนึ่ง (limit-controlled)
- `GET /pipeline/status` — สถานะ ES + index doc counts
- `GET /health` — สำหรับ healthcheck

**Scheduler:**
- ถ้า `PIPELINE_SCHEDULER_ENABLED=true` จะรัน `/pipeline/run` อัตโนมัติทุก hour (limit ตาม `PIPELINE_SCHEDULER_LIMIT`)
- ใช้ `_pipeline_lock` (threading lock) ป้องกัน concurrent runs

---

### 3.4 `utils/pipeline_documents.py` — Document builder (หัวใจของ pipeline)

**บทบาท:** ฟังก์ชัน `build_enriched_ioc_document()` คือจุดที่รวบรวมทุก enrichment เข้าด้วยกัน

**Flow ภายใน 1 IOC:**

1. **Merge sources** — ถ้า IOC เดียวกันมาจากหลายแหล่ง → รวมเข้าด้วยกัน
2. **Extract evidence** — `source_evidence` field จาก MISP/cyberint
3. **Classification policy decision** — ML หรือ rule mode? (ดู Section 3.5)
4. **WHOIS enrichment** — สำหรับ domain → domain_age_days
5. **GeoIP enrichment** — สำหรับ IP → country code
6. **Threat actor enrichment** — match malware family → actor groups
7. **Sector classification** — match keywords/domains → target_sector
8. **Risk scoring** — 6 factors → 0-100 risk score
9. **Action derivation** — แนะนำว่าควรทำอะไรกับ IOC นี้ (block/monitor/investigate)
10. **Validation** — เช็คว่าเข้าเงื่อนไข warehouse หรือเปล่า

**Output:** dict พร้อม index ลง warehouse

---

### 3.5 `pipeline_classification_policy.py` — เลือก rule vs ML

**ปัญหา:** ML zero-shot ใช้ memory เยอะ ช้า — ไม่ควรรันทุก doc

**Policy:**
```python
if source_provides_clear_threat_metadata(doc):
    use rule_mode  # เร็ว, deterministic, ใช้ source-provided threat_type
elif description has high-confidence context keywords (CVE-XXXX, RCE, etc.):
    use context_rule  # ไม่ ML แต่ใช้ keyword extraction
elif description >= PIPELINE_ML_MIN_CONTEXT_CHARS (code default 150, prod env may override):
    use ml_mode  # zero-shot NLP
else:
    use skipped_classification  # ไม่มี context พอ
```

**ผลที่ verified:**
- 99.93% docs → source_rule mode (เร็ว, ใช้ data จาก feed)
- 0.07% docs → ML mode (สำหรับ news/long descriptions)

---

### 3.6 `models/classifier.py` — NLP zero-shot classifier

**บทบาท:** ใช้ HuggingFace zero-shot model จัด IOC เป็น threat type ตาม `THREAT_LABELS`

**Labels ที่จัด:**
- Ransomware, Malware, Phishing, APT, C2 Communication
- Data Breach, Exploited Vulnerability, DDoS
- Cryptocurrency Theft, Banking Trojan
- etc.

**Sector ใน single zero-shot pass:** Phase 1.5+ ทำให้ classify threat + sector ใน batch เดียว ลด latency 50%

**Note:** ใช้ DEVICE=cpu (ไม่จำเป็นต้อง GPU เพราะ batch ช้าอยู่แล้ว)

---

### 3.7 `models/sector_classifier.py` — Keyword-based sector fallback

**บทบาท:** เมื่อ ML zero-shot confidence ต่ำ → ใช้ keyword/domain matching แทน

**Logic (Phase 1.17):**

1. **TLD shortcut** (high confidence 0.85)
   - `.gov.th`, `.go.th`, `.mi.th`, `.mil.th` → government
   - `.ac.th`, `.edu` → education
   - `.bank` → financial

2. **Keyword matching** (substring in description + URL path + hostname)
   - "ธนาคาร", "kasikorn", "krungsri" → financial
   - "hospital", "siriraj", "bumrungrad" → healthcare
   - "EGAT", "PTT", "พลังงาน" → critical_infrastructure
   - etc.

3. **Domain pattern matching** (dual mode):
   - **Substring** patterns with dots (`.bank.`, `scb.co.th`) → match anywhere in hostname
   - **Bare tokens** (`scb`, `ais`, `binance`) → match as exact label after split by `.`/`-`/`_` (ป้องกัน false positive เช่น "rtadlnacz" ไม่ tripping on "rta")
   - Token match also checks URL path tokens (`/scb/login` → financial)

4. **Threat actor matching** — ถ้า IOC linked to known actor → infer sector
   - Lazarus → financial/government
   - Sandworm → critical_infrastructure
   - APT41 → technology

5. **Fallback:** "general" (Other) ถ้าไม่ match อะไรเลย

**Sectors ที่รองรับ:**
| Key | Display name | Thai |
|-----|-------------|------|
| financial | Banking and Finance | ด้านการเงินการธนาคาร |
| government | Substantive Public Services | ด้านบริการภาครัฐที่สำคัญ |
| healthcare | Public Health | ด้านสาธารณสุข |
| critical_infrastructure | Energy and Public Utilities | ด้านพลังงานและสาธารณูปโภค |
| technology | Information Technology and Telecommunications | ด้านเทคโนโลยีสารสนเทศและโทรคมนาคม |
| education | Education | ภาคการศึกษา |
| general | Other | อื่นๆ |

---

### 3.8 `utils/whois_enrichment.py` — Domain age lookup

**บทบาท:** หา registration date ของ domain → คำนวณ `domain_age_days`

**Behavior:**
- LRU cache 2000 entries (กัน rate limit)
- timeout 5 วินาที (graceful fail)
- skip IP/localhost/private addresses
- รองรับ WHOIS field variants: `creation_date`, `create_date`, `created`, `regdate`, `registered_on`

**Note:** Phase 1.11 — ตัด `domain_age` ออกจาก scoring formula แล้ว เพราะ coverage แค่ 3-4% (90% corpus เป็น sha256 ไม่มี domain) — แต่ field ยังเก็บไว้สำหรับ Dashboard display

---

### 3.9 `utils/geoip_enrichment.py` — Country lookup

**บทบาท:** lookup IP address → ISO country code

**Uses:** GeoLite2-Country.mmdb (MaxMind) ต้อง mount เข้า container ที่ `/app/data/`

**Coverage:** 3.57% ของ corpus (IP IOCs เท่านั้น — sha256/url ไม่ apply)

---

### 3.10 `utils/threat_actor_enrichment.py` — Malware family → Actor mapping

**บทบาท:** สกัดชื่อ APT/criminal group จาก AV signature ใน description

**Data:** `data/mitre_attack_actor_mapping.json` — 98 malware families → actor groups (curated จาก MITRE ATT&CK v14.1)

**ตัวอย่าง:**
- "Recognized as Win64:Emotet-Z" → Emotet → [Mummy Spider, TA542]
- "Recognized as Backdoor:Win32/Lazarus.A" → Lazarus → [Lazarus Group]
- "Detected SUNBURST loader" → SUNBURST → [APT29]
- "WannaCry ransomware" → WannaCry → [Lazarus Group]

**Implementation:**
- tokenize + normalize (lowercase, alphanumeric only)
- min token length 4 chars (กัน false positive)
- LRU cache 4096 entries

**Coverage:** 0.3% → ~2-5% (เพิ่มจาก Phase 1.13)

---

### 3.11 `models/scorer.py` — 6-Factor Risk Scoring

ดู Section 4 ด้านล่าง

---

### 3.12 `models/actions.py` — Recommended actions

**บทบาท:** ดูจาก threat_type + severity + sector → แนะนำ action ให้ SOC

**ตัวอย่าง:**
- Critical Ransomware @ Financial sector → "Block immediately + alert Tier 1 SOC"
- Medium Phishing @ Education → "Monitor + add to threat feed"
- Low Generic Malware → "Auto-quarantine, no human review"

**Output fields:**
- `action_required` (bool)
- `action_status` (open/investigating/resolved/closed)
- `action_title`, `action_reason`

---

### 3.13 `models/relationship_graph.py` — IOC relationship building

**บทบาท:** หาความสัมพันธ์ระหว่าง IOC

**Link types ที่สร้าง:**
- IOC ↔ same domain (different paths/subdomains)
- IOC ↔ same threat actor
- IOC ↔ same malware family
- IOC ↔ same MITRE technique
- IOC → exploits CVE-XXXX (Phase 1d เพิ่ม "exploits" link type)

---

## 4. Scoring Model — คะแนนความเสี่ยง

### 4.1 สูตร (Phase 1.16 final)

```
risk_score = (factor_score × weight) × decay_factor × sector_multiplier
```

โดยมี **6 factors** น้ำหนักรวม = 100%:

| Factor | Weight | Coverage จริง |
|--------|:------:|:-------------:|
| `threat_intel_source` | 25% | 100% — ทุก doc มี source |
| `threat_type_severity` | 30% | 100% — ทุก doc มี threat_type อย่างน้อย "Unknown" |
| `cross_source` | 20% | 100% logic (แต่ 99.99% docs = single source) |
| `high_risk_keywords` | 10% | 97% (malware substring match) |
| `threat_actor` | 10% | 0.3-5% (data-limited) |
| `mitre_techniques` | 5% | 98% (Phase 1.10 mapping) |

### 4.2 Decay Factor

อายุ IOC มีผลกับ score (older = less relevant):

| ioc_age_days | Multiplier |
|:------------:|:----------:|
| 0-7 | 1.00 |
| 8-30 | 0.95 |
| 31-90 | 0.85 |
| 91-180 | 0.78 |
| 181-365 | 0.72 |
| > 365 | 0.65 |

### 4.3 Sector Multiplier (operational rule)

ภาคเศรษฐกิจที่กระทบสูง → คะแนนคูณเพิ่ม (multiplier เล็กน้อยแบบ % bonus)

สูตรจริงในโค้ด: `total = total × (1.0 + SECTOR_RISK_BONUS / 100)` cap ที่ 100

| Sector | Bonus | Multiplier |
|--------|:----:|:-----:|
| critical_infrastructure | +15 | × 1.15 |
| government | +12 | × 1.12 |
| healthcare | +10 | × 1.10 |
| financial | +10 | × 1.10 |
| technology | +5 | × 1.05 |
| education | 0 | × 1.00 |
| general | 0 | × 1.00 |

**Guardrails** (ลด bonus ลงในเคสที่ไม่มั่นใจ):
- ถ้า sector classification confidence < 0.45 → bonus cap ที่ +5
- ถ้า source ทั้งหมดเป็น news (ไม่มี trusted intel) → bonus cap ที่ +3

หมายเหตุ: `config.SECTORS[sector]["weight"]` (1.5/1.4/1.3 ฯลฯ) เป็น metadata ที่ classifier คืนกลับ — **ไม่ได้ใช้ในสูตร scoring จริง** ค่า multiplier จริงมาจาก `SECTOR_RISK_BONUS`

### 4.4 Policy Gate (Reliability Cap)

**กฎ:** ถ้า IOC มาจาก news source เดียวเท่านั้น (ไม่มี trusted intel corroboration) → cap ที่ medium severity (≤49)

**เหตุผล:** news article อาจ rumor/unverified — ไม่ควรให้ critical score โดยไม่มี multi-source confirm

### 4.5 Severity Thresholds

| Score | Severity | Thai |
|:-----:|:--------:|:----:|
| 0 | clean | ปลอดภัย |
| 1-24 | low | ต่ำ |
| 25-49 | medium | ปานกลาง |
| 50-74 | high | สูง |
| 75-100 | critical | วิกฤต |

### 4.6 Phase 1.16 — ทำไมตัด confidence multiplier ออก

**ก่อนหน้า:** `threat_type_score × ai_confidence` — แต่ ML confidence 0.34 สำหรับ cyberint descriptions สั้นๆ → กดคะแนนลง 66%

**ปัญหา:** 99.93% docs ใช้ `source_rule` mode (ไม่ใช่ ML prediction) — confidence multiplier กดทั้งที่ไม่เกี่ยวเลย

**Fix:** ตัด multiplier ออก — แต่ source quality factor + cross_source factor ก็ทำหน้าที่ "trust differentiation" อยู่แล้ว ไม่ใช่ double-counting

**ผล:** v2 distribution medium 6.48% → 72.51% (cyberint single-source malware ถูก band ขึ้นมาจาก "low" เป็น "medium" ตามจริง)

### 4.7 ทำไม sha256 (90% corpus) ติดเพดาน "general" sector

- hash ตัวเองไม่มี semantic — ไม่ extract sector ได้
- WHOIS ไม่ apply (ไม่มี domain)
- description ส่วนใหญ่เป็น generic AV signature (`Trojan.GenericKD.123`)
- **ทางเดียว = data ใหม่จากต้นทาง** (sandbox analysis, MISP feed ที่มี sector galaxy)

---

## 5. Configuration — Environment Variables

### 5.1 Production (`.44`)

```bash
# Datalake (read-only cyberint feed)
DATALAKE_ELASTICSEARCH_URL=http://192.168.100.41:9201
DATALAKE_INDEX=tcti-feeds
DATALAKE_USERNAME=ibiz
DATALAKE_PASSWORD=123456
DATALAKE_READONLY=true
DATALAKE_QUERY_MODE=all
DATALAKE_SCAN_BATCH_SIZE=200
DATALAKE_SCAN_MAX_PAGES=50

# Warehouse (writable, no auth)
WAREHOUSE_ELASTICSEARCH_URL=http://192.168.100.43:9200
WAREHOUSE_INDEX=cyber-logs-datawarehouse
PROCESSED_INDEX=cyber-logs-processed

# AI Service
AI_SERVICE_API_KEYS=<comma-separated keys>
AI_SERVICE_REQUIRE_AUTH=true
DEVICE=cpu

# Pipeline
PIPELINE_SCHEDULER_ENABLED=true
PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS=600
PIPELINE_SCHEDULER_LIMIT=10000
PIPELINE_RULE_SOURCE_TYPES=customer-datalake,misp,external-feed  # code default: ...+sandbox
PIPELINE_ML_MIN_CONTEXT_CHARS=150  # code default — production .env may override to 300

# Scoring (rarely overridden)
SCORE_MODEL_VERSION=scoring-v3.0.0
SCORE_CONFIG_VERSION=weights-v2-ioc-aware
```

### 5.2 Servers

| IP | Role | Auth |
|----|------|------|
| `192.168.100.41` | Datalake ES (cyberint feed) | ibiz/123456 |
| `192.168.100.43` | Warehouse ES | no auth |
| `192.168.100.44` | AI Service + Docker host | worlddev/W0rld@1234 |

---

## 6. การ Deploy + การรัน Pipeline

### 6.1 Auto-deploy (Production)

มี **cron auto-deploy** ที่ `.44` รันทุก 5 นาที (`/home/worlddev/scripts/auto-deploy.sh`):

1. Poll `origin/main` ของ repo
2. ถ้ามี commit ใหม่ → `git pull`
3. Build Docker image ใหม่ (tag = `tcti-ai-service-cpu:YYYYMMDD-HHMM-{commit-short}`)
4. `docker compose up -d --force-recreate ai-service`

**เพราะฉะนั้น:** push to main → auto-deploy ภายใน 5 นาที 🚀

**ตรวจสถานะ deploy:**
```bash
ssh worlddev@192.168.100.44 "docker ps --filter name=ai-service"
ssh worlddev@192.168.100.44 "tail -20 ~/auto-deploy.log"
```

### 6.2 Trigger pipeline manually

```bash
curl -X POST http://192.168.100.44:8000/pipeline/run \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <YOUR_KEY>" \
  -d '{"limit": 1000}'
```

### 6.3 รัน reseed บน warehouse ใหม่ (เช่น v3)

ใช้ docker container แยกที่ target index อื่น:

```bash
ssh worlddev@192.168.100.44 'docker run -d --name tcti-ai-v3-reseed \
  --network app_default \
  -v app_ai-model-cache:/root/.cache/huggingface \
  -e WAREHOUSE_INDEX=cyber-logs-datawarehouse-v3 \
  -e PROCESSED_INDEX=cyber-logs-processed-v3 \
  -e PIPELINE_SCHEDULER_ENABLED=false \
  -e AI_SERVICE_REQUIRE_AUTH=false \
  ... (rest of env vars) \
  tcti-ai-service-cpu:<latest-tag>'

# จากนั้น loop /pipeline/run
docker exec tcti-ai-v3-reseed curl -X POST http://localhost:8000/pipeline/run \
  -H "Content-Type: application/json" \
  -d '{"limit": 1000}'
```

---

## 7. ข้อมูลต้นทาง (Data Sources)

### 7.1 Datalake (.41)

**ปัจจุบัน:** มีแค่ `cyberint_iocs-*` indices = **99.99% ของ corpus**

**Schema มี 9 fields:**
- `@timestamp`, `confidence`, `description`
- `detected_activity` (malware_payload / phishing_website / cnc_server / etc.)
- `id`, `ioc_type`, `ioc_value`, `observation_date`, `severity_score`

**ไม่มี:** sector field, actor field, multi-source data, enrichment

### 7.2 Warehouse-side datalake (`.43 cyber-logs-datalake`)

**1,838 docs** จาก sources ที่ไม่ใช่ cyberint:
- news (1,286) — BleepingComputer, DarkReading, The Hacker News
- feed (524) — external feeds
- suricata (22) — IDS alerts
- sandbox (6)

### 7.3 IOC Type Distribution (จาก warehouse 11M docs)

| Type | จำนวน | % | Notes |
|------|------|---|-------|
| sha256 | 9.9M | 90.0% | ไม่มี sector signal |
| url | 665K | 6.0% | classify ได้ดีด้วย Phase 1.17 |
| ip | 282K | 2.6% | GeoIP works, sector ยาก |
| domain | 157K | 1.4% | classify ได้ดีที่สุด |
| md5/sha1 | ~4 | 0% | rare |

---

## 8. Known Limitations — ข้อจำกัดที่ต้องรู้

### 8.1 Data Ceilings (แก้ด้วย code ไม่ได้)

| Issue | สาเหตุ | ทางออก |
|-------|--------|--------|
| `cross_source` max 20 | datalake 99.99% = cyberint single-source | รอ datalake onboard sources ใหม่ |
| `threat_actor` coverage 0.3-5% | cyberint description = AV signature only | รอ feed ที่มี actor metadata |
| `target_sector` 87-95% "Other" | 90% corpus = sha256 hash (no sector signal) | รอ sandbox analysis หรือ MISP galaxy tags |
| `domain_age` 3-4% coverage | 90% corpus = hash (no domain) | ตัดออกจาก scoring แล้ว (Phase 1.11) |
| `geo_country` 3.57% | IP IOCs only | natural limit |

### 8.2 Test Warehouse Results

มี 2 ชุดข้อมูลทดสอบในระบบ:

**v2 (76,952 docs)** — seed ด้วย Phase 1.16 code (ก่อนเพิ่ม sector expansion)
```
Severity:
  medium:    72.51%  ← single-source cyberint malware
  low:       27.37%  ← phishing, low-severity
  high:       0.12%  ← multi-source หรือ actor-enriched
  critical:   0%     ← ต้อง multi-source + actor + ransomware
avg score:  25.2

Sector:
  general:                 95.58%  ← Phase 1.16 baseline (ก่อน Thai/intl brand expansion)
  critical_infrastructure:  1.83%
  technology:               1.48%
  financial:                0.96%
  ...
```

**v3 (3,934 docs)** — re-seed ด้วย Phase 1.17 code ผ่าน `/pipeline/run` (E2E verified)
```
Severity:
  medium:    72.70%   ← match v2 (Phase 1.16 scoring ไม่ได้เปลี่ยน)
  low:       26.03%
  high:       1.27%   ← sample variance (3.9K vs 76.9K)
  critical:   0%
avg score:  25.9

Sector (Phase 1.17 improvement):
  general:                 87.19%  ← ลดจาก 95.58% (-8.4 จุด ✅)
  technology:               6.51%  ← เพิ่ม 4x (intl SaaS phish: MS/Google/AWS/Facebook)
  critical_infrastructure:  3.08%
  financial:                1.93%  ← Thai banks + intl crypto/bank phish
  government:               1.12%
  education:                0.15%
  healthcare:               0.03%
```

**สรุป Phase 1.17 effect:** Severity ไม่เปลี่ยน (scoring formula เดิม), Sector "Other" ลด 95.58% → 87.19% (-8.4 จุด) จากการเพิ่ม keyword/domain list ของ Thai brands + international phish targets

### 8.3 Operational Limits

1. **Incremental clustering non-globally-consistent** — cluster labels ต่าง batch ไม่ต่อเนื่อง → ควรรัน rescore เป็นระยะ
2. **WHOIS rate limit** — public WHOIS ห้าม query เยอะเกินไป (LRU cache ช่วย แต่จำกัด)
3. **ML zero-shot CPU latency** — ~1-3 วินาที/inference → ไม่เหมาะรันบน 100% docs (จึงใช้ rule mode 99.93%)

---

## 9. Troubleshooting + วิธีตรวจสอบ

### 9.1 Pipeline ไม่ run / ไม่มี doc เข้า warehouse

```bash
# 1. Check container health
ssh worlddev@192.168.100.44 "docker ps --filter name=ai-service"

# 2. Check recent logs
ssh worlddev@192.168.100.44 "docker logs --tail 50 tcti-ai-service"

# 3. Manual trigger pipeline
curl -X POST http://192.168.100.44:8000/pipeline/run \
  -H "X-API-Key: <KEY>" -d '{"limit": 100}'

# 4. Check datalake has unprocessed docs
curl "http://192.168.100.43:9200/cyber-logs-processed/_count"
curl "http://ibiz:123456@192.168.100.41:9201/tcti-feeds/_count"
```

### 9.2 Score ดูแปลก / Distribution ผิด

```bash
# Check current score_model_version
curl "http://192.168.100.43:9200/cyber-logs-datawarehouse/_search?size=1&filter_path=hits.hits._source.score_model_version"

# Check severity distribution
curl -X POST "http://192.168.100.43:9200/cyber-logs-datawarehouse/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":0,"aggs":{"sev":{"terms":{"field":"ai_severity"}}}}'
```

### 9.3 Sector ทุกอันเป็น "Other"

ตรวจ:
1. IOC types — sha256 จะเป็น "Other" by design (no signal)
2. Domain/URL — เช็คว่า hostname token มี match กับ keyword/domain ใน config.SECTORS ไหม
3. Run sector_classifier locally:
```python
from models.sector_classifier import classify_sector
result = classify_sector(ioc_value="scb.co.th", ioc_type="domain")
print(result["sector"])  # → "financial"
```

### 9.4 Container OOM / slow

- ML zero-shot model takes ~1.5GB RAM
- ใช้ DEVICE=cpu (ไม่ต้อง GPU)
- ถ้าใช้ resource สูง → ลด `PIPELINE_SCHEDULER_LIMIT` หรือ batch size

---

## 10. ภาคผนวก: ไฟล์สำคัญที่ควรรู้

```
ai-service/
├── main.py                          # FastAPI + scheduler entrypoint
├── elastic_client.py                # ES wrapper (datalake + warehouse + state)
├── datalake_adapters.py             # Schema normalization per source type
├── config.py                        # SECTORS, THREAT_LABELS, SCORING_WEIGHTS, etc.
├── pipeline_classification_policy.py # rule vs ML decision
│
├── models/
│   ├── classifier.py                # NLP zero-shot (threat + sector)
│   ├── sector_classifier.py         # Keyword fallback (Thai + intl brands)
│   ├── scorer.py                    # 6-factor risk scoring
│   ├── actions.py                   # Recommended SOC actions
│   ├── validation.py                # warehouse_eligible check
│   ├── relationship_graph.py        # IOC relationship links
│   ├── campaign_clusterer.py        # IOC clustering
│   ├── forecaster.py                # Trend forecasting
│   └── ...
│
├── utils/
│   ├── pipeline_documents.py        # ⭐ build_enriched_ioc_document (heart)
│   ├── whois_enrichment.py          # WHOIS domain age
│   ├── geoip_enrichment.py          # MaxMind GeoLite2 country
│   ├── threat_actor_enrichment.py   # Malware family → actor
│   └── sanitizer.py                 # PII / sensitive field stripping
│
├── services/
│   ├── dashboard_router.py          # Dashboard API endpoints (Phase 2 — pending audit)
│   ├── external_sharing_router.py   # TLP/sharing API (Phase 2 — pending audit)
│   └── dashboard_compat_router.py   # Backward-compat wrapper
│
├── data/
│   ├── GeoLite2-Country.mmdb        # GeoIP database
│   └── mitre_attack_actor_mapping.json # 98 malware families → actor mapping
│
├── tests/
│   ├── test_scorer.py
│   ├── test_scorer_boundaries.py            # Phase 1.16 boundary tests
│   ├── test_scorer_phase_1_16_regression.py # confidence multiplier guard
│   ├── test_pipeline_documents_evidence.py
│   ├── test_pipeline_edge_cases.py          # Phase 1.16 pipeline edge cases
│   ├── test_sector_nlp.py
│   ├── test_sector_classifier_thai.py       # Phase 1.17 Thai sector tests
│   └── ... (231 tests total, 2 skipped)
│
├── Dockerfile
└── requirements.txt
```

### 10.1 Test Suite

```bash
# Run all tests (no docker needed for unit tests)
python3 -m pytest tests/ -q --timeout=30
# Expected: 231 passed, 2 skipped, 4 errors (fastapi tests — Docker-only)
```

### 10.2 Key Scripts

```
scripts/
├── dev/
│   ├── seed_dashboard_fixture.py        # Synthetic UAT fixture data
│   ├── smoke_dashboard_contract.py      # Dashboard API contract tests
│   ├── smoke_dashboard_live.py          # Live dashboard smoke
│   └── verify_models.py                 # Verify ML models load
└── ops/
    ├── backfill_geoip.py                # Backfill GeoIP for old IPs
    ├── backfill_targeted_datalake_sources.py
    ├── build_golden_news_fixture.py
    ├── export_tableau_warehouse_csv.py  # Export for Tableau
    └── import_to_datalake.py
```

---

## 📞 Contacts & References

- **Repo:** `ncsa-dashboard-model` (branch: `main`)
- **MITRE ATT&CK reference:** v14.1 (used for actor + technique mapping)
- **PDF spec:** `docs/...` — original scoring design document
- **Phase commit log:** `git log --oneline ai-service/` shows all 17 phases

---

## 🏁 สรุปสำหรับผู้รับมอบ

1. **Pipeline ทำงานอัตโนมัติทุกชั่วโมง** ผ่าน scheduler — ไม่ต้องแตะ
2. **Push to main → auto-deploy ใน 5 นาที** — CI/CD ทำให้
3. **Scoring ถูก calibrate แล้ว** ตาม Phase 1.17 — score 25 = medium คือคำตอบที่ถูกต้องสำหรับ single-source cyberint
4. **Sector "Other" 87-95% = data limitation** ไม่ใช่ bug — ต้องรอ source ใหม่ที่มี sector tag
5. **Phase 2 ยังไม่ได้ audit** — `services/dashboard_router.py` (7,901 บรรทัด) + `external_sharing_router.py` (1,219 บรรทัด) — ระวัง bug ที่ user-facing
6. **231 tests pass** — รัน `pytest tests/` ก่อน merge ทุกครั้ง

---

*เอกสารนี้สร้างจาก audit Phase 1a → 1.17 (48 bugs/fixes ใน 17 phases). หากมีคำถาม ดู `git log` หรือ ไฟล์ใน `tests/` ที่อธิบาย behavior expected ของแต่ละ component.*
