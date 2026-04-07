# TCTI — AI/ML Models Documentation

โมเดล AI/ML ที่ใช้จริงในระบบ Thailand Cyber Threat Intelligence

---

## สรุปภาพรวม

ตามที่ระบุใน `docs/CODEMAPS/architecture.md` ระบบใช้โมเดล AI/ML ทั้งหมด 6 โมเดล:

| โมเดล | ประเภท | ใช้ทำอะไร | แสดงผลใน UI |
|-------|--------|-----------|-------------|
| DeBERTa-v3-large | Zero-shot Classifier | จำแนกประเภทภัยคุกคาม (Threat Types) + ภาคส่วนเป้าหมาย (Sector) + ค่า confidence สำหรับ Validation Gate — ภาษาอังกฤษ | Threat Type, Main Type, Sector, Correlation Graph |
| BGE-M3 | Zero-shot Classifier (Multilingual) | จำแนกประเภทภัยคุกคาม (Threat Types) + ภาคส่วนเป้าหมาย (Sector) + ค่า confidence สำหรับ Validation Gate — ภาษาไทยและภาษาอื่นๆ | Threat Type, Main Type, Sector, Correlation Graph |
| opus-mt-en-th | Neural Machine Translation | แปลภาษาอังกฤษ→ไทย สำหรับบทสรุปภัยคุกคาม (Offline) | บทสรุปภาษาไทยใน Report |
| lingua-language-detector | Language Detection | ตรวจจับภาษาของข้อมูลก่อนส่งให้โมเดลที่เหมาะสม | ไม่แสดงผลโดยตรง (routing เท่านั้น) |
| HDBSCAN | Unsupervised Clustering | จัดกลุ่ม IOC ที่มีพฤติกรรมใกล้เคียงกันเป็น campaign | Correlation Graph (campaign nodes) |
| Holt-Winters | Time-series Forecasting | พยากรณ์ปริมาณการโจมตีด้วย Triple Exponential Smoothing | Threat Volume Trend (เส้นประ Forecast) |

---

## 1. DeBERTa-v3-large

**Model ID:** `MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli`
**Library:** `transformers` (HuggingFace)
**ไฟล์:** `ai-service/models/classifier.py`

### ทำงานอย่างไร

Zero-shot Natural Language Inference (NLI) — โมเดลอ่านข้อความ description ของ IOC แล้วตัดสินว่าข้อความนั้น "entail" (สอดคล้อง) กับ label ใดบ้าง โดยไม่ต้อง fine-tune หรือเห็นตัวอย่าง training data ล่วงหน้า

โมเดลนี้ถูกเลือกใช้เมื่อ Lingua ตรวจพบว่าข้อความเป็น **ภาษาอังกฤษ**

Threat label และ Sector label ถูกส่งเข้า inference ในครั้งเดียวกัน (`all_labels = threat_labels + SECTOR_LABELS`) แล้ว partition ผลลัพธ์ออกจากกันทีหลัง

### Input / Output

**Input:**
- `text` — description ของ IOC
- `candidate_labels` — รายการ Threat + Sector labels รวมกัน
- `threshold` — ค่า confidence ขั้นต่ำสำหรับ threat (default 0.3)

**Output:**
- `threat_types` — ประเภทภัยคุกคามที่ผ่าน threshold
- `confidence` — คะแนนสูงสุด (0–1)
- `sector_classifications` — ภาคส่วนเป้าหมายที่ผ่าน `SECTOR_CONFIDENCE_THRESHOLD` = 0.35

### Labels ที่ใช้

**Threat Types:** Ransomware, Phishing, DDoS, Data Breach, Supply Chain Attack, Zero-Day Exploit, APT

**Sectors:** Financial Services, Government, Healthcare, Education, Critical Infrastructure, Technology

### แสดงผลใน UI

- คอลัมน์ **Threat Type** ในตาราง IOC — ป้ายสีแสดงชื่อประเภท เช่น `Phishing`, `APT`
- Panel **"AI Score Calculation Details"** → ช่อง `Main Type`
- **Correlation Graph** → node (threattype) เชื่อมกับ IP ด้วยเส้น `CLASSIFIED_AS`

---

## 2. BGE-M3

**Model ID:** `MoritzLaurer/bge-m3-zeroshot-v2.0`
**Library:** `transformers` (HuggingFace)
**ไฟล์:** `ai-service/models/classifier.py`

### ทำงานอย่างไร

Zero-shot Multilingual classifier — ใช้หลักการเดียวกับ DeBERTa แต่รองรับหลายภาษา รวมถึงภาษาไทย โมเดลนี้ถูกเลือกใช้เมื่อ Lingua ตรวจพบว่าข้อความ **ไม่ใช่ภาษาอังกฤษ**

### ความแตกต่างจาก DeBERTa

| | DeBERTa-v3-large | BGE-M3 |
|-|-----------------|--------|
| ภาษา | อังกฤษ | หลายภาษา / ไทย |
| ความแม่นยำ (EN) | สูงกว่า | ต่ำกว่าเล็กน้อย |
| ความสามารถพหุภาษา | ไม่รองรับ | รองรับ |

### Input / Output

เหมือน DeBERTa ทุกประการ — ทั้งสองโมเดลใช้ interface เดียวกันและส่ง output format เดียวกัน ระบบเลือกโมเดลโดยอัตโนมัติ

### แสดงผลใน UI

เหมือน DeBERTa — ผลลัพธ์แสดงในส่วนเดียวกันทั้งหมด นักวิเคราะห์ไม่เห็นว่าโมเดลใดถูกใช้

---

## 3. opus-mt-en-th

**Model ID:** `Helsinki-NLP/opus-mt-en-th`
**Library:** `transformers` (HuggingFace)
**ไฟล์:** `ai-service/utils/translator.py`

### ทำงานอย่างไร

Neural Machine Translation — แปลข้อความภาษาอังกฤษเป็นภาษาไทยแบบ Offline โดยใช้โมเดลที่ download มาเก็บไว้ใน cache ของ HuggingFace (`/root/.cache/huggingface`) ไม่ต้องเชื่อมต่ออินเทอร์เน็ตขณะใช้งาน

### แสดงผลใน UI

- บทสรุปภัยคุกคามภาษาไทยใน **Executive Report**

---

## 4. lingua-language-detector

**Library:** `lingua`
**ไฟล์:** `ai-service/models/classifier.py`

### ทำงานอย่างไร

Statistical Language Detection — ตรวจจับภาษาของข้อความ description ก่อนส่งให้โมเดลที่เหมาะสม:

- ตรวจพบ **ภาษาอังกฤษ** → ส่งให้ DeBERTa-v3-large
- ตรวจพบ **ภาษาอื่น** (ไทย, ญี่ปุ่น ฯลฯ) → ส่งให้ BGE-M3

โหลดแบบ Lazy Loading ครั้งเดียว (`LanguageDetectorBuilder.from_all_languages().build()`) แล้ว cache ไว้ใช้ตลอด

### แสดงผลใน UI

ไม่แสดงผลโดยตรง — ทำหน้าที่ routing เท่านั้น

---

## 5. HDBSCAN Campaign Clusterer

**Library:** `sklearn.cluster.HDBSCAN` (scikit-learn) + `numpy`
**ไฟล์:** `ai-service/models/campaign_clusterer.py`

### ทำงานอย่างไร

Hierarchical Density-Based Spatial Clustering of Applications with Noise — จัดกลุ่ม IOC ที่มีพฤติกรรมคล้ายกันเข้าด้วยกันโดยอัตโนมัติ โดยไม่ต้องกำหนดจำนวน cluster ล่วงหน้า

แต่ละ IOC ถูกแปลงเป็น feature vector 26 มิติก่อน clustering:

| Feature Group | มิติ | ตัวอย่าง |
|--------------|------|---------|
| Threat Types (one-hot) | 7 | [0,1,0,0,0,0,0] = Phishing |
| Geographic Origin (one-hot) | 11 | [0,0,1,...] = RU |
| Domain Age | 1 | จำนวนวัน (raw) |
| Risk Score | 1 | 0–100 (raw) |
| Source Count | 1 | จำนวนแหล่งข้อมูล |
| IOC Type (one-hot) | 5 | [1,0,0,0,0] = IP |
| **รวม** | **26** | |

Feature vectors ถูก normalize ด้วย `StandardScaler` ก่อนส่งให้ HDBSCAN

### Hyperparameters

- `min_cluster_size` = 5 — ต้องมี IOC อย่างน้อย 5 ตัวจึงจะเป็น cluster
- `min_samples` = 3 — core point ต้องมีเพื่อนบ้านอย่างน้อย 3 ตัว
- IOC ที่ `cluster_label = -1` = noise (ไม่อยู่ใน campaign ใด)

### ข้อจำกัดที่พบในปัจจุบัน

Feature `domain_age_days` ไม่ถูก save ลง warehouse document (ตรวจสอบจาก `pipeline_documents.py`) จึงมีค่าเป็น `0.0` เสมอสำหรับทุก document — HDBSCAN ทำงานได้ปกติแต่ feature มิตินี้ไม่มีประโยชน์

### แสดงผลใน UI

- **Correlation Graph** → campaign nodes เชื่อมกับ IOC ด้วยเส้น `SAME_CAMPAIGN`
- **Executive Report** → Campaign Summary (จำนวนและขนาด campaign)

---

## 6. Holt-Winters Forecaster

**Algorithm:** Triple Exponential Smoothing (Additive Model)
**Library:** Built-in (ไม่มี external dependency)
**ไฟล์:** `ai-service/models/forecaster.py`

### ทำงานอย่างไร

พยากรณ์ปริมาณภัยคุกคามล่วงหน้าโดยแยก time series ออกเป็น 3 ส่วน:

```
Forecast(t) = Level + Trend + Seasonal
```

- **Level (α=0.3)** — ค่าเฉลี่ยโดยรวม
- **Trend (β=0.1)** — ทิศทาง (เพิ่ม/ลด)
- **Seasonal (γ=0.3)** — รูปแบบที่ซ้ำทุก 24 ชั่วโมง

เมื่อข้อมูลประวัติมีน้อยกว่า 48 ชั่วโมง (2 รอบ) จะ fallback ไปใช้ `seasonal_average()` แทน

พยากรณ์ 3 series แยกกัน: Total Threats, Critical Threats, High Threats โดย training window = 72 ชั่วโมง, forecast window = 24 ชั่วโมง

### Input / Output

**Input:** ยอด event รายชั่วโมง, จำนวน period ที่ต้องการพยากรณ์

**Output:** รายการตัวเลขพยากรณ์ (non-negative integers)

### แสดงผลใน UI

- **กราฟ Threat Volume Trend** → เส้นประ `Forecast >` เริ่มต้นจากเวลาปัจจุบัน (ในรูปหน้าจอเริ่มหลัง 15:00)
- **Early Warning** บน Executive Dashboard — แจ้งเตือนเมื่อ forecast พุ่งสูงผิดปกติ

---

## หมายเหตุ: สิ่งที่ไม่ใช่ AI/ML

ส่วนประกอบเหล่านี้อยู่ใน pipeline เดียวกันแต่เป็น rule-based หรือสูตรคณิตศาสตร์ล้วนๆ ไม่ใช่โมเดล ML:

| ส่วนประกอบ | ประเภทจริง |
|-----------|-----------|
| Threat Actor Extraction | String matching กับ `threat_actors.json` (ค้นหาชื่อตรงๆ ใน text) |
| MITRE ATT&CK Extraction | Regex `T\d{4}` + keyword matching กับ MITRE tactic config |
| Risk Scoring (8 factors) | Weighted arithmetic formula |
| Shannon Entropy (DGA detection) | สูตรคณิตศาสตร์ |
| Sector Keyword Matching (fallback) | Rule-based lookup table |
| Validation Gate | Rule-based (threshold + source count) |
| Relationship Graph Builder | Deterministic algorithm |

---

*อ้างอิง: `docs/CODEMAPS/architecture.md` — อัพเดทล่าสุด 2026-03-30*
*วันที่จัดทำเอกสารนี้: 31 มีนาคม 2026*
