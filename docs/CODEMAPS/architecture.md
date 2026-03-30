# แผนที่โค้ด: สถาปัตยกรรม (Architecture Codemap)

> พิมพ์เขียวล่าสุด: 2026-03-30 (อิงตาม Source of Truth ล่าสุด)

## ภาพรวมของระบบ

แพลตฟอร์ม Thailand Cyber Threat Intelligence (TCTI) — ระบบหลักทำงานด้วย Python AI Service สำหรับจำแนกประเภทภัยคุกคาม (IOC Classification), คำนวณคะแนนความเสี่ยง, จัดกลุ่มพฤติกรรมเป็นแคมเปญ (Campaign Clustering), สร้างกราฟความสัมพันธ์เพื่อระบุต้นตอ และพยากรณ์แนวโน้มล่วงหน้า

## ลำดับการไหลของข้อมูล (Data Flow)

```
[แหล่งข้อมูล/Feed ภายนอก]
          |
          | import_to_datalake.py
          v
    [ Data Lake ]
          |
          | import_enrich.py
          v
+----------- กระบวนการประมวลผล AI -----------+
|  1. Extract & Sanitize  (ลบข้อมูลขยะและ PII) |
|             |                                 |
|  2. NLP Classification  (จำแนกประเภทภัย)     |
|             |                                 |
|  3. Risk Scoring        (คำนวณคะแนนความเสี่ยง)|
|             |                                 |
|  4. Validation          (ผ่านเกณฑ์ / ปฏิเสธ) |
+---------------------------------------------+
          |
          v
  [ Data Warehouse ]
          |
          | rebuild_warehouse.py
          v
+------- การวิเคราะห์ขั้นสูง ---------+
|  - Campaign Clustering               |
|    (จัดกลุ่มภัยคุกคามที่เชื่อมโยงกัน) |
|  - Relationship Graph                |
|    (สร้างกราฟความสัมพันธ์ผู้โจมตี)    |
+--------------------------------------+
          |
          | (อัปเดตกลับลง Data Warehouse)
          v
  [ Data Warehouse ]
          |
          | API Service (FastAPI)
          v
  [ หน้า Dashboard / Report ]
```

## เซิร์ฟเวอร์หลัก (Services)

| บริการ/เซิร์ฟเวอร์ | ภาษาที่ใช้ | พอร์ตเชื่อมต่อ | เป้าหมาย |
|---------|------|------|---------| 
| `ai-service` | FastAPI + Python 3.11 | 8000 | ทำ NLP Classification, ประเมินคะแนนความเสี่ยงขั้นสูง (Advanced), ให้บริการ API สำหรับหน้า Dashboard |
| `elasticsearch` | ES 8.12 | 9200 | เก็บข้อมูลทั้งส่วนดิบ (Data Lake) และผลลัพธ์ที่ผ่านการประมวลผล (Warehouse) |

## สายโยงใยแบบแผนผังไฟล์โค้ด (Module Dependency Graph)

```text
main.py (FastAPI Application Entry Point)
├── config.py (ตัวแปรแวดล้อม, น้ำหนักคะแนน, อุตสาหกรรมเป้าหมาย, กลุ่มภัยคุกคาม (Threat Actors))
├── elastic_client.py (Elasticsearch Client สำหรับ Dual-Index พร้อมระบบ API Key แยกต่าง Index)
├── models/
│   ├── classifier.py ← ขึ้นอยู่กับ config, transformers engine, lingua language detector
│   ├── scorer.py ← อ่านกฎเกณฑ์จาก config, เรียกใช้ sector_classifier
│   ├── sector_classifier.py ← ขึ้นอยู่กับ config
│   ├── validation.py ← อ่านเกณฑ์การตรวจสอบจาก config
│   ├── campaign_clusterer.py ← ขึ้นอยู่กับ sklearn (HDBSCAN) และ numpy
│   ├── forecaster.py (Holt-Winters forecasting — ไม่มี external dependency)
│   └── relationship_graph.py (สร้าง graph โดยไม่มี external dependency)
├── services/
│   ├── dashboard_router.py ← เรียกใช้ elastic_client, dashboard_bootstrap และ forecaster
│   ├── dashboard_compat_router.py ← Legacy route bridge ที่ redirect ไปยัง dashboard_router
│   └── dashboard_bootstrap.py (จัดการข้อมูลผู้ใช้และ API Key ภายในระบบ)
├── utils/
│   ├── pipeline_documents.py ← Pipeline Controller ที่ประสานงาน classifier, scorer, validation, sanitizer
│   ├── sanitizer.py (โมดูลลบข้อมูลขยะและข้อมูลส่วนบุคคล (PII))
│   └── translator.py ← ระบบแปลภาษาผ่าน Huggingface (Offline)
├── scripts/
    ├── dev/
    │   ├── seed_dashboard_fixture.py (สร้าง Mock data สำหรับทดสอบ Dashboard)
    │   ├── smoke_dashboard_contract.py (ตรวจสอบ Contract API)
    │   ├── smoke_dashboard_live.py
    │   └── verify_models.py (ตรวจสอบสถานะการโหลดโมเดล AI)
    └── ops/
        ├── import_enrich.py
        ├── import_to_datalake.py
        └── rebuild_warehouse.py ← เรียกใช้ campaign_clusterer และ relationship_graph เพื่อสร้าง Data Warehouse ใหม่
```

## โครงสร้างพื้นฐานทางวิศวกรรม (Infrastructure)

### ระบบโครงสร้างหลัก

| ส่วนประกอบ | รายละเอียด |
|-----------|-----------|
| **Container** | Docker — `docker-compose.yml` (Local dev), `docker-compose.remote.yml` (Remote ELK) |
| **Database** | Elasticsearch 8.12 — แยก 2 Index: `cyber-logs-datalake` (ข้อมูลดิบ) และ `cyber-logs-datawarehouse` (ผลลัพธ์) |
| **API Server** | FastAPI + Uvicorn บน Python 3.11 |
| **Authentication** | `X-API-Key` สำหรับ AI Service, `JWT Bearer Token` สำหรับหน้า Dashboard, ES API Key แยกต่าง Index |

### โมเดล AI / ML ที่ใช้ในระบบ

| โมเดล | ประเภท | หน้าที่ | Library |
|-------|--------|---------|---------| 
| `MoritzLaurer/DeBERTa-v3-large-mnli-fever-anli-ling-wanli` | Zero-shot Classifier | จำแนกประเภทภัยคุกคาม (Threat & Sector) สำหรับข้อความ **ภาษาอังกฤษ** | `transformers` |
| `MoritzLaurer/bge-m3-zeroshot-v2.0` | Zero-shot Classifier (Multilingual) | จำแนกประเภทภัยคุกคาม (Threat & Sector) สำหรับ **ภาษาไทยและภาษาอื่นๆ** | `transformers` |
| `Helsinki-NLP/opus-mt-en-th` | Neural Machine Translation | แปลภาษาอังกฤษ→ไทย สำหรับบทสรุปภัยคุกคาม (Offline) | `transformers` |
| `lingua-language-detector` | Language Detection | ตรวจจับภาษาของข้อมูลก่อนส่งให้โมเดลที่เหมาะสม | `lingua` |
| `HDBSCAN` (scikit-learn) | Unsupervised Clustering | จัดกลุ่ม IOC ที่มีพฤติกรรมใกล้เคียงกันเป็นแคมเปญ (Campaign) | `scikit-learn`, `numpy` |
| `Holt-Winters` (Custom) | Time-series Forecasting | พยากรณ์ปริมาณการโจมตีล่วงหน้าด้วย Triple Exponential Smoothing | Built-in (ไม่มี external dependency) |

> **หมายเหตุ:** โมเดลทั้งหมดถูกโหลดแบบ Lazy Loading (โหลดครั้งเดียวเมื่อมี Request แรก) และเก็บ Cache ไว้ใน `/root/.cache/huggingface` สำหรับใช้งาน Offline โดยไม่ต้องเชื่อมต่ออินเทอร์เน็ต

## หลักการออกแบบระบบ (Key Design Decisions)

1. **Language-Specific Model Optimization (การประมวลผลโมเดลตามความเหมาะสมของภาษา)**: ใช้ Language Detection เพื่อเลือกใช้โมเดล NLP ที่มีประสิทธิภาพสูงสุดสำหรับแต่ละภาษา (DeBERTa สำหรับ English และ BGE-M3 สำหรับ Multilingual) แทนการใช้โมเดลเดียวครอบจักรวาล
2. **Evidence Aggregation and Validation (การหลอมรวมและตรวจสอบความน่าเชื่อถือของพยานหลักฐาน)**: รวบรวมเบาะแสจากหลายแหล่ง (Multi-source) เพื่อเพิ่มความน่าเชื่อถือ (Confidence) และลดการเกิด False Positive ก่อนที่ข้อมูลจะเข้าสู่ชั้น Data Warehouse
3. **Immutable Data Sovereignty (หลักความเป็นต้นฉบับของข้อมูลดิบ)**: ข้อมูลใน Data Lake จะถูกเก็บรักษาในสภาพเดิม (Raw State) แบบถาวร เพื่อให้สามารถประมวลผลย้อนหลัง (Reprocessing) ได้ทุกเมื่อที่มีการอัปเดตโมเดล AI หรือเกณฑ์การวัดผลชุดใหม่
4. **End-to-End Automated Pipeline (ท่อส่งข้อมูลแบบอัตโนมัติเต็มรูปแบบ)**: กำหนดให้ระบบตัดสินใจผ่าน AI และ Rules Engine (Binary Decision: Validated/Rejected) เพื่อลดระยะเวลาประมวลผลและตัดคอขวดจากการตรวจสอบด้วยมนุษย์ (No-Human-In-The-Loop)
5. **Decoupled Scoring Framework (การแยกตรรกะการประเมินออกจากซอร์สโค้ด)**: ออกแบบโครงสร้างการคิดคะแนนความเสี่ยง (Risk Scoring) ให้มีความยืดหยุ่น โดยสามารถปรับแต่งค่าน้ำหนัก (Weights) และปัจจัยความเสี่ยงได้ผ่าน Configuration โดยไม่ต้องแก้ไขโปรแกรมหลัก
6. **Unsupervised Campaign Clustering (การจัดกลุ่มพฤติกรรมผู้โจมตีที่เชื่อมโยงกัน)**: ใช้เทคนิค HDBSCAN เพื่อระบุรูปแบบแคมเปญภัยคุกคามโดยไม่ใช้ข้อมูลล่วงหน้า ช่วยให้ตรวจพบกลุ่มเป้าหมายใหม่ๆ ที่ยังไม่อยู่ในฐานข้อมูลเดิม
7. **Graph-Based Intelligence Context (การสร้างบริบทภัยคุกคามด้วยโครงสร้างกราฟ)**: เชื่อมโยงความสัมพันธ์ระหว่าง IOCs, Threat Actors และ Techniques เข้าด้วยกันแบบ Graph Network เพื่อให้เห็นความเกี่ยวพันเชิงลึกแทนการมองข้อมูลเป็นรายการแยกส่วน
8. **Predictive Cyber Analytics (การพยากรณ์เชิงรุกบนอนุกรมเวลา)**: ใช้สถิติขั้นสูงพยากรณ์แนวโน้มการโจมตี (Forecasting) เพื่อให้ทีมเฝ้าระวังสามารถคาดการณ์ช่วงเวลาที่เสี่ยงภัยและเตรียมแผนรับมือได้ล่วงหน้าเชิงรุก
9. **Idempotent Warehouse Rebuild (ความสามารถในการประมวลผลข้อมูลใหม่แบบครบวงจร)**: ออกแบบกระบวนการ Rebuild ข้อมูลที่รองรับการล้างและสร้างคันข้อมูลใหม่ทั้งหมด (Full Rebuild) ทันทีที่ระบบมีการอัปเดตโมเดล AI เพื่อให้ข้อมูลใน Warehouse ทันสมัยตามวิมานความแม่นยำล่าสุด
