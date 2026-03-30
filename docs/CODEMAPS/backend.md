# แผนที่โค้ด: หลังบ้าน (Backend Codemap)

> พิมพ์เขียวล่าสุด: 2026-03-30 (อิงตาม Source of Truth ล่าสุด)

## จุดเริ่มต้นระบบ (Entry Point)

`main.py` — Application Entry Point ของ FastAPI, จัดการ Auth middleware, โหลดโมเดล AI เข้า Memory ล่วงหน้าตอน Startup และเปิด CORS เพื่อให้ Frontend เชื่อมต่อได้

## ช่องทางเชื่อมต่อบริการ (API Endpoints)

### แกนหลัก AI (ต้องการ X-API-Key)
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | / , /health | ตรวจสอบสถานะระบบและสถานะการโหลดโมเดล |
| POST | /classify | จำแนกประเภทภัยคุกคามด้วย NLP |
| POST | /score | คำนวณคะแนนความเสี่ยงแบบ Multi-factor |
| POST | /enrich | รันทั้ง Classification และ Scoring ในคำขอเดียว |
| POST | /enrich/batch | รัน Enrichment แบบ Batch สำหรับหลายรายการพร้อมกัน |
| POST | /translate | แปลข้อความเป็นภาษาไทยผ่านโมเดล Offline (Huggingface) |

### Pipeline (ต้องการ X-API-Key)
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| POST | /pipeline/run | ประมวลผลเอกสารที่รอดำเนินการใน Data Lake |
| GET | /pipeline/status | ตรวจสอบจำนวนข้อมูลใน Elasticsearch และสุขภาพโดยรวม |
| POST | /elasticsearch/setup | สร้าง Index ของ Elasticsearch หากยังไม่มี |

### Dashboard API — Prefix `/api/v1` (ต้องการ JWT Bearer Token)

#### Authentication
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| POST | /auth/login | เข้าสู่ระบบเพื่อรับ JWT Token |
| GET | /auth/me | ดูข้อมูล Profile ของผู้ใช้ปัจจุบัน |
| POST | /auth/logout | ยกเลิก Session |

#### Executive Dashboard
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /executive/dashboard | แสดง KPI, แนวโน้มการโจมตี และกราฟพยากรณ์ |

#### Operations Dashboard
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /operations/dashboard | ภาพรวมสนามรบ (ความรุนแรง, แหล่งข่าว, Heatmap) |
| GET | /operations/reports/{key} | รายงานแยกตามแหล่งข่าว, รูปแบบภัย, ที่ตั้งทางภูมิศาสตร์ และอุตสาหกรรมเป้าหมาย |
| GET | /operations/attack-time-report | ตารางรายงานเวลาการโจมตีพร้อมรายการ IOC |
| GET | /operations/events/{id} | รายละเอียดเชิงลึกของแต่ละเหตุการณ์ |

*(หมายเหตุ: ระบบ Action / Action Center ถูกถอดออกจากระบบแล้ว)*

#### IOC Management
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /iocs | รายการ IOC พร้อม Filter |
| GET | /iocs/{id} | รายละเอียด IOC รายการเดียว |
| GET | /iocs/{id}/events | Timeline เหตุการณ์ของ IOC นั้น |
| GET | /ioc-analytics | ภาพรวม Analytics ของ IOC ทั้งหมด |

#### Reports & Exports
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| POST | /reports/executive/preview | ดู Preview รายงาน Executive ก่อน Export |
| POST | /reports/executive/export | Export รายงาน Executive (ส่งคืน HTTP 202) |
| POST | /reports/operations/{key}/preview | ดู Preview รายงาน Operations ก่อน Export |
| POST | /reports/operations/{key}/export | Export รายงาน Operations (ส่งคืน HTTP 202) |
| POST | /reports/ioc/preview | ดู Preview รายงาน IOC ก่อน Export |
| POST | /reports/ioc/export | Export รายงาน IOC (ส่งคืน HTTP 202) |
| POST | /reports/most-frequent-threats/preview | ดู Preview รายงานภัยคุกคามที่พบบ่อยที่สุด |
| GET | /exports/{id} | ดาวน์โหลดไฟล์ Export |

#### News Feed
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /news | รายการข่าวสารพร้อม Pagination |
| GET | /news/{id} | รายละเอียดข่าวแต่ละรายการ |

#### Lookup Tables
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /lookups/threat-types | รายการประเภทภัยคุกคามที่รองรับ |
| GET | /lookups/severities | รายการระดับความรุนแรง |
| GET | /lookups/risk-levels | รายการระดับความเสี่ยง |
| GET | /lookups/sources | รายการแหล่งข่าวที่รองรับ |
| GET | /lookups/export-formats | รูปแบบ Export ที่รองรับ |
| GET | /lookups/assignees | รายการผู้ใช้งานสำหรับมอบหมายงาน |
| GET | /lookups/enforcement-points | รายการ Firewall Enforcement Point |

#### Account & User Management
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /account/profile | ดู Profile ของตัวเอง |
| PATCH | /account/profile | แก้ไข Profile ส่วนตัว |
| POST | /account/password/reset | เปลี่ยนรหัสผ่าน |
| DELETE | /account | ลบบัญชีผู้ใช้ |
| GET | /users | รายการผู้ใช้ทั้งหมดในระบบ |
| POST | /users | สร้างบัญชีผู้ใช้ใหม่ |
| PATCH | /users/{id} | แก้ไขข้อมูลบัญชีผู้ใช้อื่น |
| DELETE | /users/{id} | ลบบัญชีผู้ใช้ออกจากระบบ |

#### User Groups
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /user-groups | รายการกลุ่มผู้ใช้ปัจจุบัน |
| POST | /user-groups | สร้างกลุ่มผู้ใช้ใหม่ |
| PATCH | /user-groups/{id} | แก้ไขข้อมูลกลุ่มผู้ใช้ |
| DELETE | /user-groups/{id} | ลบกลุ่มผู้ใช้ |

#### Notifications
| Method | Path | คำอธิบาย |
|--------|------|---------| 
| GET | /notifications | รับการแจ้งเตือนของผู้ใช้ |
| POST | /notifications/{id}/read | ทำเครื่องหมายอ่านแล้ว |
| POST | /notifications/read-all | ทำเครื่องหมายอ่านแล้วทั้งหมด |

### Legacy Routes (Compat Routes: Redirect ไปยัง `/api/v1`)
| Legacy Path | Redirect ไปยัง |
|------|---------| 
| /login | /api/v1/auth/login |
| /dashboard | /api/v1/operations/dashboard |
| /incidentbyseverity | operations severity breakdown |
| /attacktime | operations heatmap |
| /intelligencesources | top sources |
| /threattype | top threat types |
| /countriesbythreatassociation | top attack origins |
| /targetsectors | target sectors |
| /severity | /api/v1/lookups/severities |
| /threat-type | /api/v1/lookups/threat-types |
| /source | /api/v1/lookups/sources |
| /rick-level | /api/v1/lookups/risk-levels |
| /export-type | /api/v1/lookups/export-formats |

## Models Layer

### `classifier.py`
```text
classify_threat(text, labels?, multi_label?, threshold?) → {labels, scores, threat_types, confidence, language, model_used, sector_classifications}
extract_threat_actors(text) → List[str]
extract_mitre_techniques(text) → List[str]
models_loaded() → bool
```
`sector_classifications`: รายการในรูปแบบ `{sector, confidence, label}` — ดึงข้อมูลพร้อมกันในการ Inference ครั้งเดียว (Threat และ Sector แบบ Zero-shot `multi_label=True`) ใช้ Confidence threshold ที่: `0.35`

### `scorer.py`
```text
calculate_risk_score(ioc_value, ioc_type, description, sources, country_code, domain_age_days, ioc_age_days, threat_classification?) → {risk_score, severity, breakdown, top_factors, operational_risk_score, credibility_score, impact_score}
calculate_entropy(text) → float
```

### `validation.py`
```text
evaluate_validation_status(ioc_value, ioc_type, score_result, ai_confidence, sanitization_summary?) → {validation_status, validation_reasons, warehouse_eligible, ...}
```
สถานะผลการตรวจสอบมีเพียง 2 ค่า: `validated` หรือ `rejected`

กรณี News source path: จะได้สถานะ `validated` เมื่อ `ioc_type=cve` **หรือ** `source_count >= 2` **หรือ** `ai_confidence >= 0.60` (ไม่ต้องรอการยืนยันจากมนุษย์)

### `sector_classifier.py` (Fallback: ใช้เมื่อโมเดลหลักไม่สามารถระบุ Sector ได้)
```text
classify_sector(description?, title?, ioc_value?, ioc_type?, threat_actors?, tags?) → {sector, confidence, risk_bonus, weight, ...}
```
**ระบบหลักใช้ NLP สำหรับ Sector Classification** — ผ่านการ Inference ของ DeBERTa/BGE-M3 ร่วมกับ Threat Classification (ตาม `classifier.py`) อย่างไรก็ตาม `classify_sector()` แบบ Keyword-based ยังคงทำงานเป็น Fallback เมื่อโมเดล NLP มี Confidence ต่ำกว่า `0.50` หรือไม่พบ Sector ที่มี Confidence เกิน `0.35`

Sector Risk Multiplier: การเงิน `financial(1.3x)`, รัฐบาล `government(1.4x)`, สาธารณสุข `healthcare(1.3x)`, โครงสร้างพื้นฐานสำคัญ `critical_infrastructure(1.5x)`, เทคโนโลยี `technology(1.1x)`, การศึกษา `education(1.0x)`, ทั่วไป `general(1.0x)`

*(หมายเหตุ: ฟิลด์ `classification_method` ใน scorer จะระบุว่าใช้วิธีใด: `"nlp"`, `"nlp+keyword"` หรือ `"keyword_fallback"`)*

### `campaign_clusterer.py` [HDBSCAN Clustering]
```text
extract_features(documents) → np.ndarray  # Feature vectors ขนาด 25 มิติ
cluster_iocs(documents, min_cluster_size=5, min_samples=3) → List[{ioc_value, ioc_type, cluster_label, cluster_probability}]
build_cluster_summary(documents, cluster_results) → List[Dict]
```
การจัดกลุ่มด้วย HDBSCAN ใช้ Feature ประกอบด้วย: ประเภทภัยคุกคาม (7 มิติ), ภูมิภาค (11 มิติ), อายุโดเมน, คะแนนความเสี่ยง, จำนวนแหล่งข่าว, ประเภท IOC (5 มิติ)

### `forecaster.py` [Threat Trend Forecasting]
```text
holt_winters_forecast(values, horizon, season_length=24, alpha=0.3, beta=0.1, gamma=0.3) → List[int]
seasonal_average(values, horizon, season_length=24) → List[int]
```
ใช้ Additive Holt-Winters Triple Exponential Smoothing พยากรณ์จำนวนภัยคุกคามในระดับรายชั่วโมง

### `relationship_graph.py` [Attack Relationship Graph]
```text
build_relationship_graph(documents) → {nodes: List, links: List, stats: Dict}
```
Node Types: Threat Actor, Malware, IOC, CVE, Vendor, Threat Type, Infrastructure, Campaign
Link Types: uses, classified_as, hosts, exploits, affects, targets, same_campaign

## Utils Layer

### `pipeline_documents.py`
```text
build_enriched_ioc_document(ioc_docs: List[Dict]) → Dict
parse_dt(value) → Optional[datetime]
to_iso_z(value) → Optional[str]
pick_highest_severity(values) → str
```
ลำดับการทำงาน: Aggregation → Sanitize → Classify → Score → Validate

### `sanitizer.py`
```text
sanitize_text(value) → {text, redaction_counts, sanitized, flags}
sanitize_observation_fields(descriptions, references, tags) → {descriptions, references, tags, summary}
```
ลบข้อมูลส่วนบุคคล (PII) ออก ได้แก่: Email, เลขบัตรประชาชน 13 หลัก, Bearer token, รหัสผ่าน, Private IP และหมายเลขโทรศัพท์

### `translator.py`
```text
translate_content(text, target_lang="th", context?) → str
```
แปลภาษาแบบ Offline ผ่านโมเดล Hugging Face ที่รองรับคำศัพท์ด้านไซเบอร์ ไม่เรียกใช้ External API ภายนอก พร้อมระบบ Cache เพื่อเพิ่มประสิทธิภาพ

## Services Layer

### `dashboard_router.py` — `/api/v1` Gateway ที่ดึงข้อมูลจาก ELK
เรียกใช้ `forecaster.holt_winters_forecast` เพื่อแสดงกราฟพยากรณ์บน Executive Dashboard

### `dashboard_compat_router.py` — Legacy Route Redirect ไปยัง Dashboard Router ใหม่
### `dashboard_bootstrap.py` — In-process User Store และระบบจัดการ API Key

## Elasticsearch Client (`elastic_client.py`)

```text
ElasticClient
├── search_index(index, body)
├── get_index_document(index, doc_id)
├── count_documents(index)
├── health_check()
├── create_indexes()
├── get_unprocessed_iocs(limit)
├── search_datalake_documents(query?, limit?, offset?, ...)
├── mark_as_processed(doc_id)
├── save_to_warehouse(ioc_data)
├── bulk_index_datalake(documents)
├── get_warehouse_document(doc_id)
└── update_warehouse_document(doc_id, fields)
```
จัดการ API Key แบบ Least Privilege แยกระหว่าง DATALAKE_API_KEY และ WAREHOUSE_API_KEY

*(หมายเหตุ: ฟังก์ชันการค้นหา Review queue ถูกถอดออกจากระบบแล้ว)*

## Ops Scripts

### `rebuild_warehouse.py` [อัปเดตล่าสุด]
รื้อสร้าง Data Warehouse ใหม่ทั้งหมดโดยดึงข้อมูลจาก Data Lake ประมวลผลด้วย Pipeline ล่าสุด สร้าง Campaign Cluster ด้วย HDBSCAN และสร้าง Relationship Graph

### `import_to_datalake.py`
นำเข้าไฟล์ JSON/CSV ลง Data Lake โดยไม่มีการประมวลผล

### `import_enrich.py`
นำเข้าข้อมูลและรัน AI Enrichment ครบวงจรใน One-Stop Service

## Test Coverage

| ไฟล์ทดสอบ | ขอบเขตการทดสอบ |
|-----------|--------| 
| test_campaign_clusterer.py | HDBSCAN Clustering behavior |
| test_context_builder.py | Pipeline orchestration |
| test_e2e_pipeline.py | End-to-end pipeline flow |
| test_forecaster.py | Trend forecasting |
| test_relationship_graph.py | Graph node และ link generation |
| test_dashboard_api.py | Dashboard API endpoints |
| test_scorer.py | Risk scoring calculation |
| test_sanitizer.py | PII sanitization |
| test_validation.py | Validation logic (validated/rejected) |

*(หมายเหตุ: Test case สำหรับโหมด Manual Review ถูกถอดออกจากระบบแล้ว)*
