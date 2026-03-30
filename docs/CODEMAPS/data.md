# แผนที่โค้ด: โครงสร้างข้อมูล (Data Models Codemap)

> พิมพ์เขียวล่าสุด: 2026-03-30 (อิงตาม Source of Truth ล่าสุด)

## โครงสร้างในฐานข้อมูล Elasticsearch (Indices)

### Data Lake (`cyber-logs-datalake`)

ที่จัดเก็บข้อมูล IOC ดิบที่นำเข้าจากแหล่งข่าวภายนอก

| ฟิลด์ข้อมูล | ชนิด | คำอธิบาย |
|-------|------|---------| 
| ioc_value | keyword | ค่าของ IOC (เช่น IP, Domain, Hash) |
| ioc_type | keyword | ip, domain, url, hash, email, sha256, sha1, md5, cve |
| source_name | keyword | ชื่อแหล่งข่าวที่รายงาน |
| source_type | keyword | ประเภทแหล่งข่าว (เช่น feeds, osint) |
| confidence | integer | ค่าความเชื่อมั่นตั้งต้นจากแหล่งข่าว (0-100) |
| description | text | คำอธิบายพฤติกรรมภัยคุกคาม (free text) |
| threat_type | keyword | ประเภทภัยคุกคามตามที่แหล่งข่าวระบุ |
| severity | keyword | ระดับความรุนแรงตามที่แหล่งข่าวประเมิน |
| tags | keyword | ป้ายกำกับต่างๆ |
| reference | text | URL แหล่งอ้างอิง |
| source_url | keyword | URL ต้นทางของข่าว |
| collect_time | date | เวลาที่นำเข้าข้อมูล |
| event_time | date | เวลาที่เกิดเหตุการณ์ตามที่แหล่งข่าวระบุ |
| geo_country | keyword | รหัสประเทศ (ISO Alpha-2) |
| domain_age_days | integer | อายุโดเมน ณ วันที่นำเข้า (ถ้ามี) |
| ai_processed | boolean | สถานะการประมวลผลโดย AI (true/false) |
| created_at | date | วันที่บันทึกเอกสารนี้ |

**รูปแบบ Document ID**: `{ioc_type}:{ioc_value}:{sha1(source|source_type|event_time|collect_time|reference|desc[:256])[:24]}`

### Data Warehouse (`cyber-logs-datawarehouse`)

ข้อมูลที่ผ่านการ Sanitize, Enrich และ Validate ด้วย AI เรียบร้อยแล้ว

| ฟิลด์ข้อมูล | ชนิด | คำอธิบาย |
|-------|------|---------| 
| **Identity** | | |
| ioc_value | keyword | ค่าของ IOC |
| ioc_type | keyword | ประเภท IOC |
| **Aggregation** | | |
| sources | keyword[] | แหล่งข่าวทั้งหมดที่รายงาน IOC นี้ |
| source_types | keyword[] | ประเภทแหล่งข่าวทั้งหมด |
| source_count | integer | จำนวนแหล่งข่าวที่ไม่ซ้ำกัน |
| source_urls | keyword[] | URL แหล่งข่าวทั้งหมดที่เกี่ยวข้อง |
| first_seen | date | วันที่พบ IOC นี้ครั้งแรก |
| last_seen | date | วันที่พบ IOC นี้ล่าสุด |
| ioc_age_days | integer | อายุ IOC นับตั้งแต่ first_seen (หน่วย: วัน) |
| **AI Classification** | | |
| ai_threat_types | keyword[] | ประเภทภัยคุกคามที่ NLP ระบุ |
| ai_threat_actors | keyword[] | กลุ่มผู้โจมตีที่ระบุได้ |
| ai_mitre_techniques | keyword[] | เทคนิคการโจมตีตาม MITRE ATT&CK |
| ai_classification_confidence | float | ค่าความเชื่อมั่นของ NLP (0 ถึง 1) |
| **AI Scoring** | | |
| ai_risk_score | integer | คะแนนความเสี่ยงรวม (0-100) |
| ai_severity | keyword | ระดับความรุนแรง (critical/high/medium/low/clean) |
| ai_severity_th | keyword | ระดับความรุนแรงภาษาไทย |
| operational_risk_score | integer | คะแนนย่อยด้านผลกระทบเชิงปฏิบัติการ |
| credibility_score | integer | คะแนนย่อยด้านความน่าเชื่อถือของแหล่งข่าว |
| impact_score | integer | คะแนนย่อยด้านความรุนแรงของผลกระทบ |
| ai_score_breakdown | object | รายละเอียดคะแนนแยกตามปัจจัย |
| ai_top_factors | object | ปัจจัยหลักที่ส่งผลต่อคะแนนสูงสุด |
| ai_score_model_version | keyword | เวอร์ชันของ Scoring Model |
| ai_score_config_version | keyword | เวอร์ชันของ Scoring Config |
| **Sector** | | |
| ai_sector | keyword | อุตสาหกรรมเป้าหมาย |
| ai_sector_confidence | float | ค่าความเชื่อมั่นของการระบุ Sector |
| **Validation** | | |
| validation_status | keyword | สถานะ: `validated` หรือ `rejected` เท่านั้น |
| validation_reasons | keyword[] | รายการเหตุผลที่ถูก Reject (ถ้ามี) |
| warehouse_eligible | boolean | ผ่านเกณฑ์สำหรับบันทึกลง Warehouse (true เมื่อผ่าน) |
| **Campaign Clustering** | | |
| cluster_label | integer | รหัส Cluster (-1 = ไม่อยู่ใน Cluster ใด) |
| cluster_probability | float | ค่าความน่าจะเป็นในการเป็นสมาชิก Cluster |
| **Sanitization** | | |
| cleaning_flags | keyword[] | ป้ายกำกับระบุประเภทข้อมูลที่ถูกลบออก |
| sanitization_summary | object | สถิติการลบข้อมูล (IP, รหัสผ่าน, PII) |
| **Metadata** | | |
| processed_at | date | วันที่ AI ประมวลผลเสร็จ |
| created_at | date | วันที่บันทึกลง Data Warehouse |

**รูปแบบ Document ID**: `{ioc_type}:{sha1(ioc_type:ioc_value)[:24]}`

*(หมายเหตุ: ฟิลด์ที่เกี่ยวกับ Action Required ถูกถอดออกจากระบบแล้ว)*

## Pydantic Models สำหรับ API (API Models)

### Request Models
```text
ClassifyRequest(text, threshold=0.3)
ScoreRequest(ioc_value, ioc_type, description, sources[], country_code, domain_age_days, ioc_age_days)
EnrichRequest(ioc_value, ioc_type, description, title, sources[], country_code, domain_age_days, ioc_age_days)
BatchEnrichRequest(items: List[EnrichRequest])
TranslateRequest(text, target_lang="th", context)
CreateTicketRequest(ioc_value, ioc_type, description, risk_score, severity, threat_types[], threat_actors[])
PipelineRunRequest(limit=100)
```

### Dashboard Request Models
```text
LoginRequest(username, password)
AssignRequest(assignee_id, handover_note?)
BlockIpRequest(target_ioc, enforcement_point_ids[], duration_mode, duration_days?, reason)
ReportFilterRequest(start_date, end_date, threat_types[], sources[], ioc_types[], severities[])
ExportReportRequest(ReportFilterRequest + export_format)
DashboardDateRangeRequest(start_date, end_date)
ExecutiveReportRequest(DashboardDateRangeRequest + threat_types[], sources[], severities[])
OperationsReportRequest(DashboardDateRangeRequest + query?, filters, page, page_size)
MostFrequentThreatsRequest(start_date, end_date, threat_types[], severities[], risk_levels[])
```

### Response Models
```text
ClassifyResponse(threat_types[], confidence, all_labels[], all_scores[], threat_actors[], mitre_techniques[])
ScoreResponse(risk_score, operational_risk_score, credibility_score, impact_score, severity, breakdown, top_factors[])
EnrichResponse(IOC fields + AI results + processing_time_ms)
TranslateResponse(original, translated, target_lang, cached)
CreateTicketResponse(success, ticket_id, message, mock)
PipelineRunResponse(processed, rejected, failed, observations_updated, processing_time_ms)
HealthResponse(status, version, classifier_loaded)
ElasticsearchStatusResponse(status, datalake_index, warehouse_index, datalake_count, warehouse_count)
```

## Graph Schema

### Node Types
| ชนิด | Label มาจากฟิลด์ | Properties |
|------|-------------|------------| 
| actor | ai_threat_actors | origin, score |
| indicator | ioc_value | ioc_type, risk_score, severity |
| malware | enrichment data | family |
| cve | CVE pattern match | - |
| vendor | enrichment data | product |
| threattype | ai_threat_types | - |
| infrastructure | ASN, nameservers | - |
| campaign | cluster_label | member_count |

### Link Types
| ชนิด | โยงจาก → ไปยัง | ความหมาย |
|------|-----------|---------| 
| uses | actor → indicator | Threat Actor ใช้ IOC นี้ |
| exploits | actor → cve | Threat Actor โจมตีด้วยช่องโหว่นี้ |
| classified_as | indicator → threattype | IOC ถูกจัดประเภทเป็นภัยชนิดนี้ |
| hosts | indicator → infrastructure | IOC อยู่บน Infrastructure นี้ |
| shares_infra | indicator → infrastructure | ใช้ Infrastructure เดียวกัน |
| affects | cve → vendor | บริษัทนี้มีช่องโหว่นี้ |
| same_campaign | indicator → indicator | IOC อยู่ใน Campaign เดียวกัน |

## Campaign Clustering Features

สกัด Feature Matrix ขนาด 26 มิติต่อ 1 IOC:
| Feature | มิติ | Encoding |
|---------|-----------|----------| 
| ai_threat_types | 7 | One-hot (Ransomware, Phishing, DDoS, Data Breach, Supply Chain, Zero-Day, APT) |
| geo_country | 11 | One-hot 10 ประเทศหลัก + 1 กลุ่มอื่นๆ |
| domain_age_days | 1 | numeric, normalized |
| ai_risk_score | 1 | Raw (0-100) |
| source_count | 1 | จำนวนแหล่งข่าว |
| ioc_type | 5 | One-hot (ip, domain, url, hash, cve) |

## Scoring & Configuration (config.py)

### Scoring Weights [ผลรวม = 1.0]
| ปัจจัย | น้ำหนัก (Weight) |
|--------|--------| 
| cross_source (พบจากหลายแหล่ง) | 0.25 |
| threat_type_severity (ประเภทภัยคุกคาม) | 0.20 |
| threat_intel_source (ความน่าเชื่อถือแหล่งข่าว) | 0.15 |
| high_risk_keywords (คีย์เวิร์ดความเสี่ยงสูง) | 0.10 |
| domain_age (อายุโดเมน) | 0.10 |
| threat_actor (เชื่อมโยงกับกลุ่มผู้โจมตีที่ทราบ) | 0.10 |
| entropy (ความซับซ้อนของชื่อโดเมน) | 0.05 |
| mitre_techniques (เทคนิค MITRE ATT&CK) | 0.05 |

### Threat Actor Configuration (config.py)
ฐานข้อมูลกลุ่มผู้โจมตี 26 รายการ ประกอบด้วย: คะแนนความอันตราย (0-100), ประเทศต้นทาง, ชื่อเรียกอื่น (Aliases), เป้าหมายที่พบบ่อย, สถานะ (active/dormant/disbanded)

### Sector Risk Multipliers
| อุตสาหกรรม | Multiplier | Risk Bonus |
|--------|--------|-------| 
| critical_infrastructure (โครงสร้างพื้นฐานสำคัญ) | 1.5x | +15 |
| government (รัฐบาล) | 1.4x | +12 |
| financial (การเงิน) | 1.3x | +10 |
| healthcare (สาธารณสุข) | 1.3x | +10 |
| technology (เทคโนโลยี) | 1.1x | +5 |
| education / general (การศึกษา / ทั่วไป) | 1.0x | +0 |

### Forecaster Parameters
| พารามิเตอร์ | ค่าเริ่มต้น | คำอธิบาย |
|-----------|---------|---------| 
| season_length | 24 | รอบฤดูกาล 1 วัน (24 ชั่วโมง) |
| alpha | 0.3 | Level smoothing factor |
| beta | 0.1 | Trend smoothing factor |
| gamma | 0.3 | Seasonal smoothing factor |
