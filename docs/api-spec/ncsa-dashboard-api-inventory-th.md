# Inventory API สำหรับ `ncsa-dashboard-web`

## 1. หลักการออกแบบ

- ใช้ `ncsa-dashboard-web` เป็น source of truth ฝั่ง UI
- canonical endpoint ใช้ `/api/v1/...`
- success response ใช้ envelope มาตรฐาน `data`, `meta`, `error`
- list และ search ใช้ query มาตรฐาน `page`, `page_size`, `sort_by`, `sort_order`, `query`, `start_date`, `end_date`
- การ aggregate analytics ใช้ timezone `Asia/Bangkok`
- หน้า placeholder ล้วนจะถูก mark เป็น `deferred` และยังไม่ออกแบบ schema ลึกในรอบนี้

## 2. สถานะของหน้าที่วิเคราะห์

| หน้า | สถานะ UI | หมายเหตุ |
|------|----------|----------|
| `Login` | `implemented` | เรียก `/login` อยู่จริง |
| `Executive Dashboard` | `implemented-mock` | UI ครบ แต่ยังใช้ข้อมูล mock |
| `Operations Dashboard` | `implemented-live` | มีการเรียก analytics flat endpoints อยู่จริง |
| `Operations Detail Reports` | `implemented-mock` | หน้า detail ranking/trend มี UI ครบ |
| `Attack Time Analysis Report` | `implemented-mixed` | heatmap live, event table/detail ยัง mock |
| `Action Center` | `implemented-mock` | filters live, list/detail/action modal ยัง mock |
| `IOC Data Lake` | `implemented-mock` | filters live, list/detail/enrichment ยัง mock |
| `IOC Data Analytics` | `implemented-mock` | UI dashboard ครบ แต่ยัง mock ทั้งหมด |
| `Reports & Export` | `implemented-mock` | lookup live, preview/export ยัง mock |
| `Most Frequent Threats Report` | `implemented-mock` | filters live, log table ยัง mock |
| `Cyber News` | `implemented-mock` | source lookup live, article cards ยัง mock |
| `Settings / Account / User Management` | `implemented-mock` | CRUD flows ชัด แต่ยังไม่มี backend |
| `Notifications` | `implemented-mock` | drawer และ unread state ชัด แต่ยังไม่มี backend |
| `Threat Landscape` | `deferred` | placeholder page |
| `CVE Intelligence` | `deferred` | placeholder page |
| `News Feed` | `deferred` | placeholder page |

## 3. Canonical Endpoint Matrix

### 3.1 Auth / Session

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Request หลัก | Response หลัก |
|---------------|--------------------|--------|---------------|---------------|
| Login form | `/api/v1/auth/login` | `POST` | `username`, `password` | `access_token`, `expires_in`, `user` |
| Route guard / profile header | `/api/v1/auth/me` | `GET` | Bearer token | user session summary |
| Logout menu | `/api/v1/auth/logout` | `POST` | ไม่มี body | logout confirmation |

### 3.2 Shared Lookups

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Query | Response หลัก |
|---------------|--------------------|--------|-------|---------------|
| Threat type dropdown | `/api/v1/lookups/threat-types` | `GET` | `query?`, `active?` | `LookupItem[]` |
| Severity dropdown | `/api/v1/lookups/severities` | `GET` | `active?` | `LookupItem[]` |
| Risk level dropdown | `/api/v1/lookups/risk-levels` | `GET` | `active?` | `LookupItem[]` |
| Source dropdown | `/api/v1/lookups/sources` | `GET` | `query?`, `active?` | `LookupItem[]` |
| Export format dropdown | `/api/v1/lookups/export-formats` | `GET` | ไม่มี | `LookupItem[]` |
| Action assignee modal | `/api/v1/lookups/assignees` | `GET` | `query?`, `status?` | assignee candidates |
| Block IP modal | `/api/v1/lookups/enforcement-points` | `GET` | `query?`, `type?` | device / enforcement point list |

### 3.3 Executive Dashboard

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Query | Response หลัก |
|---------------|--------------------|--------|-------|---------------|
| Executive dashboard ทั้งหน้า | `/api/v1/executive/dashboard` | `GET` | `start_date`, `end_date` | threat level, exposure today, severity distribution, treemap, trend forecast, origin map |
| Executive export preview | `/api/v1/reports/executive/preview` | `POST` | date range + optional filters | dashboard payload เดียวกับหน้า executive พร้อม filters echo |
| Executive export job | `/api/v1/reports/executive/export` | `POST` | same filters + `export_format` | async export job |

ฟิลด์สำคัญที่ UI ใช้ใน response:

- `threat_level.level`, `threat_level.level_th`, `threat_level.score`, `threat_level.delta_percent`
- `threat_level.primary_sector.name`
- `exposure_today.total_threats`, `ioc_active`, `critical_active`, `high_active`
- `severity_distribution[]`
- `threat_volume_severity.nodes[]`
- `attack_volume_trend.points[]`, `forecast_start_index`
- `attack_origin_map.origins[]`, `target_country`

### 3.4 Operations Dashboard

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Query | Response หลัก |
|---------------|--------------------|--------|-------|---------------|
| Operations dashboard ทั้งหน้า | `/api/v1/operations/dashboard` | `GET` | `start_date`, `end_date` | overview KPI, incident by severity, attack time heatmap, top lists, target sectors |

ฟิลด์สำคัญที่ UI ใช้ใน response:

- `overview.active_ioc`, `critical_ioc_active`, `new_ioc`, `sources_active`
- `incident_by_severity[]`
- `attack_time_heatmap.mode`, `x_axis`, `y_axis`, `cells`
- `top_intelligence_sources[]`
- `top_threat_types[]`
- `top_attack_origins[]`
- `target_sectors[]`

### 3.5 Operations Detail Reports

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Query | Response หลัก |
|---------------|--------------------|--------|-------|---------------|
| หน้า detail ของ top list | `/api/v1/operations/reports/{report_key}` | `GET` | `start_date`, `end_date` | top chart, severity distribution, trend comparison, ranking table |
| Preview ก่อน export ของ operations detail | `/api/v1/reports/operations/{report_key}/preview` | `POST` | date range, filters, page/page_size | payload เดียวกับ detail report |
| Export job ของ operations detail | `/api/v1/reports/operations/{report_key}/export` | `POST` | same filters + `export_format` | async export job |
| Attack Time Analysis Report | `/api/v1/operations/attack-time-report` | `GET` | `start_date`, `end_date`, `page`, `page_size`, `query`, `threat_types[]`, `sources[]`, `severities[]` | summary cards, heatmap, paged events |
| Event detail dialog | `/api/v1/operations/events/{event_id}` | `GET` | ไม่มี | formatted event detail + raw json |

ฟิลด์สำคัญสำหรับ `report_key`:

- `summary.total_groups`, `summary.total_events`
- `filters`
- `title`
- `top_chart.items[]`
- `severity_distribution.rows[]`
- `trend_comparison.series[]`
- `ranking.items[]`, `ranking.total`, `ranking.page`, `ranking.page_size`

ฟิลด์สำคัญสำหรับ `attack-time-report`:

- `summary.peak_attack_time`
- `summary.quietest_period`
- `summary.avg_attack_rate`
- `summary.highest_day`
- `heatmap`
- `events.items[]`

### 3.6 Action Center

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Request/Query | Response หลัก |
|---------------|--------------------|--------|---------------|---------------|
| Action Center list + summary + facets | `/api/v1/actions` | `GET` | `page`, `page_size`, `query`, `start_date`, `end_date`, `threat_types[]`, `sources[]`, `severities[]`, `status[]` | counters, facets, paged action list |
| Action detail page | `/api/v1/actions/{action_id}` | `GET` | ไม่มี | action detail, context, evidence graph, owner info |
| View Related IOCs | `/api/v1/actions/{action_id}/related-iocs` | `GET` | `page`, `page_size` | related IOC list |
| Confirm transfer | `/api/v1/actions/{action_id}/assign` | `POST` | `assignee_id`, `handover_note` | updated assignee and status |
| Mark as false positive | `/api/v1/actions/{action_id}/false-positive` | `POST` | multipart: `reason_category`, `justification`, `evidence_file?` | close result + audit metadata |
| Execute block IP | `/api/v1/actions/{action_id}/block-ip` | `POST` | `target_ioc`, `enforcement_point_ids[]`, `duration_mode`, `duration_days?`, `reason` | block execution result |
| Action report preview | `/api/v1/reports/actions/preview` | `POST` | filter body เดียวกับหน้ารายการ | action summary + facets + items |
| Action export job | `/api/v1/reports/actions/export` | `POST` | same filters + optional `export_format` | async export job |

ฟิลด์สำคัญของ action list:

- `summary.total`, `open`, `in_progress`, `closed`
- `facets.threat_types[]`, `facets.sources[]`, `facets.severities[]`
- `items[].action_id`, `status`, `severity`, `title`, `ioc_type`, `context`, `sources`, `sla`, `event_time`

ฟิลด์สำคัญของ action detail:

- `owner`
- `target`
- `source`
- `source_name`
- `target_victim`
- `sector`
- `threat_type`
- `description`
- `related_evidence[]`
- `evidence_graph`
- `available_actions`

### 3.7 IOC Data Lake

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Request/Query | Response หลัก |
|---------------|--------------------|--------|---------------|---------------|
| IOC list + quick filters + facets | `/api/v1/iocs` | `GET` | `page`, `page_size`, `query`, `start_date`, `end_date`, `sources[]`, `threat_types[]`, `risk_levels[]`, `ioc_types[]`, `severities[]`, `high_risk_only`, `sort_by`, `sort_order` | summary, quick filters, facets, paged IOC list |
| IOC detail page | `/api/v1/iocs/{ioc_id}` | `GET` | ไม่มี | key identifiers, geo-location, enrichment, risk assessment |
| IOC history log | `/api/v1/iocs/{ioc_id}/events` | `GET` | `page`, `page_size` | paged observation/history list |

ฟิลด์สำคัญของ IOC list:

- `summary.total_indicators`
- `quick_filters.ioc_types[]`
- `quick_filters.severity[]`
- `facets.sources[]`, `facets.threat_types[]`, `facets.risk_levels[]`
- `items[].rank`, `ioc_value`, `ioc_type`, `severity`, `risk_score`, `threat_types[]`, `sources[]`

ฟิลด์สำคัญของ IOC detail:

- `key_identifiers`
- `risk_assessment`
- `geo_location_owner`
- `network_ownership`
- `asn_infrastructure`
- `abuse_contact`
- `score_breakdown`
- `target_sector`
- `enrichment_context`
- `history_preview`

### 3.8 IOC Data Analytics

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Query | Response หลัก |
|---------------|--------------------|--------|-------|---------------|
| IOC analytics tab data | `/api/v1/ioc-analytics` | `GET` | `tab=ioc-summary|statistics-import`, `start_date`, `end_date` | cards + charts ตาม tab |

ฟิลด์สำคัญของ `tab=ioc-summary`:

- `cards.total_ioc`, `clean_ioc`, `active_ioc`, `risk_ioc`
- `charts.ioc_by_type[]`
- `charts.ioc_by_severity[]`
- `charts.severity_by_source[]`
- `charts.severity_by_type[]`
- `charts.risk_score_distribution[]`

ฟิลด์สำคัญของ `tab=statistics-import`:

- `cards.total_import`, `successful_import`, `failed_import`, `avg_import_per_day`
- `charts.import_volume_over_time.points[]`
- `charts.ioc_by_intelligence_source[]`
- `charts.ioc_by_type[]`
- `charts.threat_type_distribution[]`
- `charts.ioc_by_severity[]`
- `charts.import_by_source[]`
- `charts.import_by_type[]`
- `charts.import_by_severity[]`

### 3.9 Reports & Export

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Request/Query | Response หลัก |
|---------------|--------------------|--------|---------------|---------------|
| IOC report preview | `/api/v1/reports/ioc/preview` | `POST` | date range, threat types, sources, IOC types, severities | summary cards + preview rows |
| IOC report export job | `/api/v1/reports/ioc/export` | `POST` | same filters + `export_format` | async export job |
| Executive report preview/export | `/api/v1/reports/executive/preview`, `/api/v1/reports/executive/export` | `POST` | date range + filters | dashboard export flow |
| Operations report preview/export | `/api/v1/reports/operations/{report_key}/preview`, `/api/v1/reports/operations/{report_key}/export` | `POST` | date range + filters | detail report export flow |
| Action report preview/export | `/api/v1/reports/actions/preview`, `/api/v1/reports/actions/export` | `POST` | list filters | action export flow |
| Most frequent threats preview | `/api/v1/reports/most-frequent-threats/preview` | `POST` | date range, threat types, severities, risk levels | detail rows |
| Export status / download | `/api/v1/exports/{export_id}` | `GET` | ไม่มี | status, file info, download url |

### 3.10 Cyber News

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Query | Response หลัก |
|---------------|--------------------|--------|-------|---------------|
| Cyber news list | `/api/v1/news` | `GET` | `page`, `page_size`, `query`, `sources[]`, `start_date`, `end_date`, `sort_by` | paged article cards |
| Cyber news detail | `/api/v1/news/{article_id}` | `GET` | `article_id`, optional date range | article detail + related IOC records |

ฟิลด์สำคัญ:

- `items[].article_id`
- `title`
- `published_at`
- `source`
- `related_ioc_count`
- `related_iocs[]`
- `references[]`
- `source_type`

### 3.11 Settings / Account / Notifications

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Request/Query | Response หลัก |
|---------------|--------------------|--------|---------------|---------------|
| Profile read | `/api/v1/account/profile` | `GET` | ไม่มี | current profile |
| Profile update | `/api/v1/account/profile` | `PATCH` | `name`, `national_id`, `phone_number`, `email`, `avatar_url?` | updated profile |
| Reset password | `/api/v1/account/password/reset` | `POST` | `current_password?`, `reset_mode`, `new_password?` | reset confirmation |
| Delete own account | `/api/v1/account` | `DELETE` | `confirmation_text`, `reason?` | delete confirmation |
| User list | `/api/v1/users` | `GET` | `page`, `page_size`, `query`, `status`, `group_ids[]` | paged users |
| Create user | `/api/v1/users` | `POST` | group, name, national_id, phone, email, password, status | created user |
| Update user | `/api/v1/users/{user_id}` | `PATCH` | partial update fields | updated user |
| Delete user | `/api/v1/users/{user_id}` | `DELETE` | ไม่มี | delete confirmation |
| User group list | `/api/v1/user-groups` | `GET` | `page`, `page_size`, `query` | paged groups |
| Create user group | `/api/v1/user-groups` | `POST` | `name`, `permissions[]` | created group |
| Update user group | `/api/v1/user-groups/{group_id}` | `PATCH` | `name?`, `permissions[]?` | updated group |
| Delete user group | `/api/v1/user-groups/{group_id}` | `DELETE` | ไม่มี | delete confirmation |
| Notifications list | `/api/v1/notifications` | `GET` | `page`, `page_size`, `unread_only`, `type`, `status` | paged notification list |
| Mark notification read | `/api/v1/notifications/{notification_id}/read` | `POST` | ไม่มี | updated notification |
| Mark all read | `/api/v1/notifications/read-all` | `POST` | `type?` | bulk update result |

### 3.12 External Threat Sharing

ข้อกำหนดเฉพาะ:

- canonical endpoint ใช้ `/api/v1/external/...`
- authentication ใช้ header `X-API-Key`
- response ยังคงใช้ envelope มาตรฐาน `data`, `meta`, `error`
- indicator identifier ภายนอกใช้รูปแบบ `ioc_type::ioc_value`
- outbound feed จะปล่อยเฉพาะ record ที่ผ่าน validation และไม่เกิน `max_tlp` ของ partner

| หน้า/ฟังก์ชัน | Canonical Endpoint | Method | Request/Query | Response หลัก |
|---------------|--------------------|--------|---------------|---------------|
| Partner profile | `/api/v1/external/profile` | `GET` | ไม่มี | partner metadata + permissions |
| IOC type lookup | `/api/v1/external/lookups/ioc-types` | `GET` | ไม่มี | IOC types ที่ partner ใช้ได้ |
| Threat type lookup | `/api/v1/external/lookups/threat-types` | `GET` | ไม่มี | threat type options |
| Severity lookup | `/api/v1/external/lookups/severities` | `GET` | ไม่มี | severity options |
| TLP lookup | `/api/v1/external/lookups/tlp-levels` | `GET` | ไม่มี | `clear`, `green`, `amber`, `red` |
| Export format lookup | `/api/v1/external/lookups/export-formats` | `GET` | ไม่มี | `json`, `csv`, `plain_text`, `suricata`, `snort` |
| Incremental sync feed | `/api/v1/external/changes` | `GET` | `cursor`, `since`, `page_size`, `tlp`, `ioc_types[]`, `threat_types[]`, `severities[]`, `updated_after` | `created[]`, `updated[]`, `revoked[]`, `next_cursor` |
| Indicator search/list | `/api/v1/external/indicators` | `GET` | `page`, `page_size`, `query`, `ioc_types[]`, `threat_types[]`, `severities[]`, `min_risk_score`, `tlp`, `start_date`, `end_date` | paged shared indicators |
| Indicator detail | `/api/v1/external/indicators/{indicator_id}` | `GET` | ไม่มี | shared IOC detail |
| Observation history | `/api/v1/external/indicators/{indicator_id}/observations` | `GET` | `page`, `page_size` | paged sightings/history |
| Relationship summary | `/api/v1/external/indicators/{indicator_id}/relationships` | `GET` | ไม่มี | related indicators, actors, MITRE, campaign graph |
| Submit single IOC | `/api/v1/external/indicators` | `POST` | IOC payload | submission receipt |
| Submit event/observation | `/api/v1/external/events` | `POST` | event payload + indicators[] | submission receipt |
| Submit bulk payload | `/api/v1/external/bulk` | `POST` | `items[]`, `default_tlp`, `dedupe_strategy` | bulk submission result |
| Submission status | `/api/v1/external/submissions/{submission_id}` | `GET` | ไม่มี | accepted/rejected/pending + normalized ids |
| Revoke submission | `/api/v1/external/submissions/{submission_id}/revoke` | `POST` | ไม่มี | revoke result + updated_count |
| Create export job | `/api/v1/external/exports` | `POST` | filters + `format` | export job status |
| Export job status | `/api/v1/external/exports/{export_id}` | `GET` | ไม่มี | `status`, `download_url`, `expires_at`, `record_count` |

## 4. Shared Schema Catalogue

| Schema | ใช้ใน endpoint |
|--------|----------------|
| `LookupItem` | dropdown/filter options |
| `PagedMeta` | list response ทุกตัว |
| `SeverityBreakdown` | executive, operations, IOC analytics |
| `TrendSeries` | executive trend, operations comparison |
| `HeatmapMatrix` | operations attack time |
| `ExportJob` | dashboard reports และ external sharing exports |
| `ActionTicket` | action center list/detail |
| `IOCRecord` | IOC list/report preview |
| `IOCEnrichment` | IOC detail |
| `PartnerProfile` | external partner profile |
| `SharedIndicator` | external indicator list/detail |
| `SharedObservation` | external observation history |
| `ChangeEvent` | external incremental sync feed |
| `SubmissionReceipt` | single indicator/event submission |
| `BulkSubmissionResult` | external bulk submit |
| `NewsArticle` | cyber news |
| `User` | settings user management |
| `UserGroup` | settings role management |
| `Notification` | navbar drawer |

## 5. Deferred Placeholder Pages

| หน้า | เหตุผลที่ defer | สถานะ |
|------|------------------|-------|
| `Threat Landscape` | ยังไม่มี field, chart, modal, หรือ filter ที่ใช้ระบุ contract ได้ | `deferred` |
| `CVE Intelligence` | ยังไม่มี list/detail schema ฝั่ง UI | `deferred` |
| `News Feed` | ยังเป็น placeholder text | `deferred` |

## 6. แนวทางใช้ inventory นี้ต่อ

1. ใช้ไฟล์นี้เพื่อยืนยันว่า UI ไหนต้องการ endpoint อะไร
2. ใช้ `ncsa-dashboard-openapi.yaml` เพื่อยืนยัน request/response schema ราย endpoint
3. ใช้ `ncsa-dashboard-compat-map-th.md` เมื่อต้องการทำ alias flat path ชั่วคราว
4. ใช้ `ncsa-dashboard-backend-gap-map-th.md` เพื่อลำดับงาน implement ฝั่ง Python/ELK
