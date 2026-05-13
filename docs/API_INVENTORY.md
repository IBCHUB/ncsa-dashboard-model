# API Inventory

Generated from the current FastAPI source code on 2026-05-13.

This file is the complete route inventory for `ncsa-dashboard-model`. It lists every FastAPI route currently declared in:

- `ai-service/main.py`
- `ai-service/services/dashboard_router.py`
- `ai-service/services/external_sharing_router.py`
- `ai-service/services/dashboard_compat_router.py`

## Summary

| API group | Prefix | Routes |
| --- | --- | ---: |
| AI service root API | none | 10 |
| Dashboard API | `/api/v1` | 58 |
| External sharing API | `/api/v1/external` | 19 |
| Compatibility API | none | 13 |
| Total | | 100 |

## Auth Legend

| Value | Meaning |
| --- | --- |
| none | No API key or session token required by route code |
| `X-API-Key` | Requires `X-API-Key`; root AI service depends on `REQUIRE_AUTH` |
| `Bearer/cookie token` | Requires dashboard session token from `Authorization: Bearer ...` or `token` cookie |
| `internal X-API-Key` | Requires key from `AI_SERVICE_API_KEYS`; used by dashboard SSO exchange |
| `partner X-API-Key` | Requires external sharing partner API key and permission check |
| compat session | Compatibility route uses built-in compatibility user or legacy cookie behavior |

## AI Service Root API

Source: `ai-service/main.py`

| Method | Path | Auth | Handler | Purpose |
| --- | --- | --- | --- | --- |
| `GET` | `/` | none | `health_check` | Service health and classifier loaded status |
| `GET` | `/health` | none | `health_check` | Service health and classifier loaded status |
| `POST` | `/classify` | `X-API-Key` | `classify_endpoint` | Classify text into threat types, actors, and MITRE techniques |
| `POST` | `/score` | `X-API-Key` | `score_endpoint` | Calculate IOC risk score |
| `POST` | `/enrich` | `X-API-Key` | `enrich_endpoint` | Classify and score one IOC |
| `POST` | `/enrich/batch` | `X-API-Key` | `batch_enrich_endpoint` | Classify and score multiple IOCs |
| `POST` | `/translate` | `X-API-Key` | `translate_endpoint` | Translate cyber threat text |
| `POST` | `/pipeline/run` | `X-API-Key` | `run_pipeline` | Run datalake to warehouse pipeline batch |
| `GET` | `/pipeline/status` | `X-API-Key` | `pipeline_status` | Return Elasticsearch and pipeline scheduler status |
| `POST` | `/elasticsearch/setup` | `X-API-Key` | `setup_elasticsearch` | Create required Elasticsearch indices |

## Dashboard API

Prefix: `/api/v1`

Source: `ai-service/services/dashboard_router.py`

| Method | Path | Auth | Handler | Purpose |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/auth/login` | none | `dashboard_login` | Login with dashboard username/password |
| `POST` | `/api/v1/auth/sso/session` | internal `X-API-Key` | `dashboard_sso_session` | Exchange verified SSO identity for dashboard session |
| `GET` | `/api/v1/auth/me` | `Bearer/cookie token` | `dashboard_me` | Return current dashboard user |
| `POST` | `/api/v1/auth/logout` | `Bearer/cookie token` | `dashboard_logout` | Logout dashboard session |
| `GET` | `/api/v1/lookups/threat-types` | `Bearer/cookie token` | `list_threat_types` | Threat type lookup list |
| `GET` | `/api/v1/lookups/severities` | `Bearer/cookie token` | `list_severities` | Severity lookup list |
| `GET` | `/api/v1/lookups/risk-levels` | `Bearer/cookie token` | `list_risk_levels` | Risk level lookup list |
| `GET` | `/api/v1/lookups/sources` | `Bearer/cookie token` | `list_sources` | Intelligence source lookup list |
| `GET` | `/api/v1/lookups/export-formats` | `Bearer/cookie token` | `list_export_formats` | Export format lookup list |
| `GET` | `/api/v1/lookups/assignees` | `Bearer/cookie token` | `list_assignees` | Action assignee lookup list |
| `GET` | `/api/v1/lookups/enforcement-points` | `Bearer/cookie token` | `list_enforcement_points` | Enforcement point lookup list |
| `GET` | `/api/v1/executive/dashboard` | `Bearer/cookie token` | `executive_dashboard` | Executive dashboard metrics |
| `POST` | `/api/v1/reports/executive/preview` | `Bearer/cookie token` | `executive_report_preview` | Preview executive report |
| `POST` | `/api/v1/reports/executive/export` | `Bearer/cookie token` | `executive_report_export` | Create executive report export job |
| `GET` | `/api/v1/operations/dashboard` | `Bearer/cookie token` | `operations_dashboard` | Operations dashboard metrics |
| `GET` | `/api/v1/operations/reports/{report_key}` | `Bearer/cookie token` | `operations_report` | Operations report by key |
| `POST` | `/api/v1/reports/operations/{report_key}/preview` | `Bearer/cookie token` | `operations_report_preview` | Preview operations report |
| `POST` | `/api/v1/reports/operations/attack-time/export` | `Bearer/cookie token` | `attack_time_report_export` | Create attack-time report export job |
| `POST` | `/api/v1/reports/operations/{report_key}/export` | `Bearer/cookie token` | `operations_report_export` | Create operations report export job |
| `POST` | `/api/v1/reports/threat-intelligence/export` | `Bearer/cookie token` | `threat_intelligence_report_export` | Create threat intelligence report export job |
| `GET` | `/api/v1/operations/attack-time-report` | `Bearer/cookie token` | `attack_time_report` | Attack time heatmap report |
| `GET` | `/api/v1/operations/events/{event_id}` | `Bearer/cookie token` | `operation_event_detail` | Operation event detail |
| `GET` | `/api/v1/actions` | `Bearer/cookie token` | `list_actions` | Action center list |
| `POST` | `/api/v1/reports/actions/preview` | `Bearer/cookie token` | `action_report_preview` | Preview action report |
| `POST` | `/api/v1/reports/actions/export` | `Bearer/cookie token` | `action_report_export` | Create action report export job |
| `GET` | `/api/v1/actions/{action_id}` | `Bearer/cookie token` | `action_detail` | Action detail |
| `GET` | `/api/v1/actions/{action_id}/related-iocs` | `Bearer/cookie token` | `related_iocs` | Related IOCs for an action |
| `POST` | `/api/v1/actions/{action_id}/assign` | `Bearer/cookie token` | `assign_action` | Assign action to user |
| `POST` | `/api/v1/actions/{action_id}/false-positive` | `Bearer/cookie token` | `mark_false_positive` | Mark action/IOC as false positive |
| `POST` | `/api/v1/actions/{action_id}/block-ip` | `Bearer/cookie token` | `block_ip` | Create block IP action |
| `GET` | `/api/v1/iocs` | `Bearer/cookie token` | `list_iocs` | IOC list |
| `GET` | `/api/v1/iocs/{ioc_id}` | `Bearer/cookie token` | `ioc_detail` | IOC detail |
| `GET` | `/api/v1/iocs/{ioc_id}/events` | `Bearer/cookie token` | `ioc_events` | IOC event history |
| `GET` | `/api/v1/ioc-analytics` | `Bearer/cookie token` | `ioc_analytics` | IOC analytics tabs |
| `POST` | `/api/v1/reports/ioc/preview` | `Bearer/cookie token` | `ioc_report_preview` | Preview IOC report |
| `POST` | `/api/v1/reports/ioc/export` | `Bearer/cookie token` | `ioc_report_export` | Create IOC report export job |
| `POST` | `/api/v1/reports/most-frequent-threats/preview` | `Bearer/cookie token` | `most_frequent_threats_preview` | Preview most frequent threats report |
| `GET` | `/api/v1/exports/{export_id}` | `Bearer/cookie token` | `export_job` | Export job status |
| `GET` | `/api/v1/exports/{export_id}/download` | `Bearer/cookie token` | `export_download` | Download export job file |
| `GET` | `/api/v1/news` | `Bearer/cookie token` | `list_news` | News/article list |
| `GET` | `/api/v1/news/{article_id}` | `Bearer/cookie token` | `news_detail` | News/article detail |
| `GET` | `/api/v1/account/profile` | `Bearer/cookie token` | `get_profile` | Current account profile |
| `PATCH` | `/api/v1/account/profile` | `Bearer/cookie token` | `update_profile` | Update account profile |
| `POST` | `/api/v1/account/password/reset` | `Bearer/cookie token` | `reset_password` | Reset current account password |
| `DELETE` | `/api/v1/account` | `Bearer/cookie token` | `delete_account` | Delete current account |
| `GET` | `/api/v1/users` | `Bearer/cookie token` | `list_users` | User list |
| `POST` | `/api/v1/users` | `Bearer/cookie token` | `create_user` | Create user |
| `PATCH` | `/api/v1/users/{user_id}` | `Bearer/cookie token` | `update_user` | Update user |
| `DELETE` | `/api/v1/users/{user_id}` | `Bearer/cookie token` | `delete_user` | Delete user |
| `GET` | `/api/v1/user-groups` | `Bearer/cookie token` | `list_user_groups` | User group list |
| `POST` | `/api/v1/user-groups` | `Bearer/cookie token` | `create_user_group` | Create user group |
| `PATCH` | `/api/v1/user-groups/{group_id}` | `Bearer/cookie token` | `update_user_group` | Update user group |
| `DELETE` | `/api/v1/user-groups/{group_id}` | `Bearer/cookie token` | `delete_user_group` | Delete user group |
| `GET` | `/api/v1/notifications` | `Bearer/cookie token` | `list_notifications` | Notification list |
| `POST` | `/api/v1/notifications/{notification_id}/read` | `Bearer/cookie token` | `mark_notification_read` | Mark one notification as read |
| `POST` | `/api/v1/notifications/read-all` | `Bearer/cookie token` | `mark_all_notifications_read` | Mark notifications as read |
| `POST` | `/api/v1/ml/feedback` | `Bearer/cookie token` | `create_ml_feedback` | Create ML feedback record; no dashboard UI button currently |
| `GET` | `/api/v1/ml/feedback` | `Bearer/cookie token` | `list_ml_feedback` | List ML feedback records; no dashboard UI button currently |

## External Sharing API

Prefix: `/api/v1/external`

Source: `ai-service/services/external_sharing_router.py`

| Method | Path | Auth | Handler | Purpose |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/external/profile` | partner `X-API-Key` | `external_profile` | Partner profile and permissions |
| `GET` | `/api/v1/external/lookups/ioc-types` | partner `X-API-Key` | `external_ioc_types` | IOC type lookup list |
| `GET` | `/api/v1/external/lookups/threat-types` | partner `X-API-Key` | `external_threat_types` | Threat type lookup list |
| `GET` | `/api/v1/external/lookups/severities` | partner `X-API-Key` | `external_severities` | Severity lookup list |
| `GET` | `/api/v1/external/lookups/tlp-levels` | partner `X-API-Key` | `external_tlp_levels` | TLP lookup list |
| `GET` | `/api/v1/external/lookups/export-formats` | partner `X-API-Key` | `external_export_formats` | Export format lookup list |
| `GET` | `/api/v1/external/changes` | partner `X-API-Key` | `external_changes` | Incremental feed changes |
| `GET` | `/api/v1/external/indicators` | partner `X-API-Key` | `external_indicators` | Shared indicator list |
| `GET` | `/api/v1/external/indicators/{indicator_id:path}/observations` | partner `X-API-Key` | `external_indicator_observations` | Indicator observations |
| `GET` | `/api/v1/external/indicators/{indicator_id:path}/relationships` | partner `X-API-Key` | `external_indicator_relationships` | Indicator relationships |
| `GET` | `/api/v1/external/indicators/{indicator_id:path}` | partner `X-API-Key` | `external_indicator_detail` | Indicator detail |
| `POST` | `/api/v1/external/indicators` | partner `X-API-Key` | `submit_external_indicator` | Submit one partner indicator |
| `POST` | `/api/v1/external/events` | partner `X-API-Key` | `submit_external_event` | Submit one partner event |
| `POST` | `/api/v1/external/bulk` | partner `X-API-Key` | `submit_external_bulk` | Submit bulk partner indicators/events |
| `GET` | `/api/v1/external/submissions/{submission_id}` | partner `X-API-Key` | `external_submission_status` | Submission status |
| `POST` | `/api/v1/external/submissions/{submission_id}/revoke` | partner `X-API-Key` | `external_revoke_submission` | Revoke partner submission |
| `POST` | `/api/v1/external/exports` | partner `X-API-Key` | `external_export` | Create external export job |
| `GET` | `/api/v1/external/exports/{export_id}` | partner `X-API-Key` | `external_export_status` | External export job status |
| `GET` | `/api/v1/external/exports/{export_id}/download` | partner `X-API-Key` | `external_export_download` | Download external export file |

## Compatibility API

Source: `ai-service/services/dashboard_compat_router.py`

These routes preserve old PoC path names and response casing. Prefer `/api/v1/*` for new dashboard work.

| Method | Path | Auth | Handler | Purpose |
| --- | --- | --- | --- | --- |
| `POST` | `/login` | none | `compat_login` | Legacy dashboard login |
| `GET` | `/dashboard` | compat session | `compat_dashboard` | Legacy dashboard overview |
| `GET` | `/incidentbyseverity` | compat session | `compat_incident_by_severity` | Legacy severity chart |
| `GET` | `/attacktime` | compat session | `compat_attack_time` | Legacy attack-time heatmap |
| `GET` | `/intelligencesources` | compat session | `compat_intelligence_sources` | Legacy intelligence source chart |
| `GET` | `/threattype` | compat session | `compat_threat_type_chart` | Legacy threat type chart |
| `GET` | `/countriesbythreatassociation` | compat session | `compat_countries_by_threat_association` | Legacy attack origin chart |
| `GET` | `/targetsectors` | compat session | `compat_target_sectors` | Legacy target sector chart |
| `GET` | `/threat-type` | compat session | `compat_threat_type_lookup` | Legacy threat type lookup |
| `GET` | `/source` | compat session | `compat_source_lookup` | Legacy source lookup |
| `GET` | `/severity` | compat session | `compat_severity_lookup` | Legacy severity lookup |
| `GET` | `/rick-level` | compat session | `compat_risk_level_lookup` | Legacy risk level lookup; path spelling is currently `rick-level` in code |
| `GET` | `/export-type` | compat session | `compat_export_type_lookup` | Legacy export type lookup |

## Notes

- Exact request and response schemas are available from FastAPI OpenAPI on the running service at `/docs` and `/openapi.json`.
- This document is source-derived and should be refreshed whenever route decorators change.
- Dashboard web local API routes are documented in `ncsa-dashboard-web/docs/API_INVENTORY.md`.
