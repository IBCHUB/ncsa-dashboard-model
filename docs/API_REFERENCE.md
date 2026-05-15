# TCTI API Reference

Last updated: 2026-05-15

This is a code-derived high-level reference. For the complete route-by-route inventory, see [API_INVENTORY.md](API_INVENTORY.md). For exact request/response schemas, inspect FastAPI OpenAPI at `/docs` on the running service.

## Core AI Service

Base local URL on `.44`:

```text
http://127.0.0.1:9000
```

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/` | none | health alias |
| `GET` | `/health` | none | service/model health |
| `POST` | `/classify` | `X-API-Key` | classify a text block |
| `POST` | `/score` | `X-API-Key` | calculate risk score |
| `POST` | `/enrich` | `X-API-Key` | classify + score one item |
| `POST` | `/enrich/batch` | `X-API-Key` | classify + score multiple items |
| `POST` | `/translate` | `X-API-Key` | translate text |
| `POST` | `/pipeline/run` | `X-API-Key` | run pipeline for a limited batch |
| `GET` | `/pipeline/status` | `X-API-Key` | ES counts and scheduler status |
| `POST` | `/elasticsearch/setup` | `X-API-Key` | create required ES indices |

## Dashboard API

Dashboard API is mounted under:

```text
/api/v1
```

Main groups in `services/dashboard_router.py`:

| Group | Paths |
| --- | --- |
| Auth | `/auth/login`, `/auth/sso/session`, `/auth/me`, `/auth/logout` |
| Lookups | `/lookups/threat-types`, `/lookups/severities`, `/lookups/risk-levels`, `/lookups/sources`, `/lookups/sectors`, `/lookups/export-formats`, `/lookups/assignees`, `/lookups/enforcement-points` |
| Executive | `/executive/dashboard` |
| Operations | `/operations/dashboard`, `/operations/reports/{report_key}`, `/operations/reports/threat-types/{threat_type}`, `/operations/attack-time-report`, `/operations/events/{event_id}` |
| Threat Intelligence | `/threat-intelligence/trend/events`, `/cve-intelligence`, `/cve-intelligence/{cve_id}`, `/threat-landscape` |
| Actions | `/actions`, `/actions/{action_id}`, `/actions/{action_id}/related-iocs`, `/actions/{action_id}/notes`, `/actions/{action_id}/assign`, `/actions/{action_id}/false-positive`, `/actions/{action_id}/block-ip` |
| IOCs | `/iocs`, `/iocs/relationships`, `/iocs/{ioc_id}`, `/iocs/{ioc_id}/events`, `/ioc-analytics` |
| Reports | `/reports/*/preview`, `/reports/*/export`, `/exports/{export_id}`, `/exports/{export_id}/download` |
| News | `/news`, `/news/{article_id}` |
| Account | `/account/profile`, `/account/password/reset`, `/account` |
| Users | `/users`, `/user-groups` |
| Notifications | `/notifications`, `/notifications/{notification_id}/read`, `/notifications/read-all` |
| ML Feedback | `/ml/feedback` backend endpoints only; no dashboard UI button currently |
| Diagnostics | `/diagnostics/data-sources` |

## Compatibility API

Legacy dashboard compatibility routes live in `services/dashboard_compat_router.py` and include old paths such as:

```text
/login
/dashboard
/incidentbyseverity
/attacktime
/intelligencesources
/threattype
/countriesbythreatassociation
/targetsectors
/threat-type
/source
/severity
/rick-level
/export-type
```

## External Sharing API

Partner sharing API is mounted under:

```text
/api/v1/external
```

Main groups:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/profile` | partner profile |
| `GET` | `/lookups/*` | IOC/threat/severity/TLP/export lookups |
| `GET` | `/changes` | change feed |
| `GET` | `/indicators` | indicator search |
| `GET` | `/indicators/{indicator_id}` | indicator detail |
| `GET` | `/indicators/{indicator_id}/observations` | observations |
| `GET` | `/indicators/{indicator_id}/relationships` | relationships |
| `POST` | `/indicators` | submit indicator |
| `POST` | `/events` | submit event |
| `POST` | `/bulk` | submit bulk indicators/events |
| `GET` | `/submissions/{submission_id}` | submission status |
| `POST` | `/submissions/{submission_id}/revoke` | revoke submission |
| `POST` | `/exports` | create export |
| `GET` | `/exports/{export_id}` | export status |
| `GET` | `/exports/{export_id}/download` | download export |
