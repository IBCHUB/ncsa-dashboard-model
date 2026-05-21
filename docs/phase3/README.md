# Phase 3 — Semantic Data Correctness Audit

Verify that every label/number shown on the dashboard UI corresponds to the
correct data pulled from the data warehouse (`.43`) via the right ES query.

**Scope rule:** backend (`ai-service`) only — do NOT modify frontend
(`ncsa-dashboard-web`). If a frontend label is ambiguous, ask the user.

**Branch:** `audit/phase3-semantic-data`

**Ground truth fixtures:** `ai-service/tests/semantic/fixtures/`
- `es_mapping_warehouse.json` — field types (captured from live `.43`)
- `es_mapping_datalake.json` — field types (captured from live `.41`)
- `sample_warehouse.json` — 5 recent docs
- `sample_datalake.json` — 5 recent docs
- `warehouse_field_distribution.json` — value distributions over 11.09M docs

## Progress

| Sub | Page | Status | Doc | Bugs fixed |
|-----|------|--------|-----|-----------|
| 3.0 | Cross-cutting helpers | ✅ Done | [3.0-cross-cutting-helpers.md](./3.0-cross-cutting-helpers.md) | 3 (1 CRITICAL, 1 HIGH, 1 MED) |
| 3.1 | Executive Dashboard | ⏳ Pending | — | — |
| 3.2 | Operations Dashboard | ⏳ Pending | — | — |
| 3.3 | TI Overview + IOC Summary | ⏳ Pending | — | — |
| 3.4 | Threat Landscape | ⏳ Pending | — | — |
| 3.5 | IOC Datalake / Analytics / Threat Hunting | ⏳ Pending | — | — |
| 3.6 | TI sub-pages (×6) | ⏳ Pending | — | — |
| 3.7 | Action Center / Reports / News / CVE | ⏳ Pending | — | — |
| 3.8 | Settings / lookups / auth | ⏳ Pending | — | — |

## Per-page document format

Each `3.X-<page>.md` follows this structure:

```
# 3.X — <Page Name>

## Routes audited
- Frontend: <path to .tsx>
- API endpoints: <list>

## Label inventory (semantic map)

| UI label | Response path | Backend fn | ES field | ES agg | Formula / meaning | Verified | Bug? |
|---------|---------------|------------|----------|--------|-------------------|----------|------|

## Bugs found
- <severity> · <one-line> · <fix commit hash>

## Deferred / data-quality notes
- ...
```

## Reality baseline (from `warehouse_field_distribution.json`, 11.09M docs)

- **severity** (and `ai_severity`): `low` 11M / `medium` 40K / `critical` 8.6K / `high` 1
- **ioc_type**: `sha256` 90% / `url` 6% / `ip` 2.6% / `domain` 1.4% / others <0.01%
- **source_name**: `cyberint_iocs` 99.99%
- **validation_status**: `validated` 96.6% / `rejected` 3.4%
- **review_state**: `not_required` 99.99% / `pending_review` 1 doc
- **action_status**: `open` 96.7% / MISSING 3.3%
- **tlp**: `amber` 100%
- **warehouse_eligible**: `true` 96.6% / `false` 3.4% (= 1:1 with `validation_status`)
- **geo_country**: `None` literal 97.3% / MISSING 2.0% / real codes 0.4%
- **target_sector**: MISSING 97.9% / `general` 1.9% / others <0.1%
- **target_sector_name**: MISSING 97.9% / `Other` 1.9% / others <0.1%
- **ai_threat_types**: `Malware` 96.7% / `Phishing` 3.3% / smaller types incl. mixed case
- **threat_type**: snake_case dominates (`malware_payload` 94%) but mixed with Title Case (`Phishing` 894, `Malware` 61) — data inconsistency

## Time field availability (from existence checks on 11.09M docs)

| Field | Populated docs | Mode |
|-------|---------------|------|
| `event_time` | 11,094,748 (100%) | observed |
| `first_seen` | 11,094,748 (100%) | observed |
| `last_seen` | 11,094,748 (100%) | observed |
| `last_shared_at` | 11,094,748 (100%) | changed |
| `action_updated_at` | 10,725,075 (96.7%) | changed |
| `reviewed_at` | 0 (never populated!) | — |
| `revoked_at` | **NOT IN MAPPING** | — |
| `updated_at` | **NOT IN MAPPING** | — |
