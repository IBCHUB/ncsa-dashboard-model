# E2E Pipeline Analysis Report

> Generated: 2026-03-24

## Source Data: source-enrichment-23032026.json

| Metric | Value |
|--------|-------|
| Total source records | 2,006 |
| Valid IOC records (with value) | 1,971 |
| Dropped (no IOC value) | 35 |

---

## Field Coverage After Fix

| Field | Total | Non-Empty | Coverage | Status |
|-------|-------|-----------|----------|--------|
| ioc_value | 1,971 | 1,971 | 100.0% | ✅ |
| ioc_type | 1,971 | 1,971 | 100.0% | ✅ |
| source_name | 1,971 | 1,971 | 100.0% | ✅ |
| source_type | 1,971 | 1,971 | 100.0% | ✅ |
| source_id | 1,971 | 1,971 | 100.0% | ✅ NEW |
| source_url | 1,971 | 1,892 | 96.0% | ✅ NEW |
| reference | 1,971 | 1,892 | 96.0% | ✅ |
| collect_time | 1,971 | 1,971 | 100.0% | ✅ |
| event_time | 1,971 | 1,971 | 100.0% | ✅ |
| enrichment | 1,971 | 562 | 28.5% | ✅ NEW |
| domain_age_days | 1,971 | 430 | 21.8% | ✅ NEW |
| severity | 1,971 | 562 | 28.5% | ⚠️ |
| confidence | 1,971 | 269 | 13.6% | ✅ NEW |
| geo_country | 1,971 | 183 | 9.3% | ⚠️ Improved |
| description | 1,971 | 88 | 4.5% | ⚠️ |
| threat_type | 1,971 | 88 | 4.5% | ⚠️ |
| related_hash | 1,971 | 0 | 0.0% | ℹ️ Data source has none |
| related_domain | 1,971 | 0 | 0.0% | ℹ️ Data source has none |
| tags | 1,971 | 0 | 0.0% | ℹ️ Data source has none |

### Before vs After Fix

| Field | Before | After | Improvement |
|-------|--------|-------|-------------|
| enrichment | ❌ DROPPED | ✅ 562 records | +28.5% |
| confidence | ❌ DROPPED (scorer got 0) | ✅ 269 records | +13.6% |
| source_url | ❌ DROPPED | ✅ 1,892 records | +96.0% |
| domain_age_days | ❌ NOT COMPUTED | ✅ 430 records | +21.8% |
| source_id | ❌ DROPPED | ✅ 1,971 records | +100% |
| geo_country | ⚠️ Only geo_info.country | ✅ +enrichment fallback | Improved |

---

## Enrichment Data Breakdown

| Enrichment Type | Records | Coverage |
|-----------------|---------|----------|
| WHOIS data | 450 | 22.8% |
| Events (registration/expiry) | 393 | 19.9% |
| Domain age computed | 430 | 21.8% |
| IP info | 217 | 11.0% |
| Source confidence > 0 | 269 | 13.6% |

---

## Data Distribution

### IOC Types
| Type | Count | % |
|------|-------|---|
| CVE | 1,090 | 55.3% |
| URL | 340 | 17.3% |
| Domain | 284 | 14.4% |
| IP | 247 | 12.5% |
| Hash (md5/sha1/sha256) | 10 | 0.5% |

### Sources
| Source | Count | % | Type |
|--------|-------|---|------|
| TheHackerNews | 1,065 | 54.0% | NEWS |
| Zone-H | 561 | 28.5% | NEWS |
| DarkReading | 312 | 15.8% | NEWS |
| suricata ids | 22 | 1.1% | TRUSTED |
| Sandbox | 6 | 0.3% | TRUSTED |
| BleepingComputer | 5 | 0.3% | NEWS |

### Severity (from source)
| Severity | Count | % |
|----------|-------|---|
| empty/unknown | 1,409 | 71.5% |
| clean | 293 | 14.9% |
| medium | 116 | 5.9% |
| low | 77 | 3.9% |
| high | 76 | 3.9% |

---

## Pipeline Impact Assessment

### Scoring Improvements

1. **Domain Age Factor**: 430 records (21.8%) will now get non-zero domain_age scores
   - Previously: always 0 (unknown age)
   - Now: scored based on WHOIS registration date

2. **Source Confidence Bonus**: 269 records (13.6%) will get confidence bonus in source_quality scoring
   - Previously: `confidence * 0.2 = 0` always
   - Now: up to +20 points for high-confidence sources

3. **Source URL Traceability**: 1,892 records (96.0%) now have audit trail back to original report

### Dashboard Improvements

1. **Attack Origin Map**: IP records with enrichment.ip_info can now show coordinates
2. **WHOIS Display**: Domain IOC detail view can now show registrant, name servers, dates
3. **ASN Data**: IP IOC detail view can show ASN organization, network info

---

## Remaining Gaps (Known Limitations)

| Gap | Reason | Impact |
|-----|--------|--------|
| description empty (95.5%) | Source data lacks descriptions | AI classifier gets less text to classify |
| tags empty (100%) | Source data has no tags | No keyword enrichment from tags |
| related IOCs empty (100%) | Source data has no related hashes/domains | No pivot analysis possible |
| confidence empty (86.4%) | Most sources don't provide confidence | Scorer defaults to 0 for these |
| geo_country sparse (9.3%) | Limited geo data in source | Attack origin map limited |
| severity empty (71.5%) | Most source records lack severity | Pipeline computes AI severity instead |

### Data Quality Observations

- **CVE-heavy dataset** (55.3%): Most records are CVE mentions from news sources
- **News-dominated** (98.6%): Only 28 records from trusted intel sources (Suricata + Sandbox)
- **Sparse descriptions**: 95.5% of records have empty descriptions — classifier relies on reference URLs and threat_type fields
- **No trusted corroboration for most**: Expect high NEEDS_REVIEW rate from validation

---

## Test Results Summary

| Test Suite | Passed | Failed | New |
|------------|--------|--------|-----|
| test_dashboard_api | 7 | 2 (pre-existing) | 0 |
| test_e2e_pipeline | 9 | 0 | **9 NEW** |
| test_review_queue | 3 | 0 | 0 |
| test_sanitizer | 2 | 0 | 0 |
| test_scorer | 11 | 0 | 0 |
| test_validation | 6 | 0 | 0 |
| **Total** | **38** | **2** | **9** |

---

## Files Modified

| File | Change |
|------|--------|
| `scripts/ops/import_to_datalake.py` | +7 fields, domain_age computation, geo fallback |
| `elastic_client.py` | Datalake +6 fields, Warehouse +1 field |
| `utils/pipeline_documents.py` | domain_age extraction, source_urls, pass domain_age to scorer |
| `services/dashboard_router.py` | Enrichment fallback chains for coordinates, country, WHOIS, ASN |
| `tests/test_e2e_pipeline.py` | NEW — 9 E2E tests |
