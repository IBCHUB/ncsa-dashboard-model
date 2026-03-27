# Dead Code Analysis Report

**Project:** Cyber / ai-service
**Date:** 2026-03-24
**Estimated Dead Code:** ~430 lines removable + ~300 MB unused deps

---

## 1. UNUSED DEPENDENCIES (requirements.txt)

| Package | Size | Status |
|---------|------|--------|
| `xgboost>=2.0.0` | ~150 MB | ❌ Never imported |
| `scikit-learn>=1.4.0` | ~30 MB | ❌ Never imported |
| `pandas>=2.0.0` | ~50 MB | ❌ Never imported |
| `prophet>=1.1.0` | ~70 MB | ❌ Never imported |
| `beautifulsoup4>=4.12.0` | ~500 KB | ❌ Never imported |
| `numpy>=1.24.0` | ~30 MB | ⚠️ Transitive dep of torch (safe to unpin) |
| `sentencepiece>=0.1.99` | ~2 MB | ⚠️ Implicit runtime dep of transformers |

**Dev-only:** `requests` used only in `scripts/dev/seed_dashboard_fixture.py`
**Missing:** `PyYAML` used in `scripts/dev/generate_postman_from_openapi.py` but not declared

---

## 2. UNUSED IMPORTS (SAFE to remove)

| File | Import |
|------|--------|
| `models/classifier.py` | `THREAT_CATEGORIES` from config |
| `models/scorer.py` | `HIGH_RISK_KEYWORDS` from config |
| `models/sector_classifier.py` | `re`, `Tuple` |
| `elastic_client.py` | `helpers` from elasticsearch |
| `utils/translator.py` | `lru_cache` from functools |

---

## 3. UNUSED FUNCTIONS (SAFE to remove)

| File | Function | Reason |
|------|----------|--------|
| `models/classifier.py` | `classify_batch()` | Never called |
| `models/scorer.py` | `calculate_geo_risk()` | Disabled, hardcoded to 0 |
| `models/scorer.py` | `get_severity_level()` | Inline logic used instead |
| `models/scorer.py` | `calculate_confidence_bonus()` | Comment: "REMOVED" |
| `models/sector_classifier.py` | `classify_sector_batch()` | Never called |
| `models/sector_classifier.py` | `get_sector_summary()` | Never called |
| `models/actions.py` | `severity_label()` | Duplicate in dashboard_router |
| `utils/translator.py` | `translate_batch()` | Never called |
| `utils/translator.py` | `clear_cache()` | Never called |

---

## 4. DEPRECATED METHODS (SAFE to remove)

| File | Method | Notes |
|------|--------|-------|
| `elastic_client.py` | `save_to_processed()` | Marked deprecated, delegates to warehouse |
| `elastic_client.py` | `search_processed_documents()` | Marked deprecated |
| `elastic_client.py` | `get_processed_document()` | Marked deprecated |
| `elastic_client.py` | `update_processed_document()` | Marked deprecated |
| `elastic_client.py` | `_build_processed_doc_id()` | Never called |
| `elastic_client.py` | `search_warehouse()` | Superseded by `search_index()` |
| `elastic_client.py` | `get_warehouse_stats()` | Never called |
| `elastic_client.py` | `get_review_document()` | Duplicate of `get_warehouse_document()` |

---

## 5. UNUSED CONSTANTS/CONFIG

| File | Constant | Reason |
|------|----------|--------|
| `config.py` | `THREAT_CATEGORIES` | Imported but never used |
| `config.py` | `HIGH_RISK_KEYWORDS` (flat list) | Replaced by `_TIERED` version |
| `utils/translator.py` | `THREAT_TERM_TRANSLATIONS` | Never referenced |
| `elastic_client.py` | `PROCESSED_INDEX` + `self.processed_index` | Vestigial |

---

## 6. DEAD DOCKER/COMPOSE CONFIG

| File | Entry | Issue |
|------|-------|-------|
| `docker-compose.yml` | `CLASSIFIER_MODEL=facebook/bart-large-mnli` | No code reads this env var |
| `docker-compose.remote.yml` | `CLASSIFIER_MODEL=facebook/bart-large-mnli` | Same |
| `docker-compose.yml` | `PROCESSED_INDEX` | Index never used |
| `docker-compose.remote.yml` | `PROCESSED_INDEX` | Same |

---

## 7. DUPLICATE CODE (consolidation opportunities)

| Pattern | Locations |
|---------|-----------|
| `normalize_severity()` | `models/actions.py` + `services/dashboard_router.py` |
| `severity_label()` | `models/actions.py` + `services/dashboard_router.py` |
| `parse_dt()` | `utils/pipeline_documents.py` + `services/dashboard_router.py` + `test_support/dashboard_fake_backend.py` |

---

## 8. CLEANABLE ARTIFACTS

| Type | Location |
|------|----------|
| `__pycache__/` | 8 directories, ~872 KB |
| `.pytest_cache/` | 2 directories, ~40 KB |
| Empty `data/` dir | `ai-service/data/` (unused placeholder) |
| `integrations/__init__.py` | Re-exports never consumed |

---

## 9. SEVERITY SUMMARY

| Severity | Count | Description |
|----------|-------|-------------|
| 🟢 SAFE | 22 | Unused imports, functions, constants |
| 🟡 CAUTION | 8 | Duplicates, unused public API methods |
| 🔴 DANGER | 0 | No config/entry point deletions needed |

**Total removable:** ~430 lines of code + 5 unused packages (~300 MB)
