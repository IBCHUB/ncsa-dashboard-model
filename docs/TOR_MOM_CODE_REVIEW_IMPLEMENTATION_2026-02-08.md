# TOR/MOM Review Implementation Status

Date: 2026-02-08  
Scope: Code remediation based on `TOR_MOM_CODE_REVIEW_AND_AI_SCORING_2026-02-08.md`

## Summary

Implemented major remediation across `ai-service` and `dashboard`:
- Fixed P0 pipeline correctness issues (score key + cross-source aggregation + dedupe behavior)
- Implemented practical risk-score governance improvements from AI-SCORING review
- Fixed reports filters (multi-select + date/report range)
- Switched threat-level/trend widgets to API/warehouse-backed data flow
- Added alert status persistence API + lifecycle transitions + audit trail
- Added internal access control baseline (login + OTP + signed session + middleware route protection)
- Added explicit Processed layer (`tcti-processed`) between datalake and warehouse
- Synchronized documentation with actual API and scoring behavior

## Implementation Matrix

| Finding | Status | What was changed |
|---|---|---|
| [P0] AI score written with wrong key | ✅ Done | `main.py` now writes from `risk_score` |
| [P0] Cross-source pipeline not truly aggregated | ✅ Done | `/pipeline/run` groups same IOC across sources before scoring; marks all source observations processed |
| Raw / Processed / Warehouse 3-layer flow | ✅ Done | Added `tcti-processed` index and pipeline writes validated docs to processed layer before warehouse |
| Data overwrite due IOC-only IDs | ✅ Done | event-level datalake IDs (hash fingerprint) in `elastic_client.py` and `import_to_datalake.py` |
| Reports filter multi-value/date range | ✅ Done | `/api/iocs` + reports UI support multi-type, multi-severity, dateFrom/dateTo/reportType |
| Dashboard pages using stale static data | ✅ Done | Threat level/trends now use `/api/sectors`, `/api/trends`, `/api/stats` with ES-first fallback |
| Alerts lifecycle not persisted | ✅ Done | New `/api/alerts` GET/PATCH with JSON store persistence + transition rules + audit entries |
| Security hardening (CORS + default API keys) | ✅ Done | Removed wildcard+credentials CORS config; removed hardcoded default AI keys |
| CVE/stats not using AI fields consistently | ✅ Done | CVE page and stats route now prioritize `aiSeverity`/`aiThreatTypes` |
| AI-SCORING docs mismatch code | ✅ Done | Rewrote `ai-service/docs/AI-SCORING.md` to match scoring-v2 behavior |
| API docs mismatch `/pipeline/run` | ✅ Done | README/API docs updated (`limit`, response shape) |
| Auth/2FA + public/internal split (baseline) | ✅ Done (baseline) | Added `/api/auth/*`, `/login`, signed cookie session, middleware on internal routes |

## Risk Score Practical Improvements Applied

1. Consistency fix
- `total_score` -> `risk_score` pipeline write fixed
- source-level evidence retained (event-level ID)

2. Governance and determinism
- `SCORING_WEIGHTS` now actively used in final weighted score
- output includes `score_model_version`, `score_config_version`
- output includes `credibility_score` and `impact_score`

3. Double-counting mitigation
- cross-source factor redesigned with diminishing returns + source diversity bonus
- separated from source-quality contribution by weighted model

4. Keyword/Extraction quality
- keyword matching moved to boundary-aware regex (reduce substring false positives)
- MITRE extractor supports tactic names in addition to `Txxxx` IDs

5. Ops policy gates
- block Critical escalation without sufficient trusted corroboration
- cap news-only evidence below High until trusted/non-news corroboration exists
- sector bonus constrained under weak confidence/news-only cases

6. Decay consistency
- `ioc_age_days` now passed through scoring pipeline path
- score breakdown captures decay and policy adjustments

## New/Updated Key Files

### AI Service
- `/Users/mm/Desktop/Cyber/ai-service/main.py`
- `/Users/mm/Desktop/Cyber/ai-service/elastic_client.py`
- `/Users/mm/Desktop/Cyber/ai-service/config.py`
- `/Users/mm/Desktop/Cyber/ai-service/models/scorer.py`
- `/Users/mm/Desktop/Cyber/ai-service/models/classifier.py`
- `/Users/mm/Desktop/Cyber/ai-service/scripts/import_to_datalake.py`
- `/Users/mm/Desktop/Cyber/ai-service/docs/AI-SCORING.md`

### Dashboard
- `/Users/mm/Desktop/Cyber/dashboard/src/lib/elastic.ts`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/iocs/route.ts`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/stats/route.ts`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/sectors/route.ts`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/trends/route.ts` (new)
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/alerts/route.ts` (new)
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/auth/login/route.ts` (new)
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/auth/logout/route.ts` (new)
- `/Users/mm/Desktop/Cyber/dashboard/src/app/api/auth/session/route.ts` (new)
- `/Users/mm/Desktop/Cyber/dashboard/src/app/login/page.tsx` (new)
- `/Users/mm/Desktop/Cyber/dashboard/src/app/login/page.module.css` (new)
- `/Users/mm/Desktop/Cyber/dashboard/middleware.ts` (new)
- `/Users/mm/Desktop/Cyber/dashboard/src/app/reports/page.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/alerts/page.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/app/threats/cve/page.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/components/widgets/ThreatLevel.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/components/widgets/TrendPrediction.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/components/widgets/TrendChart.tsx`
- `/Users/mm/Desktop/Cyber/dashboard/src/components/layout/Sidebar.tsx`

### Docs
- `/Users/mm/Desktop/Cyber/README.md`
- `/Users/mm/Desktop/Cyber/docs/API.md`

## Verification

- Python syntax check passed:
  - `python3 -m py_compile ai-service/main.py ai-service/models/scorer.py ai-service/models/classifier.py ai-service/elastic_client.py ai-service/scripts/import_to_datalake.py`
- Next.js production build passed:
  - `npm run build` in `/Users/mm/Desktop/Cyber/dashboard`

## Remaining Notes

- Full enterprise IAM (SSO/IdP integration, RBAC matrix, device trust, MFA recovery workflows) is not part of this patch; current auth is baseline internal gate + OTP.
- Internal-only routes now include `/alerts`, `/reports`, `/ioc*`, `/graph`, `/threats/cve`, `/api/alerts*`, `/api/iocs*`, `/api/helpdesk*`.
- Repository has many pre-existing ESLint violations outside this remediation scope; build/type-check passes.
- **HelpDesk Integration:** Currently operates in mock mode by default (`HELPDESK_MOCK_MODE=true`). Set `HELPDESK_API_KEY` and `HELPDESK_MOCK_MODE=false` in production to enable real THCert HelpDesk ticket creation. Mock mode logs tickets to `/tmp/helpdesk_tickets.jsonl` for testing.

---

## Future Roadmap (ไม่รวมใน patch นี้)

1. **Calibration & Monitoring**
   - เก็บ metrics รายสัปดาห์: `%critical`, ticket conversion rate, analyst override rate, mean-time-to-ack
   - ทำ precision/recall review ต่อ severity bucket (monthly/quarterly)
   - Drift detection สำหรับ score distribution changes

2. **HelpDesk Production Enablement**
   - เชื่อมต่อ THCert HelpDesk API จริง
   - เพิ่ม policy gate ก่อนสร้าง ticket อัตโนมัติ (ต้องมี trusted corroboration)

3. **Enterprise IAM**
   - SSO/IdP integration (DITP SSO, Azure AD)
   - RBAC matrix แยก role: analyst/admin/viewer
   - Device trust และ MFA recovery workflows
