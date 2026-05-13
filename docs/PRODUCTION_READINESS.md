# TCTI Production Readiness

Last updated: 2026-05-13

## Verdict

The pipeline and backfill path are production-capable when run with the current guards. Do not call the full pipeline as one unbounded request. Use controlled batches, resource limits, timeout guards, and processed-state cursoring.

Production sign-off still requires post-backfill data validation and dashboard validation.

## Confirmed Ready

- `tcti-ai-service` deploys and runs on `192.168.100.44`.
- Container resource guard is active: `4 CPU`, `6GB RAM`, `pids_limit=512`.
- Datalake source is read-only: `192.168.100.41:9201`, alias/index `tcti-feeds`.
- Warehouse target is `192.168.100.43:9200`, index `cyber-logs-datawarehouse`.
- Processed-state tracking uses `cyber-logs-processed`.
- Datalake cursor uses `search_after` and is persisted in the processed-state index.
- Elasticsearch writes are chunked with `ELASTIC_BULK_CHUNK_SIZE=500`.
- IOC feed classification uses rule-based classification; ML is reserved for news/report/context-rich records.
- Golden news evaluator passed `51/51` in the latest safe test.

## Confirmed Backfill Performance

Safe test results on `.44` after resource and bulk fixes:

| Limit | Elapsed | Failed | Notes |
| --- | ---: | ---: | --- |
| `10` | `0.5s` | `0` | smoke |
| `100` | `0.46s` | `0` | smoke |
| `500` | `1.09s` | `0` | smoke |
| `1,000` | `1.78s` | `0` | smoke |
| `5,000` | `7.44s` | `0` | safe |
| `10,000` | `17.7s` | `0` | safe after chunk fix |
| `25,000` | `48.4s` | `0` | safe |
| `50,000` | `92.2s` | `0` | recommended manual backfill batch |

Current manual backfill mode:

```text
batch_limit=50000
sleep_seconds=10
timeout_seconds=1800
scheduler_enabled=false
```

## Go-Live Checklist

- Wait for manual backfill to complete or intentionally stop it.
- Sample-check warehouse records from multiple schemas: canonical IOC feed, MISP, news/report, Zone-H/defacement, sandbox if present.
- Confirm dashboard counters, filters, detail pages, and exports against warehouse data.
- Decide whether `rejected` records should be hidden, visible, or exposed as a separate review/filter surface.
- Re-enable scheduler after manual backfill:

```text
PIPELINE_SCHEDULER_ENABLED=true
PIPELINE_SCHEDULER_INTERVAL_SECONDS=3600
PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS=600
PIPELINE_SCHEDULER_LIMIT=10000
```

- Replace the self-signed certificate with a trusted CA certificate for real user access.
- Keep direct service ports bound to `127.0.0.1`; expose through Nginx/HTTPS only.

## When Reprocessing Is Required

Reprocessing is not always required after code changes.

| Change type | Reprocess needed |
| --- | --- |
| Dashboard UI only | No |
| Dashboard API display/filter only | Usually no |
| Scheduler, Docker resources, batch size | No |
| Validation policy | Yes, affected records |
| Risk score formula/weights | Yes, affected records or full backfill |
| Adapter/normalization fields | Yes, affected source/schema |
| Classification policy/rules | Yes, affected records if warehouse values must change |

Do not delete the warehouse for ordinary fixes. Prefer targeted reprocess by date/source/schema unless a full policy reset is required.

