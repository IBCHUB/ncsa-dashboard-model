# TCTI Operations Runbook

Last updated: 2026-05-13

## Servers

```bash
# App server: AI service, dashboard, PostgreSQL, Nginx
ssh worlddev@192.168.100.44

# Elasticsearch server
ssh worlddev@192.168.100.43
```

On `.44`, runtime files are in:

```bash
/opt/tcti/app
/opt/tcti/src/ncsa-dashboard-model/ai-service
/opt/tcti/src/ncsa-dashboard-web
```

## Health Checks

```bash
ssh worlddev@192.168.100.44

curl -fsS http://127.0.0.1:9000/health
curl -fsS -H "X-API-Key: admin-key" http://127.0.0.1:9000/pipeline/status

sudo docker compose -f /opt/tcti/app/docker-compose.yml ps
sudo docker stats --no-stream --format "{{.Name}} cpu={{.CPUPerc}} mem={{.MemUsage}}" tcti-ai-service
free -h
```

Expected safe runtime guard:

```text
tcti-ai-service memory limit: 6GB
tcti-ai-service CPU limit: 4 CPU
pids_limit: 512
```

Check the active container limits:

```bash
sudo docker inspect tcti-ai-service \
  --format "Memory={{.HostConfig.Memory}} NanoCPUs={{.HostConfig.NanoCpus}} PidsLimit={{.HostConfig.PidsLimit}}"
```

## Manual Backfill

Manual backfill must run with scheduler off to avoid concurrent pipeline runs.

Current recommended batch:

```text
batch_limit=50000
sleep_seconds=10
timeout_seconds=1800
```

Monitor the latest backfill run:

```bash
sudo tail -f /opt/tcti/app/readiness/backfill-20260513-124857/summary.log
```

Stop the current backfill run:

```bash
sudo kill $(cat /opt/tcti/app/readiness/backfill-20260513-124857/pid)
```

Check if the worker is still alive:

```bash
RUN=/opt/tcti/app/readiness/backfill-20260513-124857
ps -p $(sudo cat "$RUN/pid") -o pid,etime,pcpu,pmem,args
```

## Scheduler

Keep scheduler disabled during manual backfill:

```bash
cd /opt/tcti/app
sudo sed -i 's/^PIPELINE_SCHEDULER_ENABLED=.*/PIPELINE_SCHEDULER_ENABLED=false/' .env
sudo docker compose up -d --force-recreate ai-service
```

After backfill and data validation, enable incremental processing:

```bash
cd /opt/tcti/app
sudo sed -i 's/^PIPELINE_SCHEDULER_ENABLED=.*/PIPELINE_SCHEDULER_ENABLED=true/' .env
sudo sed -i 's/^PIPELINE_SCHEDULER_INTERVAL_SECONDS=.*/PIPELINE_SCHEDULER_INTERVAL_SECONDS=3600/' .env
sudo sed -i 's/^PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS=.*/PIPELINE_SCHEDULER_INITIAL_DELAY_SECONDS=600/' .env
sudo sed -i 's/^PIPELINE_SCHEDULER_LIMIT=.*/PIPELINE_SCHEDULER_LIMIT=10000/' .env
sudo docker compose up -d --force-recreate ai-service
```

## Deploy AI Service

From local workspace root:

```bash
cd /Users/m/Desktop/ibusiness/cyber-workspace
APP_SUDO_PASSWORD='<sudo-password>' ./deploy/tcti-uat/scripts/deploy_ai_service_uat.sh
```

The script uploads local `ncsa-dashboard-model/ai-service`, builds the image on `.44`, updates `AI_IMAGE`, restarts `ai-service`, and checks health.

## Deploy Dashboard

From local workspace root:

```bash
cd /Users/m/Desktop/ibusiness/cyber-workspace
./deploy/tcti-uat/scripts/deploy_dashboard_uat.sh
```

If dependencies or `package-lock.json` changed:

```bash
./deploy/tcti-uat/scripts/deploy_dashboard_uat.sh --npm-ci
```

## Logs

```bash
ssh worlddev@192.168.100.44

cd /opt/tcti/app
sudo docker compose logs -f ai-service
sudo docker compose logs -f dashboard
sudo docker compose logs -f postgres
```

Recent AI logs:

```bash
sudo docker logs --tail 200 tcti-ai-service
```

## Guard Conditions

Stop the backfill immediately if any of these occur:

- `failed` is non-zero in the batch result.
- `curl http://127.0.0.1:9000/health` fails repeatedly.
- AI memory approaches the `6GB` container limit.
- Host memory pressure or swap starts increasing.
- Elasticsearch returns repeated `429`, `413`, or connection errors.

## Known Current Constraints

- `ctidashboard.worldinfinity.co.th` currently uses a self-signed certificate unless the customer replaces it with a trusted CA certificate.
- PostgreSQL dev access may be exposed on `5434` in some local templates; production should bind service ports to `127.0.0.1` and expose through Nginx only.
- Direct public access to `9000`/`9001` should not be treated as the production path.

