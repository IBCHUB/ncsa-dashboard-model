# เช็คลิสต์ก่อนขึ้นระบบจริง (Production Readiness Checklist)

> สร้าง: 2026-03-27
> อัปเดตล่าสุด: 2026-03-30
> สถานะ: เตรียมพร้อมสำหรับ Production — ยังไม่ได้ Deploy จริง
> สภาพปัจจุบัน: ทดสอบบนเครื่อง Dev ผ่าน, เชื่อมต่อ Remote ELK ได้สำเร็จ

เอกสารฉบับนี้รวบรวมข้อกำหนดและขั้นตอนทั้งหมดที่ต้องดำเนินการก่อน Deploy ระบบสู่ Production Environment

---

## 1. Infrastructure Requirements

| รายการ | สภาพแวดล้อม Dev | ข้อกำหนดสำหรับ Production |
|--------|-----------|------------------------| 
| Elasticsearch Cluster | Local single-node | Production Cluster หรือ Cloud Managed ELK |
| AI Service Host | Docker (Local) | VM หรือ Container Instance สำหรับรัน `docker-compose.remote.yml` |
| HuggingFace Model Cache | ดาวน์โหลดใหม่ทุกครั้ง | Persistent Volume สำหรับ Cache หรือ Build โมเดลเข้า Docker Image |
| Dashboard Frontend | แยก Project — ชี้ API มาที่ Repo นี้ | ตั้งค่า Deploy และกำหนด API Endpoint ให้ถูกต้อง |

## 2. Environment Variables

```bash
# === Required (ต้องตั้งค่าทุกตัว) ===

# API Key สำหรับ AI Service — ต้องเป็นค่าสุ่มที่ซับซ้อน ไม่ควรตั้งค่าง่าย
AI_SERVICE_API_KEYS=<production-key-1>,<production-key-2>
AI_SERVICE_REQUIRE_AUTH=true

# Elasticsearch — ขอรายละเอียดจากทีม Infra
ELASTICSEARCH_URL=https://<production-elk-server>:9200
DATALAKE_INDEX=tcti-datalake
WAREHOUSE_INDEX=tcti-warehouse
DATALAKE_API_KEY=<ขอจากทีม ELK Admin>
WAREHOUSE_API_KEY=<ขอจากทีม ELK Admin>

# === Recommended ===

# CORS — อนุญาตเฉพาะ Domain ของ Dashboard จริงเท่านั้น
AI_SERVICE_CORS_ORIGINS=https://dashboard.example.go.th

# === Optional (ใช้ค่า Default ได้) ===
AI_SERVICE_HOST=0.0.0.0
AI_SERVICE_PORT=8000
DEVICE=cpu
```

## 3. ขั้นตอนการ Deploy

```bash
# 1. Clone Repository ลงเครื่อง Production
git clone <repo-url> && cd Cyber

# 2. สร้างไฟล์ .env ตามรายการตัวแปรด้านบน
cat > .env << 'EOF'
AI_SERVICE_API_KEYS=...
ELASTICSEARCH_URL=...
DATALAKE_API_KEY=...
WAREHOUSE_API_KEY=...
EOF

# 3. Build และ Start Container (ใช้ Remote Compose — ไม่รัน Elasticsearch ในเครื่องนี้)
docker-compose -f docker-compose.remote.yml up -d --build

# 4. ตรวจสอบสถานะระบบ
curl http://localhost:9000/health
# ผลลัพธ์ที่ถูกต้อง: {"status": "healthy", "classifier_loaded": true}

# 5. ตรวจสอบการเชื่อมต่อฐานข้อมูล
curl -H "X-API-Key: <key>" http://localhost:9000/pipeline/status
# ผลลัพธ์ที่ถูกต้อง: รายงานยอด datalake_count และ warehouse_count

# 6. สร้าง Elasticsearch Index หากยังไม่มี
curl -X POST -H "X-API-Key: <key>" http://localhost:9000/elasticsearch/setup
```

## 4. การตั้งค่า Automation (Pipeline Scheduling)

ปัจจุบัน Pipeline ต้องเรียกใช้งานด้วยตนเอง จึงต้องตั้งค่า Scheduled Job เพื่อให้ทำงานอัตโนมัติ

### ตัวเลือกที่ 1: Cron Job บน Host Machine

```bash
# เพิ่มใน crontab -e บนเครื่อง Server
# รันทุก 5 นาทีเพื่อประมวลผล IOC ใหม่
*/5 * * * * curl -s -X POST http://localhost:9000/pipeline/run \
  -H "X-API-Key: <production-key>" \
  -H "Content-Type: application/json" \
  -d '{"limit": 200}' >> /var/log/tcti-pipeline.log 2>&1
```

### ตัวเลือกที่ 2: Docker Service (เพิ่มใน Compose)

```yaml
# เพิ่ม Service นี้ใน docker-compose.remote.yml
  pipeline-scheduler:
    image: curlimages/curl:latest
    container_name: tcti-pipeline-scheduler
    restart: unless-stopped
    entrypoint: /bin/sh
    command: >
      -c "while true; do
        curl -s -X POST http://ai-service:8000/pipeline/run
          -H 'X-API-Key: $${AI_SERVICE_API_KEYS}'
          -H 'Content-Type: application/json'
          -d '{\"limit\": 200}';
        sleep 300;
      done"
    environment:
      - AI_SERVICE_API_KEYS=${AI_SERVICE_API_KEYS}
    depends_on:
      - ai-service
    networks:
      - tcti-network
```

### ตัวเลือกที่ 3: Systemd Timer (สำหรับ Bare-metal Server)

```ini
# สร้างไฟล์ /etc/systemd/system/tcti-pipeline.service
[Unit]
Description=TCTI Pipeline Run

[Service]
Type=oneshot
ExecStart=/usr/bin/curl -s -X POST http://localhost:9000/pipeline/run \
  -H "X-API-Key: <key>" -H "Content-Type: application/json" -d '{"limit": 200}'

# สร้างไฟล์ /etc/systemd/system/tcti-pipeline.timer
[Unit]
Description=Run TCTI Pipeline every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

### แนวทางการกำหนดความถี่การรัน

| ปริมาณ IOC ต่อวัน | ความถี่ที่แนะนำ | Limit ต่อรอบ |
|---------------------|----------------|-------------| 
| น้อยกว่า 500 รายการ | ทุก 15 นาที | 100 รายการ |
| 500 - 5,000 รายการ | ทุก 5 นาที | 200 รายการ |
| มากกว่า 5,000 รายการ | ทุก 1 นาที | 500 รายการ |

## 5. Monitoring

| จุดตรวจสอบ | Endpoint | เงื่อนไข Alert |
|----------------|---------|---------------| 
| Service Health | `GET /health` | HTTP Status ไม่ใช่ 200 นานเกิน 5 นาที |
| Model Status | ฟิลด์ `classifier_loaded` | ค่าเป็น `false` นานเกิน 5 นาที |
| Elasticsearch | `GET /pipeline/status` | สถานะเป็น error หรือ unavailable |
| Pipeline Throughput | เปรียบ `datalake_count` กับ `warehouse_count` | Data Lake เพิ่มขึ้นแต่ Warehouse ไม่มีข้อมูลใหม่เกิน 30 นาที |
| Disk Usage | `df -h` บน HuggingFace Cache Directory | ใช้พื้นที่เกิน 80% |

*(หมายเหตุ: การตรวจสอบ Manual Review Queue ถูกถอดออกแล้ว ระบบทำงานแบบ Fully Automated)*

## 6. Backup & Recovery

```bash
# สร้าง Elasticsearch Snapshot Repository
curl -X PUT "http://<elk>:9200/_snapshot/tcti_backup" \
  -H "Content-Type: application/json" \
  -d '{"type": "fs", "settings": {"location": "/backup/es"}}'

# สร้าง Snapshot
curl -X PUT "http://<elk>:9200/_snapshot/tcti_backup/snapshot_$(date +%Y%m%d)" \
  -H "Content-Type: application/json" \
  -d '{"indices": "tcti-datalake,tcti-warehouse"}'

# กรณี Dashboard แสดงผลผิดพลาด — Rebuild Data Warehouse จาก Data Lake
cd ai-service
python scripts/ops/rebuild_warehouse.py --write --limit 10000
```

## 7. Security Checklist

- [ ] ตั้ง `AI_SERVICE_API_KEYS` เป็นค่าสุ่มที่ซับซ้อน (อย่างน้อย 32 ตัวอักษร)
- [ ] ตั้ง `AI_SERVICE_DEBUG=false`
- [ ] จำกัด `AI_SERVICE_CORS_ORIGINS` ให้รับเฉพาะ Domain จริงของ Dashboard (ห้ามใช้ `*`)
- [ ] บังคับใช้ `AI_SERVICE_REQUIRE_AUTH=true`
- [ ] บังคับใช้ HTTPS ผ่าน Reverse Proxy ด้านหน้า Application
- [ ] ไม่เปิด Port ของ AI Service สู่ Public Internet โดยตรง
- [ ] แยก ES API Key ระหว่าง Data Lake และ Data Warehouse (Least Privilege)
- [ ] ยกเว้นไฟล์ `.env` ออกจาก Git Repository
- [ ] กำหนด Log Rotation Policy สำหรับ Docker Logs

## 8. Pending Items (รายการที่รอดำเนินการ)

| รายการ | รอการอนุมัติจาก | เหตุผลที่ติดขัด |
|--------|---------|----------| 
| Production ELK Cluster + API Key | ทีม Infra / ELK Admin | Server ยังไม่ได้รับการจัดสรร |
| Dashboard Domain Name | ทีม Frontend | ยังไม่ได้กำหนด Domain สำหรับตั้งค่า CORS |
| HTTPS / TLS Certificate | ทีม Infra | ต้องมี HTTPS ก่อน Deploy จริง |
| Pipeline SLA | ทีม Development + ผู้บริหาร | ยังไม่ได้กำหนด Acceptable Latency |
