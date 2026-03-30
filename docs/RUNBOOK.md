# คัมภีร์หน้างาน (Operations Runbook)

> อัปเดตล่าสุด: 2026-03-30 (อิงตาม Source of Truth ล่าสุด)

## การติดตั้งและเดินเครื่อง (Deployment)

### รันบนเครื่องนักพัฒนา (Local Development)

```bash
docker-compose up -d
# Elasticsearch: http://localhost:9200
# AI Service:    http://localhost:8000
# API Docs:      http://localhost:8000/docs
```

### รันบน Production Server (Remote ELK)

```bash
# กำหนด Environment Variables ที่จำเป็น
export ELASTICSEARCH_URL=https://your-elk.example.com
export DATALAKE_INDEX=tcti-datalake
export WAREHOUSE_INDEX=tcti-warehouse
export DATALAKE_API_KEY=your-key
export WAREHOUSE_API_KEY=your-key
export AI_SERVICE_API_KEYS=your-secure-key

docker-compose -f docker-compose.remote.yml up -d
# AI Service จะรันที่: http://localhost:9000
```

### Build Image และ Restart (Docker Build & Deploy)

```bash
# Build Image ใหม่
docker-compose build ai-service

# Deploy พร้อม Build
docker-compose up -d --build ai-service

# ดู Log แบบ Real-time
docker-compose logs -f ai-service
```

## การตรวจสอบสุขภาพระบบ (Health Checks)

### ตรวจสอบสถานะ Service

```bash
curl http://localhost:8000/health
# ผลลัพธ์ที่ถูกต้อง: {"status": "healthy", "version": "1.0.0", "classifier_loaded": true}
```

### ตรวจสอบการเชื่อมต่อ Elasticsearch

```bash
curl -H "X-API-Key: <your-api-key>" http://localhost:8000/pipeline/status
# ผลลัพธ์ที่ถูกต้อง: รายงานยอด Document Count และสถานะการเชื่อมต่อ
```

### ตรวจสอบ Dashboard Endpoints

```bash
# Executive Dashboard
curl -H "Authorization: Bearer <JWT_TOKEN>" http://localhost:8000/api/v1/executive/dashboard

# Operations Dashboard
curl -H "Authorization: Bearer <JWT_TOKEN>" http://localhost:8000/api/v1/operations/dashboard
```

### ตรวจสอบสถานะการโหลดโมเดล (Model Loading)

การบูตระบบครั้งแรกจะใช้เวลา 30-120 วินาทีสำหรับการโหลดโมเดล AI หลังจากนั้น Request จะประมวลผลได้ทันที

```bash
# ตรวจสอบว่าโมเดลโหลดสำเร็จหรือไม่
curl http://localhost:8000/health | python3 -c "import sys,json; print(json.load(sys.stdin)['classifier_loaded'])"
```

## การเฝ้าระวังระบบ (Monitoring)

### Key Metrics

| Metric | จุดตรวจสอบ | เงื่อนไข Alert |
|--------|-------|-----------------| 
| Service Health | `GET /health` → `status: healthy` | HTTP Status ไม่ใช่ 200 |
| Model Status | `GET /health` → `classifier_loaded` | ค่าเป็น `false` นานเกิน 5 นาที |
| Pipeline Processing Time | `POST /pipeline/run` | ใช้เวลาเกิน 30 วินาทีต่อ 1 รายการ |
| Elasticsearch Connectivity | `GET /pipeline/status` | สถานะเป็น `unavailable` |
| HuggingFace Cache Disk | `/root/.cache/huggingface` | ใช้พื้นที่เกิน 10 GB |
| Dashboard Response Time | `GET /api/v1/executive/dashboard` | ใช้เวลาตอบสนองเกิน 5 วินาที |

### Log Locations

| Component | วิธีเข้าถึง |
|-----------|----------| 
| AI Service | `docker-compose logs ai-service` |
| Elasticsearch | `docker-compose logs elasticsearch` |

## งานประจำ (Common Operations)

### รัน AI Pipeline

```bash
# ประมวลผล 100 เอกสารจาก Data Lake
curl -X POST http://localhost:8000/pipeline/run \
  -H "X-API-Key: <your-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"limit": 100}'
```

### นำเข้าข้อมูลลง Data Lake

```bash
# วางไฟล์ JSON ไว้ในโฟลเดอร์ data_lake/ แล้วรัน
cd ai-service
python scripts/ops/import_to_datalake.py
```

### Rebuild Data Warehouse

ดึงข้อมูลจาก Data Lake กลับมาประมวลผลใหม่ทั้งหมด เพื่ออัปเดตผล AI Scoring, HDBSCAN Campaign Clustering และ Relationship Graph

```bash
cd ai-service

# Dry run — ตรวจสอบจำนวนรายการก่อนเขียนจริง
python scripts/ops/rebuild_warehouse.py \
  --date-from 2026-03-01T00:00:00+07:00 \
  --date-to 2026-03-27T23:59:59+07:00 \
  --limit 500

# Write mode — เขียนลงฐานข้อมูลจริง
python scripts/ops/rebuild_warehouse.py \
  --write \
  --date-from 2026-03-01T00:00:00+07:00 \
  --date-to 2026-03-27T23:59:59+07:00
```

### นำเข้า Mock Data สำหรับ UAT

```bash
cd ai-service
python scripts/dev/seed_dashboard_fixture.py
# สร้างข้อมูลจำลองลง Datalake + Warehouse พร้อมกระจาย Timestamp สำหรับแสดงกราฟ
```

### เข้าสู่ระบบ Dashboard

```bash
# ขอ JWT Token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'

# ใช้ Token เรียก Protected Endpoint
curl -H "Authorization: Bearer <JWT_TOKEN>" \
  http://localhost:8000/api/v1/iocs?page=1&page_size=20
```

## การแก้ไขปัญหาที่พบบ่อย (Common Issues & Fixes)

### 1. โหลดโมเดล AI ไม่สำเร็จ (Model Download Fails)

**อาการ:** `/health` ส่งคืน `classifier_loaded: false`

**วิธีแก้ไข:**
```bash
# ตรวจสอบพื้นที่ Disk บน HuggingFace Cache
df -h /root/.cache/huggingface

# ล้าง Cache และ Restart
docker exec tcti-ai-service rm -rf /root/.cache/huggingface/*
docker-compose restart ai-service

# หรือข้ามการ Preload ตอน Startup และให้โหลดเมื่อมี Request แรก
AI_SERVICE_SKIP_STARTUP_PRELOAD=true docker-compose up -d ai-service
```

### 2. ไม่สามารถเชื่อมต่อ Elasticsearch (Elasticsearch Connection Failed)

**อาการ:** `/pipeline/status` ส่งคืนสถานะ `unavailable`

**วิธีแก้ไข:**
```bash
# ตรวจสอบ Cluster Health โดยตรง
curl http://localhost:9200/_cluster/health

# ตรวจสอบสถานะ Container
docker-compose ps elasticsearch
docker-compose logs elasticsearch | tail -20

# Restart Container
docker-compose restart elasticsearch
```

### 3. Container ใช้ Memory เกินกำหนด (Out of Memory)

**อาการ:** Container ถูกหยุดและ Restart วนซ้ำ

**วิธีแก้ไข:**
```bash
# เพิ่ม Heap Memory สำหรับ Elasticsearch
# แก้ไขใน docker-compose.yml: ES_JAVA_OPTS=-Xms1g -Xmx1g ให้สูงขึ้น

# บังคับใช้ CPU (ใช้ RAM น้อยกว่า CUDA)
# ตั้งค่า DEVICE=cpu

# ลด Batch Size ต่อรอบ
curl -X POST .../pipeline/run -d '{"limit": 10}'
```

### 4. CORS Error จาก Dashboard Frontend

**อาการ:** Browser Console แสดง CORS Error

**วิธีแก้ไข:**
```bash
# อนุญาต Domain ที่ต้องการ (คั่นด้วย comma)
AI_SERVICE_CORS_ORIGINS=http://localhost:3000,http://localhost:5173

# หรือเปิด Wildcard (สำหรับ Development เท่านั้น ห้ามใช้บน Production)
AI_SERVICE_CORS_ORIGINS=*
```

## ขั้นตอน Rollback

### Rollback AI Service

```bash
# Tag Image ปัจจุบันก่อน Deploy
docker tag tcti-ai-service:latest tcti-ai-service:backup-$(date +%Y%m%d)

# หาก Deployment ใหม่มีปัญหา — คืน Image เดิม
docker-compose down ai-service
docker tag tcti-ai-service:backup-YYYYMMDD tcti-ai-service:latest
docker-compose up -d ai-service
```

### Rollback Data Warehouse

```bash
# Data Warehouse เป็น Append-only
# หากต้องการยกเลิกข้อมูลที่ผิดพลาด ให้ Mark เป็น rejected ผ่าน Elasticsearch โดยตรง
# หรือ Rebuild Warehouse ด้วยช่วงเวลาที่ต้องการ

python scripts/ops/rebuild_warehouse.py \
  --write \
  --date-from START \
  --date-to END
```

### Rollback Source Code (Git)

```bash
# ดู Commit History 10 รายการล่าสุด
git log --oneline -10

# Revert Commit ที่มีปัญหา
git revert <commit-hash>
```

## Port Reference

| Service | Local Port | Remote Port | คำอธิบาย |
|---------|-------|--------|---------| 
| AI Service | 8000 | 9000 | FastAPI Application |
| Elasticsearch | 9200 | - | REST API |
| Elasticsearch | 9300 | - | Inter-node Transport (Cluster Communication) |
