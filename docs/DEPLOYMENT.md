# 🚀 Deployment Guide

Complete guide for deploying TCTI Platform to production.

---

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 16 GB | 32 GB |
| Storage | 100 GB SSD | 500 GB SSD |
| OS | Ubuntu 22.04 | Ubuntu 22.04 |

---

## Production Deployment

### 1. Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install docker-compose-plugin
```

### 2. Clone Repository

```bash
cd /opt
sudo git clone <repository-url> tcti
sudo chown -R $USER:$USER tcti
cd tcti
```

### 3. Configure Environment

```bash
# Create .env file
cat > .env << EOF
# OpenAI API Key for translation
OPENAI_API_KEY=sk-your-api-key-here

# Elasticsearch
ELASTICSEARCH_URL=http://elasticsearch:9200

# AI Service authentication (server accepts comma-separated keys; dashboard uses one)
AI_SERVICE_API_KEYS=your-secure-api-keys-here
AI_SERVICE_API_KEY=your-secure-api-key-here

# Dashboard internal access (set these for /login + session cookies)
DASHBOARD_SESSION_SECRET=change-me-long-random-secret
EOF
```

### 4. Production Docker Compose

```bash
# Build and start services
docker compose up -d --build
```

### 5. Nginx Reverse Proxy

```nginx
# /etc/nginx/sites-available/tcti
server {
    listen 80;
    server_name tcti.your-domain.com;

    # Dashboard
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # AI Service API
    location /api/ai/ {
        proxy_pass http://localhost:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Kibana (optional, restrict access)
    location /kibana/ {
        proxy_pass http://localhost:5601/;
        auth_basic "Kibana Access";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```

### 6. SSL Certificate

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d tcti.your-domain.com
```

---

## Remote Deployment (192.168.1.20)

### Access
- **Server:** `192.168.1.20`
- **User:** `ibiz-mint`
- **Code:** `~/cyber`

### Configuration
- **External ELK:** `https://pluto-elk.ibusiness.co.th`
- **Ports:**
  - Dashboard: `http://192.168.1.20:9001` (Mapped to 3000)
  - AI Service: `http://192.168.1.20:9000` (Mapped to 8000)

### Deployment Commands

```bash
# Connect
ssh ibiz-mint@192.168.1.20

# Deploy
cd cyber
git pull # If using git, otherwise scp
docker compose --env-file .env.remote -f docker-compose.remote.yml down
docker compose --env-file .env.remote -f docker-compose.remote.yml up -d --build
```

### default Login
- **URL:** [http://192.168.1.20:9001](http://192.168.1.20:9001)
- **Username:** `admin`
- **Password:** `TCTI_Admin_2026!`
- **2FA Secret:** `JBSWY3DPEHPK3PXP` (Currently Disabled)

#### 📝 วิธีใช้งาน 2FA (เมื่อเปิดใช้งาน)
*(ปัจจุบันปิดใช้งานชั่วคราวเพื่อให้ล็อกอินได้ทันที)*

> **Note:** `DASHBOARD_SESSION_SECRET` must be set for login to work.

1. **ดาวน์โหลดแอป:** ติดตั้ง **Google Authenticator** หรือ **Microsoft Authenticator** บนมือถือ
2. **เพิ่มบัญชี:** เปิดแอป กดปุ่ม `+` แล้วเลือก **"Enter setup key" (ป้อนคีย์ตั้งค่า)**
3. **กรอกข้อมูล:**
   - **Account:** ตั้งชื่อว่า `TCTI Dashboard`
   - **Key:** กรอก `JBSWY3DPEHPK3PXP`
   - **Type:** เลือก `Time-based` (ถ้ามีให้เลือก)
4. **ใช้งาน:** แอปจะแสดงเลข 6 หลัก (เปลี่ยนทุก 30 วิ) นำเลขนั้นมากรอกช่อง OTP ตอนล็อกอิน

---

## Compose Files

- `docker-compose.yml`: local all-in-one (Elasticsearch + Kibana + AI Service + Dashboard)
- `docker-compose.remote.yml`: remote deployment using external ELK (use `--env-file .env.remote`)

---

## Monitoring

### Health Checks

```bash
# Dashboard
curl -I http://localhost:3000

# AI Service
curl http://localhost:8000/health

# Elasticsearch
curl http://localhost:9200/_cluster/health
```

### Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f ai-service
```

---

## Backup

### Elasticsearch Data

```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/backup" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backup"
  }
}'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/backup/snapshot_1?wait_for_completion=true"
```

### Full Backup Script

```bash
#!/bin/bash
BACKUP_DIR=/backup/tcti/$(date +%Y%m%d)
mkdir -p $BACKUP_DIR

# Elasticsearch
docker exec tcti-elasticsearch elasticsearch-backup $BACKUP_DIR/es

# Config files
cp /opt/tcti/.env $BACKUP_DIR/
cp /opt/tcti/docker-compose.yml $BACKUP_DIR/

echo "Backup completed: $BACKUP_DIR"
```

---

## Troubleshooting

### Elasticsearch Out of Memory

```bash
# Increase heap size in docker-compose
ES_JAVA_OPTS=-Xms8g -Xmx8g
```

### Dashboard Not Loading

```bash
# Check container status
docker ps -a

# Restart dashboard
docker-compose restart dashboard
```

### AI Service Slow

```bash
# Check GPU availability
nvidia-smi

# Switch to CPU mode
DEVICE=cpu docker-compose up -d ai-service
```
