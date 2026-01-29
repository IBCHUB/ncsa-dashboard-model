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

# Security
AI_SERVICE_API_KEY=your-secure-api-key-here
EOF
```

### 4. Production Docker Compose

```bash
# Use production compose file
docker-compose -f docker-compose.prod.yml up -d
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

## Docker Compose Production

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    container_name: tcti-elasticsearch
    restart: always
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    volumes:
      - es-data:/usr/share/elasticsearch/data
    networks:
      - tcti-network

  ai-service:
    build: ./ai-service
    container_name: tcti-ai-service
    restart: always
    environment:
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    depends_on:
      - elasticsearch
    networks:
      - tcti-network

  dashboard:
    build: ./dashboard
    container_name: tcti-dashboard
    restart: always
    environment:
      - AI_SERVICE_URL=http://ai-service:8000
    depends_on:
      - ai-service
    ports:
      - "3000:3000"
    networks:
      - tcti-network

volumes:
  es-data:

networks:
  tcti-network:
```

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
