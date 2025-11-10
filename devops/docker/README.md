# 🐳 Docker Deployment

Verify API Docker yapılandırma dosyaları.

## 📁 İçerik

```
devops/docker/
├── Dockerfile              # Docker image definition
├── docker-compose.yml      # Monitoring stack
├── .dockerignore          # Build optimization
├── .env.example           # Environment template
├── unix/                  # Unix helper scripts
│   └── start.sh
├── windows/               # Windows helper scripts
│   └── start.ps1
└── README.md
```

## 🚀 Hızlı Başlangıç

### Basit Başlatma

```bash
# Bu dizine git
cd devops/docker

# Direkt başlat
docker-compose up -d
```

### Production için

```bash
# .env.example'dan kendi .env'ini oluştur
cp .env.example .env
nano .env

# Production ile başlat
docker-compose --env-file .env up -d
```

## 🌐 Endpoint'ler

- **Verify API:** http://localhost:8086
- **Health Check:** http://localhost:8086/actuator/health
- **API Docs:** http://localhost:8086/api-docs
- **Prometheus:** http://localhost:9090
- **Grafana:** http://localhost:3000 (admin/admin)

## 📊 Grafana Dashboard

**Dashboard ID: 11378** (Spring Boot 2.x)

Import adımları:
1. http://localhost:3000 → Login (admin/admin)
2. `+` → `Import` → `11378`
3. Prometheus data source seç → Import

## 🔧 Servisler

### Verify API

```bash
# Başlat
docker-compose up -d verify-api

# Log'ları izle
docker-compose logs -f verify-api

# Restart
docker-compose restart verify-api

# Durdur
docker-compose stop verify-api

# Sil
docker-compose down
```

### Monitoring Stack

```bash
# Prometheus + Grafana
docker-compose up -d

# AlertManager dahil
docker-compose --profile monitoring-full up -d

# Sadece Verify API (monitoring olmadan)
docker-compose up -d verify-api
```

## 🧪 Test

### Health Check

```bash
# Verify API
curl http://localhost:8086/actuator/health

# Prometheus
curl http://localhost:9090/-/healthy

# Grafana
curl http://localhost:3000/api/health
```

### Verification Test

```bash
# XAdES verification
curl -X POST http://localhost:8086/api/verify/xades \
  -H "Content-Type: application/json" \
  -d '{
    "signedDocument": "BASE64_ENCODED_SIGNED_DOCUMENT"
  }'

# PAdES verification
curl -X POST http://localhost:8086/api/verify/pades \
  -F "file=@signed-document.pdf"

# Timestamp verification
curl -X POST http://localhost:8086/api/verify/timestamp \
  -H "Content-Type: application/json" \
  -d '{
    "timestampToken": "BASE64_ENCODED_TOKEN"
  }'
```

## 🔍 Debugging

### Container'a Gir

```bash
# Shell açbastion
docker-compose exec verify-api sh

# Log dosyalarını kontrol et
docker-compose exec verify-api cat /app/logs/application.log
```

### Servis Durumu

```bash
# Tüm servislerin durumu
docker-compose ps

# Verify API logs
docker-compose logs verify-api

# Real-time logs
docker-compose logs -f --tail=100 verify-api
```

## 🔄 Güncelleme

### Image Güncelleme

```bash
# Yeni image'i build et
docker-compose build verify-api

# Restart et
docker-compose up -d verify-api

# Veya tek komutla
docker-compose up -d --build verify-api
```

### Volume Temizleme

```bash
# Tüm volume'leri sil
docker-compose down -v

# Sadece belirli volume'ü sil
docker volume rm docker_prometheus-data
```

## 📦 Production Deployment

### 1. Environment Hazırlığı

```bash
# .env dosyası oluştur
cat > .env << EOF
LOG_LEVEL=INFO
CORS_ALLOWED_ORIGINS=https://yourdomain.com
GRAFANA_PASSWORD=secure-password-here
EOF
```

### 2. SSL/TLS (Nginx)

```bash
# Nginx reverse proxy ekle
docker-compose --profile nginx up -d
```

### 3. Backup

```bash
# Prometheus data backup
docker run --rm -v docker_prometheus-data:/data -v $(pwd):/backup ubuntu tar czf /backup/prometheus-backup.tar.gz /data

# Grafana data backup
docker run --rm -v docker_grafana-data:/data -v $(pwd):/backup ubuntu tar czf /backup/grafana-backup.tar.gz /data
```

## 🛠️ Helper Scripts

### Unix/Linux/macOS

```bash
./unix/start.sh          # Start all services
```

### Windows (PowerShell)

```powershell
.\windows\start.ps1      # Start all services
```

## 📝 Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | 8086 | Verify API port |
| `LOG_LEVEL` | INFO | Logging level (DEBUG, INFO, WARN, ERROR) |
| `LOG_PATH` | /app/logs | Log directory |
| `JAVA_OPTS` | -Xmx1g -Xms512m | JVM options |
| `CORS_ALLOWED_ORIGINS` | * | CORS allowed origins |
| `TSL_REFRESH_CRON` | 0 0 2 * * ? | TSL refresh schedule |
| `GRAFANA_USER` | admin | Grafana username |
| `GRAFANA_PASSWORD` | admin | Grafana password |

## 🔐 Security

### Production Checklist

- [ ] `CORS_ALLOWED_ORIGINS` production domain'e set edildi
- [ ] `GRAFANA_PASSWORD` güçlü bir şifre ile değiştirildi
- [ ] Log dosyaları düzenli temizleniyor
- [ ] Volume backup stratejisi oluşturuldu
- [ ] SSL/TLS sertifikası eklendi
- [ ] Firewall kuralları yapılandırıldı (sadece gerekli portlar açık)

## 📚 Detaylı Döküman

Tüm detaylar için: [Verify API Documentation](../../../README.md)

---

**Kolay deployment için Docker!** 🐳

