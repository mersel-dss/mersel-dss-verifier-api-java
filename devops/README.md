# DevOps

Verify API için DevOps yapılandırma dosyaları ve deployment araçları.

## 📁 Dizin Yapısı

```
devops/
├── docker/              # Docker deployment
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── README.md
│   ├── unix/           # Unix helper scripts
│   └── windows/        # Windows helper scripts
├── monitoring/         # Monitoring stack
│   ├── prometheus/
│   ├── grafana/
│   └── alertmanager/
└── README.md
```

## 🐳 Docker Deployment

En hızlı ve kolay deployment yöntemi.

### Hızlı Başlangıç

```bash
cd devops/docker
docker-compose up -d
```

Detaylı bilgi: [docker/README.md](docker/README.md)

## 📊 Monitoring

Prometheus + Grafana ile monitoring ve alerting.

### Monitoring Stack

```bash
cd devops/docker
docker-compose up -d
```

**Endpoint'ler:**
- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)
- AlertManager: http://localhost:9093

Detaylı bilgi: [monitoring/README.md](monitoring/README.md)

## 🚀 Deployment Seçenekleri

### 1. Docker Compose (Önerilen)

**Kullanım Durumu:** Development, test, küçük production

```bash
cd devops/docker
docker-compose up -d
```

**Avantajları:**
- ✅ En hızlı setup
- ✅ Monitoring dahil
- ✅ Kolay yönetim

### 2. Docker (Standalone)

**Kullanım Durumu:** Minimal deployment

```bash
docker build -t verify-api -f devops/docker/Dockerfile .
docker run -d -p 8086:8086 verify-api
```

**Avantajları:**
- ✅ Minimal resource
- ✅ Basit

### 3. Kubernetes (Gelecek)

**Kullanım Durumu:** Large-scale production

```bash
cd devops/kubernetes
kubectl apply -f .
```

**Avantajları:**
- ✅ Auto-scaling
- ✅ High availability
- ✅ Rolling updates

## 🛠️ Helper Scripts

### Unix/Linux/macOS

```bash
# Docker Compose ile başlat
./devops/docker/unix/start.sh
```

### Windows (PowerShell)

```powershell
# Docker Compose ile başlat
.\devops\docker\windows\start.ps1
```

## 📦 Environment Variables

Ana environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | 8086 | Verify API port |
| `LOG_LEVEL` | INFO | Logging level |
| `JAVA_OPTS` | -Xmx1g | JVM options |
| `CORS_ALLOWED_ORIGINS` | * | CORS config |

Tüm environment variables için: [docker/env.example](docker/env.example)

## 🔐 Production Best Practices

### 1. Security

```bash
# Strong passwords
GRAFANA_PASSWORD=very-secure-password

# Restricted CORS
CORS_ALLOWED_ORIGINS=https://yourdomain.com

# Non-root user (already configured in Dockerfile)
```

### 2. Resource Management

```bash
# JVM tuning
JAVA_OPTS=-Xmx2g -Xms1g -XX:+UseG1GC

# Container limits (docker-compose.yml)
deploy:
  resources:
    limits:
      memory: 2g
      cpus: '2'
```

### 3. Monitoring

```bash
# Enable all monitoring
docker-compose --profile monitoring-full up -d

# Set alerts
# Configure: monitoring/alertmanager/alertmanager.yml
```

### 4. Backup

```bash
# Backup script
./devops/scripts/backup.sh

# Automated backups
crontab -e
0 2 * * * /opt/verify-api/devops/scripts/backup.sh
```

## 🔄 CI/CD

GitHub Actions workflow otomatik olarak:
1. ✅ Maven ile build
2. ✅ Test çalıştırma
3. ✅ Docker image build
4. ✅ Docker Hub'a push

Workflow: [../.github/workflows/docker-publish.yml](../.github/workflows/docker-publish.yml)

## 📚 Kaynaklar

- [Docker Deployment Guide](docker/README.md)
- [Monitoring Setup](monitoring/README.md)
- [Main README](../README.md)
- [API Guide](../API_GUIDE.md)

## 💡 Sorun Giderme

### Docker Build Hatası

```bash
# Cache'i temizle
docker system prune -a

# Tekrar build et
docker-compose build --no-cache
```

### Port Çakışması

```bash
# Port değiştir (.env)
SERVER_PORT=8087

# Veya docker-compose.yml'de
ports:
  - "8087:8086"
```

### Memory Problemi

```bash
# JVM heap boyutunu artır
JAVA_OPTS=-Xmx2g -Xms1g
```

## 🆘 Yardım

Sorun mu yaşıyorsunuz?
1. [Troubleshooting Guide](../TROUBLESHOOTING.md)
2. [GitHub Issues](https://github.com/yourusername/verify-api/issues)
3. [Main Documentation](../README.md)

---

**Happy Deploying!** 🚀

