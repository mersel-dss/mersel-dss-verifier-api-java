# Grafana Dashboards

Bu klasör Grafana dashboard JSON dosyalarını içerir.

## Dashboard Import

### Spring Boot 2.x Dashboard

1. Grafana'ya giriş yap: http://localhost:3000
   - Kullanıcı: `admin`
   - Parola: `admin`

2. Dashboard ID: **11378** (Spring Boot 2.x)
   - Sol menüden `Dashboards` → `Import`
   - Dashboard ID gir: `11378`
   - Prometheus datasource seç
   - `Import` butonuna tıkla

### Önemli Paneller

**Application Metrics:**
- Request Rate
- Error Rate
- Response Time (avg, p95, p99)
- Active Requests
- Throughput

**JVM Metrics:**
- Heap Memory Usage
- Non-Heap Memory Usage
- GC Count & Duration
- Thread Count
- Class Loading

**System Metrics:**
- CPU Usage
- System Load Average
- Uptime

## Custom Dashboards

Özel dashboard'lar eklemek için JSON dosyalarını bu klasöre ekleyin.
Docker Compose ile otomatik olarak yüklenecektir.

