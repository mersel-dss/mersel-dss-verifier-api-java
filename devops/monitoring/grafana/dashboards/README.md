# Grafana Dashboards

Bu klasör Grafana dashboard JSON dosyalarını içerir. Docker Compose
çalıştığında bu klasör `/var/lib/grafana/dashboards`'a mount edilir ve
`provisioning/dashboards/dashboard.yml` ile **otomatik** yüklenir —
elle import gerekmez.

## Provisioned (otomatik) dashboard

### `mersel-dss-verify-api.json` — Mersel DSS Verify API — Genel Bakış & Teşhis

Bu projeye özel, domain metrikleriyle (VerificationMetrics) beslenen
kapsamlı dashboard. Grafana açıldığında **`Verify API`** klasörü altında
hazır gelir. Bölümler:

- **SLO / Özet** — istek hızı, VALID/INVALID oranı, exception hızı, p95/p99.
- **İstek Hacmi & Sonuç Dağılımı** — sonuca ve imza tipine göre kırılım.
- **İstek Sonuçlanma Süreleri** — uçtan uca p50/p95/p99, latency heatmap ve
  **aşama bazlı kırılım** (`read_input → build_validator → dss_validate →
  parse_result`). "Doğrulama neden yavaş?" sorusunun cevabı burada;
  genellikle `dss_validate` (OCSP/CRL/AIA fetch) baskındır.
- **Kök Neden** — imza başına `sub_indication`/`indication` dağılımı, en sık
  başarısızlık nedenleri tablosu ve MDSS Tolerance Gate paneli.
- **Bağımlılıklar (KamuSM)** — OCSP/CRL/AIA fetch hız+latency, retry
  (retried/recovered/exhausted), cache hit-rate, güven deposu sertifika
  sayısı ve son refresh yaşı.
- **HTTP Katmanı** — endpoint bazlı hız, p95, 5xx, bildirim kanalları.
- **JVM / Runtime** — heap, GC, CPU, thread (collapsed).

Dashboard üstündeki **Data source** ve **Application** değişkenleriyle
(çoklu deployment varsa) filtrelenebilir.

## Dashboard Import (opsiyonel — genel Spring Boot dashboard'u)

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

