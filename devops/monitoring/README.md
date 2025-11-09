# 📊 Monitoring & Load Testing

Bu klasör monitoring (Prometheus, Grafana, AlertManager) yapılandırmaları ve load test script'lerini içerir.

## 📁 İçerik

```
monitoring/
├── prometheus/
│   ├── prometheus.yml      # Prometheus configuration
│   └── alerts.yml          # Alert rules
├── grafana/
│   ├── provisioning/       # Auto-provisioned datasources & dashboards
│   └── dashboards/         # Dashboard JSON files
├── alertmanager/
│   └── alertmanager.yml    # Alert routing configuration
├── load-test.sh            # Grafana metrics load test
└── README.md
```

## 🚀 Load Test Kullanımı

### Hızlı Başlangıç

```bash
# Varsayılan ayarlarla (10 iterasyon)
./load-test.sh

# Özel iterasyon sayısı
ITERATIONS=50 ./load-test.sh

# Farklı API URL
API_URL=http://production-api:8086 ITERATIONS=100 ./load-test.sh

# Hızlı test (bekleme süresi olmadan)
ITERATIONS=20 SLEEP_BETWEEN=0 ./load-test.sh
```

### Ne Yapar?

Load test script'i şu işlemleri yapar:

1. **Health Check** - `/api/v1/health` endpoint'ini kontrol eder
2. **Metrics Collection** - `/actuator/prometheus` metrics'lerini çeker
3. **PAdES Verification** - Test PDF dosyası doğrular (başarılı)
4. **XAdES Verification** - Test XML dosyası doğrular (başarılı)
5. **Timestamp Verification** - Test timestamp token doğrular (başarılı)
6. **Error Generation** - Invalid endpoint çağırarak 404 hatası generate eder

Bu çağrılar şu metrikleri üretir:
- **HTTP Request Rate** - İstek sayısı/saniye
- **Response Time Distribution** - p50, p95, p99 percentile'ları
- **Error Rate** - 4xx, 5xx hata oranları
- **Throughput** - Veri transfer hızı
- **JVM Metrics** - Memory, GC, threads

## 📈 Grafana Dashboard

### Dashboard Import

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

## 🔍 Prometheus Queries

### Request Metrics

```promql
# Request rate (requests/second)
rate(http_server_requests_seconds_count{job="verify-api"}[5m])

# Average response time
rate(http_server_requests_seconds_sum{job="verify-api"}[5m]) 
  / rate(http_server_requests_seconds_count{job="verify-api"}[5m])

# Error rate (percentage)
sum(rate(http_server_requests_seconds_count{job="verify-api",status=~"5.."}[5m])) 
  / sum(rate(http_server_requests_seconds_count{job="verify-api"}[5m])) * 100

# 95th percentile response time
histogram_quantile(0.95, 
  sum(rate(http_server_requests_seconds_bucket{job="verify-api"}[5m])) by (le))
```

### JVM Metrics

```promql
# Heap memory usage
jvm_memory_used_bytes{job="verify-api",area="heap"} 
  / jvm_memory_max_bytes{job="verify-api",area="heap"} * 100

# GC rate
rate(jvm_gc_pause_seconds_count{job="verify-api"}[5m])

# Thread count
jvm_threads_live_threads{job="verify-api"}
```

## 🎯 Test Senaryoları

### 1. Stress Test (Yüksek yük)

```bash
# 5 dakika boyunca sürekli istek
ITERATIONS=300 SLEEP_BETWEEN=1 ./load-test.sh
```

### 2. Spike Test (Ani yük artışı)

```bash
# Hızlı ardışık istekler
ITERATIONS=100 SLEEP_BETWEEN=0 ./load-test.sh
```

### 3. Endurance Test (Uzun süreli)

```bash
# 1 saat boyunca düzenli yük
ITERATIONS=3600 SLEEP_BETWEEN=1 ./load-test.sh
```

### 4. Concurrent Load (Paralel)

```bash
# 3 paralel test
./load-test.sh &
./load-test.sh &
./load-test.sh &
wait
```

## 📊 Metric Örnekleri

Load test çalıştırdıktan sonra Grafana'da göreceğin metrikler:

### Request Patterns
- **Normal Load**: ~6 req/sec (10 iterasyon, 1s bekleme)
- **High Load**: ~60 req/sec (100 iterasyon, 0s bekleme)
- **Peak Load**: Spike test'te anlık yükselme

### Response Times
- **Health Check**: ~5-10ms
- **PAdES Verification**: ~100-300ms (dosya boyutuna göre)
- **XAdES Verification**: ~50-200ms
- **Timestamp Verification**: ~50-150ms

### Error Distribution
- **2xx Success**: %80-90 (başarılı işlemler)
- **4xx Client Error**: %10-20 (invalid endpoint test'leri)
- **5xx Server Error**: %0 (idealde hiç olmamalı)

## 🚨 Alerts

Alertmanager'da tanımlı alert'ler:

1. **VerifyApiDown** - API 1 dakikadan uzun süredir çalışmıyor
2. **HighErrorRate** - %5'ten fazla hata oranı
3. **HighResponseTime** - 5 saniyeden uzun response time
4. **HighMemoryUsage** - %90'dan fazla memory kullanımı
5. **HighCPUUsage** - %85'ten fazla CPU kullanımı
6. **ThreadPoolExhaustion** - Thread pool %90'dan fazla dolu

Alert'leri test etmek için:

```bash
# Yüksek yük oluştur
ITERATIONS=1000 SLEEP_BETWEEN=0 ./load-test.sh
```

## 📚 İlgili Dökümanlar

- [Prometheus Configuration](prometheus/prometheus.yml)
- [Alert Rules](prometheus/alerts.yml)
- [Grafana Provisioning](grafana/provisioning/)
- [AlertManager Config](alertmanager/alertmanager.yml)

## 🔧 Troubleshooting

### Metrikler görünmüyor
```bash
# Prometheus target'larını kontrol et
curl http://localhost:9090/api/v1/targets

# API metrics endpoint'ini kontrol et
curl http://localhost:8086/actuator/prometheus
```

### Grafana dashboard boş
```bash
# Prometheus datasource'u kontrol et
# Grafana UI: Configuration → Data Sources → Prometheus
# Test datasource: http://prometheus:9090
```

### Load test hataları
```bash
# API'nin çalıştığını kontrol et
curl http://localhost:8086/api/v1/health

# Docker container'ları kontrol et
docker-compose -f ../../docker/docker-compose.yml ps
```

---

**💡 İpucu:** Load test'i çalıştırırken Grafana dashboard'unu aç ve real-time metrikleri izle!

