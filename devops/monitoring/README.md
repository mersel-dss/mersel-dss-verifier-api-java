# 📊 Monitoring

Verify API için Prometheus + Grafana monitoring stack.

## 🚀 Hızlı Başlangıç

```bash
cd devops/docker
docker-compose up -d
```

## 🌐 Access Points

- **Prometheus:** http://localhost:9090
- **Grafana:** http://localhost:3000 (admin/admin)
- **AlertManager:** http://localhost:9093

## 📁 Yapı

```
monitoring/
├── prometheus/
│   ├── prometheus.yml    # Prometheus config
│   └── alerts.yml        # Alert rules
├── grafana/
│   └── provisioning/
│       ├── datasources/  # Auto datasource config
│       └── dashboards/   # Auto dashboard config
├── alertmanager/
│   └── alertmanager.yml  # Alert routing
└── README.md
```

## 📊 Grafana Dashboard

### Import Dashboard

1. Grafana'ya girin: http://localhost:3000 (admin/admin)
2. `+` → `Import`
3. Dashboard ID girin: **11378** (Spring Boot 2.x)
4. Prometheus datasource seç
5. Import

### Önemli Metrikler

#### Request Metrics
```promql
# Request rate
rate(http_server_requests_seconds_count{application="mersel-dss-verify-api"}[5m])

# 95th percentile response time
histogram_quantile(0.95, rate(http_server_requests_seconds_bucket{application="mersel-dss-verify-api"}[5m]))

# Error rate
rate(http_server_requests_seconds_count{application="mersel-dss-verify-api",status=~"5.."}[5m])
```

#### JVM Metrics
```promql
# Heap memory usage
jvm_memory_used_bytes{application="mersel-dss-verify-api",area="heap"} / jvm_memory_max_bytes{application="mersel-dss-verify-api",area="heap"}

# GC time
rate(jvm_gc_pause_seconds_sum{application="mersel-dss-verify-api"}[5m])

# Thread count
jvm_threads_live{application="mersel-dss-verify-api"}
```

#### Verification Metrics (VerificationMetrics — domain iş metrikleri)
> NOT: Eski `verification_operations_total` / `verification_success_total` /
> `verification_failures_total` isimleri hiç implement edilmemişti. Gerçek
> metrikler Micrometer Timer'ları olduğu için `_count` / `_sum` / `_bucket`
> serileriyle gelir.

```promql
# Doğrulama hızı (uçtan uca Timer count)
sum(rate(mdss_verification_duration_seconds_count{application="mersel-dss-verify-api"}[5m]))

# VALID başarı oranı
sum(rate(mdss_verification_duration_seconds_count{application="mersel-dss-verify-api",result="valid"}[5m]))
  / clamp_min(sum(rate(mdss_verification_duration_seconds_count{application="mersel-dss-verify-api"}[5m])), 0.001)

# INVALID oranı
sum(rate(mdss_verification_duration_seconds_count{application="mersel-dss-verify-api",result="invalid"}[5m]))
  / clamp_min(sum(rate(mdss_verification_duration_seconds_count{application="mersel-dss-verify-api"}[5m])), 0.001)

# Hata (exception) hızı — parse/IO/altyapı
sum(rate(mdss_verification_errors_total{application="mersel-dss-verify-api"}[5m]))

# Uçtan uca latency p95
histogram_quantile(0.95, sum(rate(mdss_verification_duration_seconds_bucket{application="mersel-dss-verify-api"}[5m])) by (le))

# Aşama bazlı latency p95 — "zaman nerede harcandı?" (read_input/build_validator/dss_validate/parse_result)
histogram_quantile(0.95, sum by (le, stage) (rate(mdss_verification_stage_duration_seconds_bucket{application="mersel-dss-verify-api"}[5m])))

# Kök neden dağılımı — imza başına sub_indication
sum by (sub_indication) (rate(mdss_signature_results_total{application="mersel-dss-verify-api", indication!="TOTAL_PASSED"}[10m]))
```

#### Dependency Metrics (KamuSM: OCSP / CRL / AIA / Trust Store)
```promql
# Revocation fetch latency p95 (tip bazlı)
histogram_quantile(0.95, sum by (le, type) (rate(mdss_revocation_fetch_duration_seconds_bucket{application="mersel-dss-verify-api"}[5m])))

# Revocation fetch hata oranı
sum by (type) (rate(mdss_revocation_fetch_duration_seconds_count{application="mersel-dss-verify-api",outcome="error"}[5m]))

# Retry tükenmesi (KamuSM flaky/down sinyali)
sum by (type) (rate(mdss_revocation_retry_total{application="mersel-dss-verify-api",event="exhausted"}[5m]))

# AIA (ara CA) fetch latency p95
histogram_quantile(0.95, sum by (le) (rate(mdss_aia_fetch_duration_seconds_bucket{application="mersel-dss-verify-api"}[5m])))

# Cache hit-rate (ocsp/crl/aia)
sum by (cache) (rate(cache_gets_total{application="mersel-dss-verify-api",result="hit"}[5m]))
  / clamp_min(sum by (cache) (rate(cache_gets_total{application="mersel-dss-verify-api"}[5m])), 0.001)

# Güven deposu kök sertifika sayısı + son refresh yaşı (saniye)
mdss_trusted_root_certificates{application="mersel-dss-verify-api"}
time() - mdss_trusted_root_last_success_timestamp_seconds{application="mersel-dss-verify-api"}
```

## 🔔 Alerting

### Configured Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| HighErrorRate | Error rate > 10% for 5min | Critical |
| HighResponseTime | p95 > 2s for 5min | Warning |
| HighMemoryUsage | Heap > 90% for 5min | Warning |
| HighCpuUsage | CPU > 80% for 5min | Warning |
| ServiceDown | Service down for 1min | Critical |
| HighVerificationFailureRate | INVALID > 20% for 5min | Warning |
| HighVerificationErrorRate | Exception > 0.1 req/s for 5min | Critical |
| HighVerificationLatencyP95 | p95 > 5s for 10min | Warning |
| HighRevocationFetchErrorRate | OCSP/CRL error > 0.2 req/s for 5min | Warning |
| HighTomcatThreadSaturation | busy/max threads > 85% for 5min | Warning |
| TrustedRootRefreshStale | Last success > 26h | Warning |
| TrustedRootStoreEmpty | 0 trusted roots for 10min | Critical |
| MdssToleranceUsageSpike | applied > 1 req/s for 10min | Warning |
| MdssToleranceRejectionRateHigh | rejected > 5 req/s for 10min | Info |

### Kubernetes Probe'ları & HTTP Connection Pool (HttpTimeout self-heal)

Birkaç saat çalıştıktan sonra gelen `HttpTimeout` arızasının kök nedeni DSS
`CommonsDataLoader`'ın tehlikeli default'larıydı: `maxPerRoute=2`,
`maxTotal=20`, `connectionRequest=60000ms`. Tüm OCSP istekleri tek KamuSM
host'una gittiğinden pod başına yalnız 2 eşzamanlı fetch yapılabiliyor; havuz
dolunca thread'ler 60 sn bloke kalıp Tomcat havuzunu kilitliyordu.

Uygulanan düzeltmeler:

- **Connection pool tuning** (`RevocationServicesConfiguration.applyTimeouts`):
  `connection-request-timeout=3s` (60s yerine hızlı fail), `maxPerRoute=50`,
  `maxTotal=200`. Hepsi `REVOCATION_HTTP_*` env var'larıyla ayarlanabilir.
- **Ayrı CRL cache cap'i** (`REVOCATION_CRL_CACHE_MAX_SIZE=256`) — MB
  boyutundaki CRL'lerin OCSP ile aynı 10K cap'i paylaşıp heap'i şişirmesini
  önler.
- **Readiness HealthIndicator'ları** (yalnız `readiness` grubunda, liveness'ta
  DEĞİL):
  - `verifierThreadPool` — `tomcat.threads.busy/max > %95` ise OUT_OF_SERVICE;
    doygun pod LB'den düşer, yük sağlıklı pod'lara kayar. Pod **öldürülmez**,
    yük azalınca otomatik tekrar hazır olur.
  - `trustedRootStore` — güven deposu boşsa pod hazır değil (trafik almaz).

Kubernetes probe URL'leri (Actuator):

```yaml
readinessProbe:
  httpGet: { path: /actuator/health/readiness, port: 8086 }
  periodSeconds: 10
  failureThreshold: 3
livenessProbe:
  httpGet: { path: /actuator/health/liveness, port: 8086 }
  periodSeconds: 10
  failureThreshold: 3
```

### Alert Routing

Alerts are routed based on severity:
- **Critical** → `critical-alerts` receiver
- **Warning** → `warning-alerts` receiver
- **Info** → `default` receiver

### Configure Notifications

Edit `alertmanager/alertmanager.yml`:

#### Slack
```yaml
receivers:
  - name: 'critical-alerts'
    slack_configs:
      - api_url: 'YOUR_SLACK_WEBHOOK_URL'
        channel: '#alerts-critical'
        title: 'Critical Alert: {{ .GroupLabels.alertname }}'
```

#### Email
```yaml
receivers:
  - name: 'critical-alerts'
    email_configs:
      - to: 'ops@yourcompany.com'
        from: 'alertmanager@yourcompany.com'
        smarthost: 'smtp.gmail.com:587'
        auth_username: 'your-email@gmail.com'
        auth_password: 'your-app-password'
```

#### PagerDuty
```yaml
receivers:
  - name: 'critical-alerts'
    pagerduty_configs:
      - routing_key: 'YOUR_PAGERDUTY_INTEGRATION_KEY'
```

## 🔧 Configuration

### Prometheus

Edit `prometheus/prometheus.yml`:

```yaml
global:
  scrape_interval: 15s     # Scrape every 15s
  evaluation_interval: 15s  # Evaluate rules every 15s

scrape_configs:
  - job_name: 'verify-api'
    metrics_path: '/actuator/prometheus'
    static_configs:
      - targets: ['verify-api:8086']
```

### Alert Rules

Edit `prometheus/alerts.yml`:

```yaml
groups:
  - name: custom_alerts
    rules:
      - alert: MyCustomAlert
        expr: my_metric > threshold
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "My alert"
          description: "Details"
```

## 📈 Custom Dashboards

### Create Custom Panel

1. Grafana → Dashboards → New Dashboard
2. Add Panel
3. Query editor'da PromQL yazın:
```promql
rate(http_server_requests_seconds_count{application="mersel-dss-verify-api",uri="/api/verify/xades"}[5m])
```
4. Visualization seçin (Graph, Gauge, etc.)
5. Save Dashboard

### Export/Import

```bash
# Export
curl http://localhost:3000/api/dashboards/db/my-dashboard \
  -H "Authorization: Bearer YOUR_API_KEY" \
  > my-dashboard.json

# Import
curl -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d @my-dashboard.json
```

## 🔍 Troubleshooting

### Prometheus Not Scraping

```bash
# Check targets
http://localhost:9090/targets

# Check Prometheus logs
docker-compose logs prometheus

# Test scrape endpoint
curl http://localhost:8086/actuator/prometheus
```

### Grafana Can't Connect to Prometheus

```bash
# Check Grafana logs
docker-compose logs grafana

# Test from Grafana container
docker-compose exec grafana wget -O- http://prometheus:9090/-/healthy
```

### Alerts Not Firing

```bash
# Check alert rules
http://localhost:9090/rules

# Check AlertManager
http://localhost:9093/#/alerts

# Check AlertManager logs
docker-compose logs alertmanager
```

## 📚 Resources

- [Prometheus Documentation](https://prometheus.io/docs/)
- [Grafana Documentation](https://grafana.com/docs/)
- [AlertManager Documentation](https://prometheus.io/docs/alerting/latest/alertmanager/)
- [Spring Boot Metrics](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html#actuator.metrics)

---

**Happy Monitoring!** 📊
