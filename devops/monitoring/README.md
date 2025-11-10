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
rate(http_server_requests_seconds_count{application="verify-api"}[5m])

# 95th percentile response time
histogram_quantile(0.95, rate(http_server_requests_seconds_bucket{application="verify-api"}[5m]))

# Error rate
rate(http_server_requests_seconds_count{application="verify-api",status=~"5.."}[5m])
```

#### JVM Metrics
```promql
# Heap memory usage
jvm_memory_used_bytes{application="verify-api",area="heap"} / jvm_memory_max_bytes{application="verify-api",area="heap"}

# GC time
rate(jvm_gc_pause_seconds_sum{application="verify-api"}[5m])

# Thread count
jvm_threads_live{application="verify-api"}
```

#### Verification Metrics
```promql
# Verification rate
rate(verification_operations_total{application="verify-api"}[5m])

# Verification success rate
rate(verification_success_total{application="verify-api"}[5m]) / rate(verification_operations_total{application="verify-api"}[5m])

# Verification failure rate
rate(verification_failures_total{application="verify-api"}[5m])
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
| HighVerificationFailureRate | Failure > 20% for 5min | Warning |

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
rate(http_server_requests_seconds_count{application="verify-api",uri="/api/verify/xades"}[5m])
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
