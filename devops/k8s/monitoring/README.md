# Kubernetes Monitoring — Mersel DSS Verify API

Bu klasör, **kube-prometheus-stack** (Prometheus Operator) ile çalışan bir
Kubernetes ortamında verifier'ı izlemek için gereken tüm kaynakları içerir.

## Ortam varsayımları (sizin cluster'ınıza göre dolduruldu)

| Değer | Bu repo'da | Nasıl doğrularsın |
|-------|-----------|-------------------|
| Uygulama namespace | `general` | `kubectl get deploy -n general` |
| Monitoring namespace | `o11y` | `kubectl get prometheus -A` |
| Helm release adı (label) | `prometheus` | aşağıdaki komut |
| App metrik portu | `8080` | `SERVER_PORT=8080` (containerPort:80 yanıltıcı) |
| App `application` etiketi | `mersel-dss-verify-api` | `spring.application.name` |

Operator'ın hangi label/namespace'leri taradığını doğrula:

```bash
kubectl -n o11y get prometheus -o jsonpath='{range .items[*]}{"sm="}{.spec.serviceMonitorSelector}{" smNs="}{.spec.serviceMonitorNamespaceSelector}{" rule="}{.spec.ruleSelector}{"\n"}{end}'; echo
```
- `sm`/`rule` → `release: prometheus` bekleniyor (manifest label'ı bu).
- `smNs` boş `{}` ise tüm namespace'ler taranır (ServiceMonitor `general`'da kalabilir).
  Boş değil ve `general`'ı kapsamıyorsa: `servicemonitor.yaml`'ın `metadata.namespace`'ini `o11y` yap.

## Dosyalar

| Dosya | Kaynak | Namespace |
|-------|--------|-----------|
| `service.yaml` | metrics Service (8080 → `http-metrics`) | `general` |
| `servicemonitor.yaml` | ServiceMonitor (scrape `/actuator/prometheus`) | `general` |
| `prometheusrule.yaml` | tüm alert kuralları | `o11y` |
| `kustomization.yaml` | yukarıdaki 3 kaynağı bundle eder | — |
| `deployment-probes.patch.yaml` | readiness/liveness/startup probe (port 8080) | `general` |

## Uygulama

### 1) Scrape + alert'ler (Service + ServiceMonitor + PrometheusRule)

```bash
kubectl apply -k devops/k8s/monitoring/
```

> Kustomize yoksa tek tek de uygulayabilirsin:
> ```bash
> kubectl apply -f devops/k8s/monitoring/service.yaml
> kubectl apply -f devops/k8s/monitoring/servicemonitor.yaml
> kubectl apply -f devops/k8s/monitoring/prometheusrule.yaml
> ```

### 1b) Grafana dashboard (ConfigMap — ayrı komut)

Dashboard JSON'u repo'daki tek doğruluk kaynağında durduğu ve kustomize kök
dışından dosya okumaya izin vermediği için ayrı uygulanır:

```bash
kubectl -n o11y create configmap mersel-verify-api-dashboard \
  --from-file=mersel-dss-verify-api.json=devops/monitoring/grafana/dashboards/mersel-dss-verify-api.json \
  --dry-run=client -o yaml \
| kubectl label -f - --local -o yaml --dry-run=client grafana_dashboard=1 \
| kubectl apply -f -
```

### 2) Probe'lar (readiness self-heal) — Helm/ArgoCD üzerinden

⚠️ Deployment ArgoCD (`java-proxies`) + Helm (`backend-api-base-...`) ile
yönetiliyor. `deployment-probes.patch.yaml` içindeki değerleri **Helm chart
values'una** girip ArgoCD ile sync et — `kubectl patch` bir sonraki sync'te
geri alınır. Acil/test için manuel patch:

```bash
kubectl -n general patch deployment mersel-signature-verifier-proxy \
  --type merge --patch-file devops/k8s/monitoring/deployment-probes.patch.yaml
```

## Doğrulama

```bash
# App 8080'de metrik + readiness veriyor mu?
kubectl -n general port-forward deploy/mersel-signature-verifier-proxy 8080:8080
curl -s localhost:8080/actuator/prometheus | grep -c mdss_     # >0 olmalı
curl -s localhost:8080/actuator/health/readiness               # {"status":"UP",...}

# Prometheus target'ı topladı mı?
kubectl -n o11y port-forward svc/prometheus-prometheus 9090:9090
# http://localhost:9090/targets → "mersel-signature-verifier-proxy" UP

# Alert kuralları yüklendi mi?
# http://localhost:9090/rules → verify_api_alerts grubu

# Grafana dashboard geldi mi?
kubectl -n o11y port-forward svc/prometheus-grafana 3000:80
# http://localhost:3000 → Dashboards → "Mersel DSS Verify API"
```

## Sık karşılaşılan sorunlar

- **Target görünmüyor**: ServiceMonitor label'ı (`release: prometheus`) ya da
  namespace selector eşleşmiyor. Yukarıdaki doğrulama komutunu çalıştır.
- **Target DOWN / connection refused**: muhtemelen 8080 yerine 80'e bağlanıyor.
  `service.yaml` `targetPort: 8080` olmalı.
- **Alert'ler yok**: `prometheusrule.yaml` label'ı `ruleSelector` ile uyumsuz.
- **Dashboard gelmiyor**: sidecar ConfigMap'i farklı namespace'te arıyor olabilir;
  `grafana_dashboard=1` label'ını ve ConfigMap namespace'ini kontrol et.
