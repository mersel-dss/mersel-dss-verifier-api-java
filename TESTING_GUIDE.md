# Testing Guide - Mersel DSS Verify API

## Test Ortamı Kurulumu

### 1. API'yi Başlatma
```bash
cd /path/to/verify-api
mvn clean package
java -jar target/mersel-dss-verify-api-0.1.0.jar
```

veya

```bash
mvn spring-boot:run
```

API varsayılan olarak `http://localhost:8086` adresinde çalışır.

### 2. Health Check
```bash
curl http://localhost:8086/actuator/health
```

Beklenen yanıt:
```json
{
  "status": "UP"
}
```

## Test Senaryoları

### Scenario 1: XAdES-BES İmza Doğrulama (Simple Mode)

**Açıklama:** Basit XAdES-BES imzası doğrulaması

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@test-xades-bes.xml" \
  -F "level=SIMPLE"
```

**Beklenen Sonuç:**
- `valid: true/false`
- `signatureType: "XADES"`
- `signatureFormat: "XAdES-BES"` veya benzer
- Temel sertifika bilgileri

### Scenario 2: XAdES-T İmza Doğrulama (Comprehensive Mode)

**Açıklama:** Zaman damgalı XAdES imzası, tam detaylarla

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@test-xades-t.xml" \
  -F "level=COMPREHENSIVE"
```

**Beklenen Sonuç:**
- Tam sertifika zinciri
- Timestamp bilgileri
- ValidationDetails
- OCSP/CRL kontrol durumu

### Scenario 3: XAdES Detached İmza Doğrulama

**Açıklama:** İmza ve veri ayrı dosyalarda

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@signature-detached.xml" \
  -F "originalDocument=@original-data.xml" \
  -F "level=COMPREHENSIVE"
```

**Beklenen Sonuç:**
- Her iki dosya da doğru şekilde işlenmeli
- Message digest doğrulaması yapılmalı

### Scenario 4: PAdES (PDF) İmza Doğrulama

**Açıklama:** İmzalı PDF dokümanı doğrulama

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@signed-document.pdf" \
  -F "level=COMPREHENSIVE"
```

**Beklenen Sonuç:**
- `signatureType: "PADES"`
- PDF'teki tüm imzalar listelenmeli
- Her imza için ayrı SignatureInfo

### Scenario 5: XAdES-A Arşiv İmzası

**Açıklama:** Uzun vadeli arşivleme imzası

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@xades-a-archive.xml" \
  -F "level=COMPREHENSIVE"
```

**Beklenen Sonuç:**
- `signatureLevel: "XAdES-A"` veya `"XAdES_BASELINE_LTA"`
- Birden fazla timestamp
- Arşiv timestamp bilgileri

### Scenario 6: XAdES-EPES Policy Bazlı İmza

**Açıklama:** Explicit policy içeren imza

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@xades-epes.xml" \
  -F "level=COMPREHENSIVE"
```

**Beklenen Sonuç:**
- `policyIdentifier` alanı dolu olmalı
- Policy OID gösterilmeli

### Scenario 7: Zaman Damgası Doğrulama

**Açıklama:** Standalone timestamp token doğrulama

```bash
curl -X POST "http://localhost:8086/api/v1/verify/timestamp" \
  -H "Accept: application/json" \
  -F "timestampFile=@timestamp.tsr" \
  -F "validateCertificate=true"
```

**Beklenen Sonuç:**
- `timestampTime`: Timestamp zamanı
- `tsaName`: TSA adı
- TSA sertifika bilgileri

### Scenario 8: Zaman Damgası + Message Imprint Doğrulama

**Açıklama:** Timestamp'in orijinal veriye ait olduğunu doğrulama

```bash
curl -X POST "http://localhost:8086/api/v1/verify/timestamp" \
  -H "Accept: application/json" \
  -F "timestampFile=@timestamp.tsr" \
  -F "originalData=@document.pdf" \
  -F "validateCertificate=true"
```

**Beklenen Sonuç:**
- Message imprint doğrulaması yapılmalı
- `digestAlgorithm` belirtilmeli
- İmprint eşleşmezse hata verilmeli

### Scenario 9: Çoklu İmza Doğrulama

**Açıklama:** Birden fazla imza içeren doküman

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@multi-signature.xml" \
  -F "level=COMPREHENSIVE"
```

**Beklenen Sonuç:**
- `signatureCount > 1`
- Her imza için ayrı SignatureInfo
- Genel geçerlilik: Tüm imzalar geçerliyse true

### Scenario 10: Geçersiz İmza Testi

**Açıklama:** Bozulmuş veya geçersiz imza

```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -H "Accept: application/json" \
  -F "signedDocument=@invalid-signature.xml" \
  -F "level=COMPREHENSIVE"
```

**Beklenen Sonuç:**
- `valid: false`
- `validationErrors` dolu olmalı
- `indication: "FAILED"` veya `"INDETERMINATE"`

## Legacy Endpoint Testleri

### XAdES Legacy Endpoint
```bash
curl -X POST "http://localhost:8086/api/v1/verify/xades" \
  -F "signedDocument=@test-xades.xml" \
  -F "level=SIMPLE"
```

### PAdES Legacy Endpoint
```bash
curl -X POST "http://localhost:8086/api/v1/verify/pades" \
  -F "signedDocument=@test-pades.pdf" \
  -F "level=SIMPLE"
```

### CAdES Endpoint
```bash
curl -X POST "http://localhost:8086/api/v1/verify/cades" \
  -F "signedDocument=@test-cades.p7s" \
  -F "originalDocument=@original.txt" \
  -F "level=COMPREHENSIVE"
```

## Performans Testleri

### Büyük Dosya Testi
```bash
# 50MB+ PDF
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@large-signed.pdf" \
  -F "level=SIMPLE" \
  --max-time 60
```

### Çoklu İmza Performans Testi
```bash
# 10+ imza içeren doküman
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@10-signatures.xml" \
  -F "level=COMPREHENSIVE" \
  --max-time 120
```

## Hata Durumu Testleri

### Test 1: Eksik Parametre
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature"
```
**Beklenen:** HTTP 400 Bad Request

### Test 2: Geçersiz Dosya Formatı
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@image.jpg" \
  -F "level=SIMPLE"
```
**Beklenen:** HTTP 400 veya validation error

### Test 3: Çok Büyük Dosya
```bash
# 250MB+ dosya (limit: 200MB)
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@huge-file.pdf" \
  -F "level=SIMPLE"
```
**Beklenen:** HTTP 413 Payload Too Large veya 400

### Test 4: Geçersiz Level Parametresi
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@test.xml" \
  -F "level=INVALID"
```
**Beklenen:** SIMPLE modu kullanılır (default)

## Monitoring Testleri

### Metrics Kontrolü
```bash
curl http://localhost:8086/actuator/prometheus | grep verification
```

### Health Check
```bash
curl http://localhost:8086/actuator/health
```

### API Info
```bash
curl http://localhost:8086/actuator/info
```

## Automation Scripts

### Bash Test Script Örneği
```bash
#!/bin/bash

API_BASE="http://localhost:8086/api/v1/verify"

# Test 1: XAdES Simple
echo "Testing XAdES Simple..."
curl -X POST "$API_BASE/signature" \
  -F "signedDocument=@test-xades.xml" \
  -F "level=SIMPLE" \
  -o result1.json

# Test 2: XAdES Comprehensive
echo "Testing XAdES Comprehensive..."
curl -X POST "$API_BASE/signature" \
  -F "signedDocument=@test-xades.xml" \
  -F "level=COMPREHENSIVE" \
  -o result2.json

# Test 3: PAdES
echo "Testing PAdES..."
curl -X POST "$API_BASE/signature" \
  -F "signedDocument=@test-pades.pdf" \
  -F "level=COMPREHENSIVE" \
  -o result3.json

# Test 4: Timestamp
echo "Testing Timestamp..."
curl -X POST "$API_BASE/timestamp" \
  -F "timestampFile=@timestamp.tsr" \
  -F "validateCertificate=true" \
  -o result4.json

echo "All tests completed!"
```

## Python Test Script Örneği

```python
import requests
import json

API_BASE = "http://localhost:8086/api/v1/verify"

def test_xades_simple():
    files = {'signedDocument': open('test-xades.xml', 'rb')}
    data = {'level': 'SIMPLE'}
    response = requests.post(f"{API_BASE}/signature", files=files, data=data)
    print(f"XAdES Simple: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def test_xades_comprehensive():
    files = {'signedDocument': open('test-xades.xml', 'rb')}
    data = {'level': 'COMPREHENSIVE'}
    response = requests.post(f"{API_BASE}/signature", files=files, data=data)
    print(f"XAdES Comprehensive: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

def test_timestamp():
    files = {'timestampFile': open('timestamp.tsr', 'rb')}
    data = {'validateCertificate': 'true'}
    response = requests.post(f"{API_BASE}/timestamp", files=files, data=data)
    print(f"Timestamp: {response.status_code}")
    print(json.dumps(response.json(), indent=2))

if __name__ == "__main__":
    test_xades_simple()
    test_xades_comprehensive()
    test_timestamp()
```

## Test Verileri Hazırlama

### XAdES Test Verisi Oluşturma
sign-api projesini kullanarak test verileri oluşturabilirsiniz:

```bash
# XAdES-BES
curl -X POST "http://localhost:8080/api/v1/sign/xades" \
  -F "document=@test.xml" \
  -F "certificateFile=@test.pfx" \
  -F "password=12345" \
  -F "signatureLevel=XAdES_BASELINE_B" \
  -o signed-xades-bes.xml

# XAdES-T (with timestamp)
curl -X POST "http://localhost:8080/api/v1/sign/xades" \
  -F "document=@test.xml" \
  -F "certificateFile=@test.pfx" \
  -F "password=12345" \
  -F "signatureLevel=XAdES_BASELINE_T" \
  -F "tsaUrl=http://zd.kamusm.gov.tr" \
  -o signed-xades-t.xml
```

## Sonuç Değerlendirme

### Başarılı Test Kriterleri
- ✅ HTTP 200 status code
- ✅ JSON response formatı doğru
- ✅ `valid` field var ve boolean
- ✅ `signatureType` doğru belirleniyor
- ✅ Sertifika bilgileri eksiksiz
- ✅ Hatalar varsa `validationErrors` dolu
- ✅ Comprehensive modda ek detaylar var

### Başarısız Test İşaretleri
- ❌ HTTP 500 Internal Server Error
- ❌ Timeout
- ❌ Eksik response field'ları
- ❌ Null pointer exceptions
- ❌ Yanlış signatureType belirleme

## Troubleshooting

### Problem: "Signature validation timeout"
**Çözüm:** OCSP/CRL kontrollerini devre dışı bırakın:
```properties
verification.online-validation-enabled=false
```

### Problem: "Trusted root not found"
**Çözüm:** KamuSM certificate store'u kontrol edin:
```properties
trusted.root.resolver.type=kamusm-online
```

### Problem: "Certificate chain validation failed"
**Çözüm:** Sertifika zincirini kontrol edin ve gerekirse custom root ekleyin.

## Continuous Integration Test

```yaml
# .github/workflows/test.yml
name: API Tests
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up JDK
        uses: actions/setup-java@v2
        with:
          java-version: '8'
      - name: Build and Test
        run: |
          mvn clean package
          java -jar target/*.jar &
          sleep 30
          bash test-suite.sh
```

## Test Coverage Hedefleri

- [ ] Tüm XAdES seviyeleri (BES, EPES, T, C, X, XL, A)
- [ ] Tüm PAdES seviyeleri (B-B, B-T, B-LT, B-LTA)
- [ ] CAdES formatları
- [ ] Detached signatures
- [ ] Multiple signatures
- [ ] Timestamp validation
- [ ] Message imprint validation
- [ ] Certificate chain validation
- [ ] OCSP/CRL checks
- [ ] Error scenarios
- [ ] Performance benchmarks

