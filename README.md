# 🔍 Verify API

Türkiye e-imza standartlarına uygun dijital imza doğrulama (PAdES, XAdES, Timestamp) servisi.

[![Java](https://img.shields.io/badge/Java-8+-orange.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-2.7-green.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![DSS](https://img.shields.io/badge/DSS-6.3-blue.svg)](https://github.com/esig/dss)
[![Version](https://img.shields.io/badge/version-unreleased-blue.svg)](https://github.com/mersel-dss/verify-api)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 📚 Tam Dökümantasyon

### 👉 [Sign Platform Dökümanları](https://dss.mersel.dev) 👈

**Tüm detaylı dökümantasyon merkezi dökümantasyon sitesinde bulunur:**

- 📖 Kurulum ve yapılandırma
- 🚀 Hızlı başlangıç kılavuzu
- 🔍 İmza doğrulama detayları
- ⚙️ Docker ve Kubernetes deployment
- 📊 Monitoring ve performance tuning
- ⏰ Zaman damgası doğrulama
- 💡 Kod örnekleri ve kullanım senaryoları
- 🧪 Test stratejileri
- 🔒 Güvenlik en iyi pratikleri

---

Bu API, PAdES (PDF), XAdES (XML) dijital imzaların ve zaman damgalarının doğrulanması için kapsamlı bir servis sağlar. EU DSS (Digital Signature Service) kütüphanesi üzerine inşa edilmiştir.

## 🌟 Özellikler

### 📝 Desteklenen İmza Formatları

#### XAdES (XML Advanced Electronic Signatures)
- ✅ **XAdES-BES** - Basic Electronic Signature
- ✅ **XAdES-EPES** - Explicit Policy-based Electronic Signature
- ✅ **XAdES-T** - Timestamp
- ✅ **XAdES-C** - Complete
- ✅ **XAdES-X** - eXtended
- ✅ **XAdES-XL** - eXtended Long-term
- ✅ **XAdES-A** - Archival (uzun vadeli arşivleme)

#### PAdES (PDF Advanced Electronic Signatures)
- ✅ **PAdES-B-B** - Basic
- ✅ **PAdES-B-T** - Basic with Timestamp
- ✅ **PAdES-B-LT** - Basic Long-Term
- ✅ **PAdES-B-LTA** - Basic Long-Term with Archive timestamp

#### CAdES (CMS Advanced Electronic Signatures)
- ✅ **CAdES-BES** - Basic Electronic Signature
- ✅ **CAdES-EPES** - Explicit Policy-based Electronic Signature
- ✅ **CAdES-T, C, X, XL, A** - Tüm seviyeler desteklenir

### 🔧 Temel Özellikler

- ✅ **Birleşik Doğrulama Endpoint** - Tüm formatları otomatik algılar
- ✅ **Enveloped, Enveloping ve Detached İmza** - Tüm imza tipleri
- ✅ **Zaman Damgası Doğrulama** - RFC 3161 uyumlu, TSA sertifika kontrolü
- ✅ **Message Imprint Doğrulama** - Orijinal veri ile timestamp eşleştirme
- ✅ **Sertifika Zinciri Doğrulama** - Güvenilir root'a kadar tam zincir
- ✅ **OCSP ve CRL Kontrolü** - Sertifika iptal durumu kontrolü
- ✅ **AIA Support** - Otomatik sertifika zinciri tamamlama
- ✅ **Güvenilir Kök Sertifika Resolver Desteği** - Üç farklı resolver tipi
  - **KamuSM XML Depo Online**: İnternet üzerinden KamuSM XML deposunu yükler
  - **KamuSM XML Depo Offline**: Yerel dosyadan KamuSM XML deposunu yükler
  - **Certificate Folder**: Klasördeki tüm .crt/.cer/.pem dosyalarını yükler
- ✅ **İki Seviyeli Doğrulama**
  - **Simple**: Hızlı, temel imza doğrulaması
  - **Comprehensive**: Detaylı, tüm bilgileri içeren doğrulama (sertifika zinciri, policy bilgisi, vb.)
- ✅ **Çoklu İmza Desteği** - Tek dokümanda birden fazla imza
- ✅ **Docker Desteği** - Kolay deployment
- ✅ **Prometheus Metrics** - Monitoring ve metrikleme
- ✅ **RESTful API** - OpenAPI/Scalar dokümantasyonu
- ✅ **OpenAPI Dokümantasyonu** - Swagger UI alternatifi

## 🚀 Hızlı Başlangıç

### Gereksinimler

- Java 8 veya üzeri
- Maven 3.6+
- Docker (opsiyonel)

### Local Çalıştırma

1. **Repoyu klonlayın:**
```bash
git clone https://github.com/mersel-dss/verify-api.git
cd verify-api
```

2. **Maven ile derleyin:**
```bash
mvn clean package
```

3. **Uygulamayı başlatın:**
```bash
java -jar target/verify-api.jar
```

Servis `http://localhost:8086` adresinde çalışmaya başlayacaktır.

### Docker ile Çalıştırma

1. **Docker Compose ile başlatın:**
```bash
cd devops/docker
cp .env.example .env
docker-compose up -d
```

2. **Logları kontrol edin:**
```bash
docker-compose logs -f verify-api
```

3. **Health check:**
```bash
curl http://localhost:8086/api/v1/health
```

## 📚 API Kullanımı

### PAdES (PDF) İmza Doğrulama

#### Basit Doğrulama
```bash
curl -X POST http://localhost:8086/api/v1/verify/pades \
  -F "signedDocument=@signed-document.pdf" \
  -F "level=SIMPLE"
```

#### Kapsamlı Doğrulama (Tüm Detaylar)
```bash
curl -X POST http://localhost:8086/api/v1/verify/pades \
  -F "signedDocument=@signed-document.pdf" \
  -F "level=COMPREHENSIVE" \
  -F "checkRevocation=true" \
  -F "validateTimestamp=true"
```

> **Not:** 
> - `level=SIMPLE`: Sadece temel bilgiler (valid/invalid, format, signing time)
> - `level=COMPREHENSIVE`: Tüm detaylar (sertifika zinciri, timestamp, validation details)
> - Validation parametreleri (`checkRevocation`, `validateTimestamp`) her iki seviyede de kullanılabilir

**Örnek Response (Simple):**
```json
{
  "valid": true,
  "status": "VALID",
  "signatureType": "PADES",
  "verificationTime": "2024-11-08T10:30:00Z",
  "signatures": [
    {
      "signatureId": "id-1234",
      "valid": true,
      "signatureFormat": "PAdES-BASELINE-B",
      "signingTime": "2024-11-07T14:20:00Z"
    }
  ]
}
```

**Örnek Response (Comprehensive):**
```json
{
  "valid": true,
  "status": "VALID",
  "signatureType": "PADES",
  "verificationTime": "2024-11-08T10:30:00Z",
  "signatures": [
    {
      "signatureId": "id-1234",
      "valid": true,
      "signatureFormat": "PAdES-BASELINE-LT",
      "signatureLevel": "PAdES-BASELINE-LT",
      "signingTime": "2024-11-07T14:20:00Z",
      "claimedSigningTime": "2024-11-07T14:20:00Z",
      "signerCertificate": {
        "subjectDN": "CN=Test User, O=Test Organization",
        "issuerDN": "CN=Test CA, O=KamuSM",
        "serialNumber": "5A2295753A906E",
        "notBefore": "2023-01-01T00:00:00Z",
        "notAfter": "2025-01-01T00:00:00Z",
        "trusted": true,
        "expired": false,
        "revoked": false
      },
      "certificateChain": [...],
      "timestampInfo": {
        "valid": true,
        "timestampTime": "2024-11-07T14:20:05Z"
      }
    }
  ],
  "validationDetails": {
    "signatureIntact": true,
    "certificateChainValid": true,
    "certificateNotExpired": true,
    "certificateNotRevoked": true,
    "trustAnchorReached": true,
    "timestampValid": true
  }
}
```

### XAdES (XML) İmza Doğrulama

#### Basit Doğrulama (Enveloped/Enveloping)
```bash
curl -X POST http://localhost:8086/api/v1/verify/xades \
  -F "signedDocument=@signed-document.xml" \
  -F "level=SIMPLE"
```

#### Kapsamlı Doğrulama (Tüm Detaylar)
```bash
curl -X POST http://localhost:8086/api/v1/verify/xades \
  -F "signedDocument=@signed-document.xml" \
  -F "level=COMPREHENSIVE" \
  -F "checkRevocation=true" \
  -F "validateTimestamp=true"
```

#### Detached İmza Doğrulama
```bash
curl -X POST http://localhost:8086/api/v1/verify/xades \
  -F "signedDocument=@signature.xml" \
  -F "originalDocument=@original-document.xml" \
  -F "level=COMPREHENSIVE" \
  -F "checkRevocation=true"
```

> **Not:** 
> - DSS otomatik olarak imza tipini (Enveloped, Enveloping, Detached) tespit eder
> - **Detached imza için `originalDocument` parametresi opsiyoneldir** - DSS otomatik tespit edebilir ancak belirtilmesi daha güvenilir sonuçlar verir
> - `level` parametresi sadece response detay seviyesini belirler
> - Validation özellikleri (OCSP/CRL, timestamp) bağımsız olarak kontrol edilir

### Zaman Damgası Doğrulama

```bash
curl -X POST http://localhost:8086/api/v1/verify/timestamp \
  -F "timestampToken=@timestamp.tst" \
  -F "originalData=@data.pdf" \
  -F "validateCertificate=true"
```

**Örnek Response:**
```json
{
  "valid": true,
  "status": "VALID",
  "timestampTime": "2024-11-07T14:20:05Z",
  "tsaName": "CN=KamuSM TSA",
  "digestAlgorithm": "SHA-256",
  "messageImprint": "ZGF0YSBoYXNo...",
  "tsaCertificate": {
    "subjectDN": "CN=KamuSM TSA",
    "notBefore": "2023-01-01T00:00:00Z",
    "notAfter": "2026-01-01T00:00:00Z"
  },
  "verificationTime": "2024-11-08T10:30:00Z"
}
```


## ⚙️ Konfigürasyon

### Environment Variables

Uygulama aşağıdaki environment variable'lar ile yapılandırılabilir:

#### Server Configuration
```bash
SERVER_PORT=8086                    # Sunucu portu
```

#### Logging
```bash
LOG_LEVEL=INFO                      # Log seviyesi (DEBUG, INFO, WARN, ERROR)
LOG_PATH=./logs                     # Log dosya dizini
```

#### CORS
```bash
CORS_ALLOWED_ORIGINS=*              # İzin verilen origin'ler
CORS_ALLOWED_METHODS=GET,POST       # İzin verilen HTTP metodları
```

#### Certificate Store (Zorunlu)
```bash
CERTSTORE_PATH=/path/to/store.jks   # Sertifika deposu yolu (zorunlu)
CERTSTORE_PASSWORD=secret           # Sertifika deposu şifresi
CUSTOM_ROOT_CERT_PATH=/path/to/root.cer  # Özel root sertifika (opsiyonel)
```

#### Validation Configuration
```bash
ONLINE_VALIDATION_ENABLED=true      # Online OCSP/CRL kontrolü
VERIFICATION_POLICY=STRICT          # STRICT veya RELAXED
CERT_CACHE_TTL=3600                 # Sertifika cache süresi (saniye)
CRL_CACHE_TTL=3600                  # CRL cache süresi (saniye)
```

### Güvenilir Kök Sertifika Resolver Kullanımı

Sistem üç farklı resolver tipini destekler. `TRUSTED_ROOT_RESOLVER_TYPE` parametresi ile seçim yapılır.

#### 1. KamuSM XML Depo Online (Varsayılan)

Varsayılan olarak, KamuSM root ve ara sertifikaları **otomatik** olarak şu adresten yüklenir:
- [http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml](http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml)

Bu sayede her zaman güncel sertifikalar kullanılır. Periyodik olarak otomatik yenilenir (varsayılan: her gün saat 03:15).

```bash
export TRUSTED_ROOT_RESOLVER_TYPE=kamusm-online
export KAMUSM_ROOT_URL=http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml
export KAMUSM_ROOT_REFRESH_CRON="0 15 3 * * *"  # Her gün saat 03:15
```

#### 2. KamuSM XML Depo Offline

Offline ortamlarda veya internet bağlantısı olmayan sistemlerde, KamuSM sertifika deposunu yerel dosya sisteminden yükleyebilirsiniz:

```bash
export TRUSTED_ROOT_RESOLVER_TYPE=kamusm-offline
export KAMUSM_ROOT_OFFLINE_PATH=file:/path/to/SertifikaDeposu.xml
# veya classpath'ten
export KAMUSM_ROOT_OFFLINE_PATH=classpath:certs/SertifikaDeposu.xml
```

**Offline Mod Kullanım Senaryoları:**
- Air-gapped (izole) sistemler
- İnternet bağlantısı olmayan ortamlar
- Güvenlik gereksinimleri nedeniyle dış bağlantı kısıtlamaları
- Yerel sertifika deposu kullanımı

**Not:** Offline modda sertifikalar sadece uygulama başlangıcında yüklenir. Otomatik yenileme yapılmaz.

#### 3. Certificate Folder Resolver

Belirtilen klasördeki tüm `.crt`, `.cer` ve `.pem` dosyalarını güvenilir kök sertifika olarak yükler. Bu resolver, özel sertifika klasörlerinden sertifika yüklemek için idealdir.

```bash
export TRUSTED_ROOT_RESOLVER_TYPE=certificate-folder
export TRUSTED_ROOT_CERT_FOLDER_PATH=/path/to/certificates
# veya file: prefix ile
export TRUSTED_ROOT_CERT_FOLDER_PATH=file:/path/to/certificates
```

**Certificate Folder Resolver Kullanım Senaryoları:**
- Özel sertifika klasörlerinden yükleme
- Kurumsal CA sertifikalarının toplu yüklenmesi
- Test ortamlarında özel sertifika kullanımı
- Farklı kaynaklardan sertifika birleştirme

**Not:** Klasördeki tüm geçerli sertifika dosyaları otomatik olarak yüklenir. Alt klasörler taranmaz.

#### Sertifika Deposu (Zorunlu)

Sertifika deposu kullanmak için (zorunlu):

```bash
export CERTSTORE_PATH=/path/to/kamusm-certstore.jks
export CERTSTORE_PASSWORD=yourpassword
```

veya özel bir root sertifika eklemek için:

```bash
export CUSTOM_ROOT_CERT_PATH=/path/to/custom-root.cer
```

## 📊 Monitoring

Prometheus metrikleri `/actuator/prometheus` endpoint'inde sunulur:

```bash
curl http://localhost:8086/actuator/prometheus
```

Grafana ile birlikte çalıştırmak için:

```bash
docker-compose --profile monitoring up -d
```

- Grafana: http://localhost:3000 (admin/admin)
- Prometheus: http://localhost:9090

## 🔒 Güvenlik

### Production Önerileri

1. **CORS Ayarları**: Production'da `CORS_ALLOWED_ORIGINS` değerini spesifik domain'lere sınırlayın
2. **HTTPS**: Reverse proxy (nginx, traefik) ile HTTPS kullanın
3. **Rate Limiting**: API rate limiting uygulayın
4. **Network Segmentation**: Servislerinizi izole network'lerde çalıştırın
5. **Sertifika Güvenliği**: Sertifika deposu şifrelerini güvenli bir şekilde saklayın (vault, secrets manager)

## 🧪 Test

```bash
# Tüm testleri çalıştır
mvn test

# Spesifik test
mvn test -Dtest=SignatureVerificationServiceTest
```

## 📖 API Dokümantasyonu

OpenAPI dokümantasyonuna erişim:

```
http://localhost:8086/api-docs
```

## 🔗 Önemli Bağlantılar

| Dosya | Açıklama |
|-------|----------|
| [**dss.mersel.dev**](https://dss.mersel.dev) | 📚 **Merkezi Dökümantasyon** |
| [LICENSE](LICENSE) | MIT Lisansı |
| [CHANGELOG.md](CHANGELOG.md) | Versiyon geçmişi |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Katkıda bulunma rehberi |
| [SECURITY.md](SECURITY.md) | Güvenlik politikası |
| [COMPARISON_REPORT.md](COMPARISON_REPORT.md) | Sign-API ile karşılaştırma raporu |

---

## 🤝 Katkıda Bulunma

[CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bakın.

---

## 📄 Lisans

[MIT](LICENSE)

---

## 💡 Hatırlatma

**Detaylı dökümantasyon, API referansları, deployment rehberleri ve tüm güncellemeler için:**

### 👉 [https://dss.mersel.dev](https://dss.mersel.dev) merkezi dökümantasyon sitesini ziyaret edin! 📚

---

**Not**: Bu servis, [sign-api](https://github.com/mersel-dss/mersel-dss-server-signer-java) projesinin doğrulama karşılığıdır. İmzalama işlemleri için sign-api'yi kullanın.

