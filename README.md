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
- ✅ **Strict-Safe Revocation Pipeline** - OCSP/CRL üretim sınıfı: Caffeine cache (token `nextUpdate`-aware TTL + configurable üst sınır), exponential backoff + jitter retry (anlık flake toleransı), INFO seviyesinde audit log, Prometheus metric expose. Strict policy'de tüm retry'lar tükenirse imza güvenle `INDETERMINATE/NO_REVOCATION_DATA` döner — anlık kesinti yüzünden valid imza reddedilmez, gerçek kesintide de "iptal mi belli değil" asla VALID gösterilmez. Sonuçlar her sertifika için response'a zengin biçimde yansır (`signerCertificate.revocation` alt nesnesi: `source`, `status`, `responderUrl`, `producedAt`/`thisUpdate`/`nextUpdate`, `origin`, vb.).
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
      "signingTime": "2024-11-07T14:20:00Z",
      "signatureAlgorithm": "RSA_SHA256",
      "digestAlgorithm": "SHA256"
    }
  ]
}
```

> **`signatureAlgorithm` vs `digestAlgorithm`:**
> - `signatureAlgorithm` → İmzayı üreten kriptografik kompozit
>   (encryption + digest). DSS `SignatureAlgorithm` enum sabit adı —
>   örn. `RSA_SHA256`, `ECDSA_SHA384`, `RSA_SSA_PSS_SHA256`. Belgeyi
>   imzacının nasıl imzaladığını söyler.
> - `digestAlgorithm` → `ds:SignedInfo` özet algoritması — örn.
>   `SHA256`. Belgenin nasıl özetlendiğini söyler; kriptografik politika
>   denetimi (zayıf algoritma yasağı) için tek başına da yeterli.
>
> Bu iki alan SIMPLE ve COMPREHENSIVE modlarda eşit görünür ve
> imzanın <em>kendisinin</em> algoritmasıdır — `signerCertificate.signatureAlgorithm`
> ise CA'nın leaf sertifikayı hangi algoritmayla imzaladığını gösterir
> (farklı kavram, karıştırılmamalı).

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
      "signatureAlgorithm": "RSA_SHA256",
      "digestAlgorithm": "SHA256",
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
        "revoked": false,
        "revocation": {
          "source": "OCSP",
          "status": "GOOD",
          "producedAt": "2024-11-07T14:20:03Z",
          "thisUpdate": "2024-11-07T14:00:00Z",
          "nextUpdate": "2024-11-07T15:00:00Z",
          "responderUrl": "http://ocsp.kamusm.gov.tr",
          "origin": "REVOCATION_VALUES"
        }
      },
      "chainRevocationStatus": "ALL_GOOD",
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
ONLINE_VALIDATION_ENABLED=true      # Online OCSP/CRL kontrolü (master switch).
                                    # false: revocation source bean'leri context'e yaratılmaz,
                                    # tek paket bile dışarı çıkmaz (air-gapped / offline modu).
                                    # OCSP/CRL pipeline parametreleri için aşağıdaki
                                    # "Revocation Pipeline (OCSP/CRL)" bölümüne bakın.
VERIFICATION_STRICT_MODE=true       # Rapor seviyesi katılık: SubIndication varsa imza invalid sayılır
                                    # (Not: Bu DSS policy XML değildir; DSS validation kuralları
                                    #  için aşağıdaki "DSS Validation Policy" bölümüne bakın.)
TR_LEGACY_XADES_TOLERANCE=true      # KamuSM/GİB üreticisinin XAdES SignedProperties Type URI
                                    # yazım hatasına tolerans (TÜBİTAK İmzager paritesi).
                                    # Detaylar için aşağıdaki "TR-Legacy XAdES Toleransı" bölümüne bakın.
CERT_CACHE_TTL=3600                 # Sertifika cache süresi (saniye)
CRL_CACHE_TTL=3600                  # [LEGACY] CRL cache süresi (saniye). Geriye dönük uyumluluk
                                    # için korunuyor; yeni revocation cache sistemi
                                    # REVOCATION_CACHE_TTL'i kullanır — set edilmezse buradaki
                                    # değer fallback olur. Detay: "Revocation Pipeline" bölümü.
```

#### DSS Validation Policy

Doğrulamada kullanılacak constraint XML'ini iki kademeli olarak seçer:

```bash
# 1) Built-in profil — değerler: signer-strict (DEFAULT) | strict
DSS_POLICY_PROFILE=signer-strict

# 2) Tam custom override — set edilirse DSS_POLICY_PROFILE ignore edilir
#    Spring Resource paterni: classpath: | file: | http(s):
DSS_POLICY_PATH=                    # boş = profil kullan
# Production typical:
# DSS_POLICY_PATH=file:/etc/mersel-dss-verify/policy.xml
```

| Profil          | İmzacı sertifika OCSP/CRL | Ara CA OCSP/CRL | TS signer OCSP/CRL | TS CA OCSP/CRL | Ne zaman? |
|-----------------|---------------------------|-----------------|--------------------|----------------|-----------|
| `signer-strict` | **FAIL** (zorunlu)        | WARN            | WARN               | WARN           | Mali Mühür / KamuSM üretim default'u. İptal kontrolü garanti, ara CA endpoint kesintilerinde yine validation devam eder. |
| `strict`        | **FAIL**                  | **FAIL**        | **FAIL**           | WARN           | eIDAS-QES paralel; online OCSP/CRL altyapısı kesintisiz olan ortamlar (sigorta, banka, kamu kurumu). |

**Profil seçim kılavuzu** — özet:

- **`signer-strict` (default)**: İmzacının iptali için zero-tolerance, ama ara CA OCSP responder'larının geçici kesintilerinde imzayı feda etmez. Türkiye e-Fatura / e-Defter ekosisteminde KamuSM ara CA'larının operasyonel realitesini gözeten **pragmatik denge**. Tüketici `chainRevocationStatus: LEAF_GOOD_CA_REVOKED` görse bile `valid: true` döner — politika tercihini explicit hale getirir.
- **`strict`**: eIDAS QES paralelinde tüm zincir için sıkı davranış — ara CA REVOKED ise imza geçersiz. **Operasyonel kesinti tolere edilmez**; OCSP/CRL altyapısı garanti edilmiş kurumsal ortamlar için. `chainRevocationStatus: LEAF_GOOD_CA_REVOKED` durumunda `valid: false` + sub-indication `REVOKED_CA_NO_POE` döner.
- **Custom XML**: Yukarıdaki iki profil ihtiyacı karşılamazsa `DSS_POLICY_PATH` ile kendi XML'inizi mount edin. Built-in profiller `src/main/resources/policy/` altında tam yorumlu, baz alabilirsiniz.

**Önemli:** `DSS_POLICY_PATH` ile verilen XML erişilemezse servis sessizce
DSS default'una düşmez — `VerificationException` atar. Built-in profil XML
jar'da yoksa da aynı şekilde fail-fast. Bilinmeyen `DSS_POLICY_PROFILE`
değeri verilirse default `signer-strict`'e düşülür ve startup'ta **WARN**
loglanır.

**`DSS_POLICY_PROFILE` + `ONLINE_VALIDATION_ENABLED=false` kombinasyonu**
risk yaratır: imzacı için OCSP/CRL FAIL ama online fetch kapalı →
her doğrulama `INDETERMINATE/NO_REVOCATION_DATA` döner. Servis startup'ta
bu kombinasyonu tespit edip uyarır. Test/CI ortamları için
`DSS_POLICY_PATH` ile permissive bir XML mount edin.

**Custom policy yazımı**: Built-in XML'ler `src/main/resources/policy/`
altında tam yorumlu. CA / ara / imzacı / counter signature / timestamp
katmanları için ayrı ayrı `RevocationDataAvailable`, `NotRevoked`,
`AcceptableRevocationDataFound` vb. constraint'leri `FAIL/WARN/IGNORE`
seviyesinde yapılandırabilirsiniz — DSS native policy şeması zaten
katman bazlı (bkz. `SigningCertificate` ve `CACertificate` node'ları).

#### Revocation Pipeline (OCSP/CRL)

DSS policy revocation **kuralını** belirler (`RevocationDataAvailable=FAIL` mı, `WARN` mı, vb.); bu bölümdeki env'ler revocation **altyapısını** (HTTP fetch, cache, retry) yapılandırır. İkisi ortogonal.

**Decorator sırası** (içten dışa):

```
OnlineOCSPSource / OnlineCRLSource   [DSS — gerçek HTTP fetch]
   │
   ▼ RetryingOCSPSource / RetryingCRLSource    [exponential backoff + jitter]
   │
   ▼ LoggingCachingOCSPSource / LoggingCachingCRLSource    [Caffeine cache + INFO log]
   │
   ▼ CertificateVerifier (DSS) — policy kararı uygular
```

Cache **dış** katman: cache hit retry'a girilmez (hızlı dönüş). Retry yalnız gerçek HTTP fetch'inde devreye girer. Strict-safe garantisi: tüm retry'lar tükenirse son exception `LoggingCachingOCSPSource`'ta WARN'lanır ve `null` döner → DSS `signer-strict` / `strict` policy'sindeki `RevocationDataAvailable=FAIL` kuralı tetiklenir → imza `INDETERMINATE/NO_REVOCATION_DATA`.

##### Cache Parametreleri

```bash
REVOCATION_CACHE_MAX_SIZE=10000         # Cache'te tutulacak maks entry sayısı
                                        # (OCSP ve CRL ayrı cache'ler — her biri 10K)
REVOCATION_CACHE_TTL=3600               # Default TTL (saniye). Token'in kendi
                                        # nextUpdate alanı varsa ondan küçük olan
                                        # seçilir; bu değer ÜST SINIR (iptali geç
                                        # görmeyelim diye). Set edilmezse legacy
                                        # CRL_CACHE_TTL fallback olur.
```

**Cache davranış invariant'ları**:

| Status | Cache'lenir mi? | Gerekçe |
|---|---|---|
| `GOOD` / `REVOKED` | ✅ Cache'lenir | Status sabit; tekrar fetch israf |
| `UNKNOWN` | ❌ Cache'lenmez | Responder geçici down olabilir, bir sonraki çağrıda yeniden denenir |
| `null` (responder boş döndü) | ❌ Cache'lenmez | Transient olabilir |
| Exception (network fail) | ❌ Cache'lenmez | Retry exhausted sonrası |

##### HTTP Timeout Parametreleri

```bash
REVOCATION_HTTP_CONNECT_TIMEOUT_MS=10000  # TCP connect timeout (ms)
REVOCATION_HTTP_SOCKET_TIMEOUT_MS=10000   # Socket read timeout (ms).
                                          # CRL'ler MB seviyesinde olabildiği için
                                          # düşük tutmuyoruz.
```

##### Retry Parametreleri (Anlık Flake Toleransı)

Strict policy revocation verisini ZORUNLU işaretler; tek bir KamuSM 503 / connection reset / TLS glitch geçerli bir e-Faturayı reddederdi. Retry mekanizması bunu çözer: anlık flake'te imza VALID kalır, gerçek kesintide hala FAIL.

**Algoritma** — exponential backoff + jitter:
```
delay(n)  = min(initialBackoff * multiplier^(n-1), maxBackoff)
sleepMs   = delay * (1 + uniform(-jitterRatio, +jitterRatio))
```

```bash
REVOCATION_RETRY_ENABLED=true             # Master switch.
                                          # false: maxAttempts=1 gibi davranır
                                          # (sadece ilk deneme, retry yok).
REVOCATION_RETRY_MAX_ATTEMPTS=3           # Toplam attempt: 1 = retry yok;
                                          # 3 = 1 ilk + 2 retry. KamuSM uçlarını
                                          # bombalamamak için >=5 default değildir.
REVOCATION_RETRY_INITIAL_BACKOFF_MS=200   # İlk retry öncesi temel bekleme.
                                          # KamuSM 503'leri tipik 200ms-1s içinde
                                          # toparlanır.
REVOCATION_RETRY_MAX_BACKOFF_MS=2000      # Exponential growth üst sınırı (clamp).
REVOCATION_RETRY_BACKOFF_MULTIPLIER=2.0   # Her retry'da çarpan. 1.0 = sabit
                                          # backoff; 2.0 = ikiye katla.
REVOCATION_RETRY_JITTER_RATIO=0.2         # ±jitterRatio rastgele varyasyon
                                          # (uniform). Thundering herd önleme
                                          # standart best-practice'i; 0.0
                                          # yaparsanız test determinizmi artar.
```

**Default'larla worst-case latency** (bir token için): `maxAttempts × httpTimeout + Σ backoffs` = `3 × 10s + (0.2s + 0.4s)` ≈ **30.6s** (KamuSM tamamen kapalıysa). Tipik flake yalnız +200-400ms ekler.

**Senaryo örnekleri**:

| Senaryo | `MAX_ATTEMPTS` | `INITIAL_BACKOFF_MS` | `MAX_BACKOFF_MS` | `JITTER_RATIO` | Worst-case latency |
|---|---|---|---|---|---|
| **Üretim default** (Mali Mühür) | 3 | 200 | 2000 | 0.2 | ~30.6s |
| **Agresif retry** (KamuSM stresli) | 5 | 300 | 5000 | 0.2 | ~75s |
| **Düşük-latency** (canlı API) | 2 | 100 | 1000 | 0.2 | ~20.1s |
| **Deterministic test/CI** | 3 | 200 | 2000 | **0.0** | ~30.6s (sabit) |
| **Retry kapalı** (`REVOCATION_RETRY_ENABLED=false`) | 1 (effective) | – | – | – | ~10s |

##### Response — Revocation Detayları

Her doğrulama response'unda zincir üzerindeki her sertifika için DSS DiagnosticData'sından çıkarılan zengin iptal detayı `signerCertificate.revocation` (ve `certificateChain[].revocation`) alt nesnesinde döner. Daha önce hem `revoked: false` hem `certificateNotRevoked: true` hardcoded'tu — REVOKED bir sertifika bile response'da "iptal değil" görünüyordu. Şimdi gerçek durum yansıtılır.

```jsonc
"signerCertificate": {
  "subjectDN": "CN=Test User, ...",
  "revoked": true,                          // geriye dönük; artık gerçeği yansıtır
  "revocationReason": "KEY_COMPROMISE",
  "revocationDate": "2024-09-15T08:30:00Z",
  "revocation": {                           // YENİ — zengin detay
    "source": "OCSP",                       // OCSP | CRL
    "status": "REVOKED",                    // GOOD | REVOKED | UNKNOWN
    "revocationDate": "2024-09-15T08:30:00Z",
    "revocationReason": "KEY_COMPROMISE",
    "producedAt": "2024-11-08T10:29:55Z",   // token üretim anı
    "thisUpdate": "2024-11-08T10:00:00Z",   // token freshness başlangıcı
    "nextUpdate": "2024-11-08T11:00:00Z",   // bir sonraki güncelleme (cache TTL ile uyumlu)
    "responderUrl": "http://ocsp.kamusm.gov.tr",
    "origin": "EXTERNAL"                    // EXTERNAL | CACHED | REVOCATION_VALUES | …
  }
}
```

**Alan anlamları**:

| Alan | Anlam |
|---|---|
| `source` | İptal token'ının türü: `OCSP` veya `CRL`. |
| `status` | Sertifikanın gerçek durumu: `GOOD` (iptal değil), `REVOKED` (iptalli), `UNKNOWN` (responder bilmiyor). |
| `revocationDate` | Sertifikanın iptal edildiği an (yalnız `REVOKED` ise dolar). |
| `revocationReason` | RFC 5280 iptal nedeni (örn. `KEY_COMPROMISE`, `CESSATION_OF_OPERATION`). |
| `producedAt` | OCSP response / CRL'in üretildiği zaman. |
| `thisUpdate` | Token'ın temsil ettiği bilginin geçerli olduğu başlangıç anı. |
| `nextUpdate` | Bir sonraki güncellemenin beklendiği an. Cache TTL bu değerle clamp'lenir. |
| `responderUrl` | İptal verisinin alındığı responder/dağıtım noktası — audit için kritik. |
| `origin` | Veri menşei: `EXTERNAL` (canlı sorgu), `CACHED` (Caffeine cache hit), `REVOCATION_VALUES` / `CMS_SIGNED_DATA` (LT-level imzada gömülü), `TIMESTAMP_VALIDATION_DATA`, vb. |

**`origin` neden önemli?** LT-level (PAdES/XAdES/CAdES BASELINE-LT) imzalarda revocation token'lar imzanın içinde gömülü gelir — bu durumda Mersel hiç OCSP/CRL ağ çağrısı yapmadan kararı verebilir. `origin: REVOCATION_VALUES` görüyorsanız "imzanın kendi içindeki güven kanıtı kullanıldı" demektir. `origin: EXTERNAL` ise canlı sorgu yapıldı (cache miss + retry zinciri çalıştı).

**`revocation` ne zaman `null` olur?**

- `ONLINE_VALIDATION_ENABLED=false` ve imza içinde gömülü revocation yoksa,
- DSS sertifika için hiçbir revocation token üretemediyse (örn. B-level imza, çevrimdışı, AIA çözülmedi),
- Responder ile hiç iletişim kurulamadı ve gömülü veri de yok.

Bu durumda alan tamamen JSON'a düşmez (`@JsonInclude(NON_NULL)`). Strict policy'de imzanın `valid` field'ı zaten DSS tarafından `INDETERMINATE/NO_REVOCATION_DATA` ile FAIL'lenmiş olur.

##### Zincir Genel Durumu — `chainRevocationStatus`

`signatures[].chainRevocationStatus`, **her doğrulama modunda** (SIMPLE + COMPREHENSIVE) yayınlanan kompakt bir özet enum'dur. Önceden SIMPLE mod tüketicisi yalnız `signerCertificate.revocation`'i görüyordu; ara CA seviyesindeki "leaf GOOD ama bir CA REVOKED" gibi durumlar yalnız COMPREHENSIVE modda `certificateChain[].revocation` alt nesneleriyle ifşa ediliyordu. Bu alan tek bir string ile tüketicinin SIMPLE'da da zincirin geneline dair doğru kararı vermesini sağlar.

```jsonc
"signatures": [{
  "valid": true,
  "signerCertificate": { "revoked": false, ... },
  "chainRevocationStatus": "ALL_GOOD"   // YENİ
}]
```

**Değer matrisi**:

| Değer | Anlam | Önerilen aksiyon |
|---|---|---|
| `ALL_GOOD` | Zincirdeki tüm sertifikalar (leaf + ara CA'lar) revocation kontrolünden `GOOD` geçti. | İşlemi gönül rahatlığıyla sürdür. |
| `LEAF_REVOKED` | İmzacı sertifika **REVOKED**. CA durumu ne olursa olsun en kritik sinyal. | Imza üzerinde iş yapma; sertifika sahibine bilgi ver. |
| `LEAF_GOOD_CA_REVOKED` | İmzacı `GOOD`, ama zincirdeki bir ara CA **REVOKED**. `signer-strict` profilinde imza yine `valid: true` döner (`NotRevoked=WARN`); `strict` profilinde imza geçersiz olur (`NotRevoked=FAIL`). | Politika tercihini sorgula; audit'e detay için COMPREHENSIVE çek. |
| `UNKNOWN` | Zincirde bir veya daha fazla sertifika için durum `UNKNOWN` (responder cevap verdi ama "bilmiyorum" dedi) ya da leaf için karar verilemiyor. | Operasyonel sorun olabilir; COMPREHENSIVE ile incele. |
| `NOT_CHECKED` | Hiçbir sertifika için revocation kontrolü yapılmadı/yapılamadı. Çevrimdışı mod, B-level imza, ya da responder hep down olabilir. | Çevrimdışı/strict kombinasyonu mu kontrol et. |

**Önemli — Bu alan doğrulama kararını <em>değiştirmez</em>.** DSS policy zincirin tamamını `SigningCertificate` + `CACertificate` blokları üzerinden kendi kuralları çerçevesinde kontrol eder; `signatures[].valid` bu policy'ye göre belirlenir. `chainRevocationStatus` yalnız UI/audit görünürlüğü için bir özet sinyaldir.

**Önceliklendirme**: Leaf `REVOKED` her zaman kazanır (`LEAF_REVOKED`). Leaf `UNKNOWN` ikinci önceliktedir (`UNKNOWN`) — CA `REVOKED` olsa bile imzacı için belirsizlik daha öncelikli sinyal. Sadece leaf `GOOD` ise CA seviyesi değerlendirilir.

**Politika profilleri ile etkileşim**: 

- `signer-strict` (default) + `LEAF_GOOD_CA_REVOKED` → `valid: true` (CA için sadece WARN). Operasyonel toleranslı.
- `strict` + `LEAF_GOOD_CA_REVOKED` → `valid: false`, sub-indication: `REVOKED_CA_NO_POE` / benzeri. eIDAS QES paralelinde sıkı davranır.

Detaylı zincir cert'lerine erişim için doğrulamayı `level=COMPREHENSIVE` ile çağırın — `certificateChain[i].revocation` alt nesneleri her cert için ayrı dolar.

#### TR-Legacy XAdES Toleransı

KamuSM / GİB ekosistemindeki bazı imzalama araçları (özellikle bazı
e-Belge entegratörlerinin eski sürümleri), XAdES `Reference` Type URI'sini
standart dışı yazıyor:

| | Type URI |
|---|---|
| ❌ Bazı TR araçlarında üretilen | `http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties` |
| ✅ ETSI TS 101 903 standardı | `http://uri.etsi.org/01903#SignedProperties` |

Eclipse DSS spec'e harfiyen uyduğu için bu Type URI'yi tanımıyor ve **kriptografik olarak sağlam** imzaları bile `INDETERMINATE / SIG_CONSTRAINTS_FAILURE` ile reddediyor (BBB sebebi: `BBB_SAV_ISQPMDOSPP`). TÜBİTAK İmzager ve KamuSM doğrulama servisleri ise bu imzaları kabul ediyor.

```bash
TR_LEGACY_XADES_TOLERANCE=true      # Default: true (TÜBİTAK İmzager paritesi)
# TR_LEGACY_XADES_TOLERANCE=false   # eIDAS-QES paralelinde davran (DSS strict)
```

Tolerans **AÇIK**ken aşağıdaki **6 koşulun TAMAMI** sağlanırsa imza
`TOTAL_PASSED`'e yükseltilir, açıklayıcı bir uyarı `validationWarnings`'e
eklenir:

1. Indication = `INDETERMINATE`
2. SubIndication = `SIG_CONSTRAINTS_FAILURE`
3. DSS DiagnosticData: `signatureIntact && signatureValid` (kriptografik bütünlük)
4. BBB SAV içinde **yalnızca** `BBB_SAV_ISQPMDOSPP` constraint'i FAIL
5. Orijinal XML'de `01903 + .xsd + #SignedProperties` paterniyle eşleşen Type URI bulundu
6. `verification.tr-legacy-xades-tolerance-enabled=true`

**Önemli — bu jenerik bir SIG_CONSTRAINTS bypass değildir**: zayıf algoritma
(`BBB_SAV_ISCDC`), bozuk SignedProperties digest, eksik SigningCertificate
gibi diğer SAV constraint'leri FAIL ediyorsa imza yine reddedilir.

Tolerans uygulandığında log'a tek satır kaydedilir:

```
TR legacy XAdES toleransı uygulandı (signatureId=…, code=MDSS-XADES-LEGACY-TR-TYPE-URI).
DSS INDETERMINATE/SIG_CONSTRAINTS_FAILURE iken imza kriptografik olarak sağlam
ve tek hata BBB_SAV_ISQPMDOSPP. Üretici Type URI: '…'
```

#### Applied Suppressions — Audit Trail

Mersel DSS Verifier'ın DSS kararını **override ettiği** her durum response içinde
yapılandırılmış olarak raporlanır. Bu, *"DSS aslında ne demişti, biz ne yaptık,
neden?"* sorusuna machine-readable cevap verir — audit, compliance ve operasyonel
görünürlük için kritik.

```jsonc
{
  "signatures": [
    {
      "valid": true,
      "indication": "TOTAL_PASSED",
      "appliedSuppressions": [
        {
          "code": "MDSS-XADES-LEGACY-TR-TYPE-URI",
          "title": "TR-legacy XAdES SignedProperties Type URI toleransı",
          "reason": "İmza, KamuSM/GİB ekosistemine özgü XAdES SignedProperties Type URI yazım hatası içeriyor. Kriptografik bütünlük doğrulandı; tolerans uygulandı. Üretici Type URI: \"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\".",
          "severity": "INFO",
          "originalIndication": "INDETERMINATE",
          "originalSubIndication": "SIG_CONSTRAINTS_FAILURE",
          "evidence": {
            "detectedTypeUri": "http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties",
            "expectedTypeUri": "http://uri.etsi.org/01903#SignedProperties",
            "dssBbbConstraint": "BBB_SAV_ISQPMDOSPP"
          },
          "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md"
        }
      ]
    }
  ]
}
```

**Code naming convention**: `MDSS-{LAYER}-{DESCRIPTIVE-SLUG}`

- `MDSS` — Mersel DSS prefix'i.
- `{LAYER}` — `XADES` / `CADES` / `PADES` / `CHAIN` / `CRYPTO` / `TIMESTAMP` / `REVOCATION`.
- `{DESCRIPTIVE-SLUG}` — UPPER-KEBAB-CASE özellik adı.

**Kararlılık (stability)**: bir kez yayınlanan kod değiştirilmez. Davranış
değişiyorsa yeni kod eklenir, eskisi `@Deprecated` olur.

**Detaylı dokümantasyon**: Her bir kodun ne yaptığını, hangi koşullarda
tetiklendiğini, severity gerekçesini ve nasıl kapatılabileceğini
[`docs/suppressions/`](docs/suppressions/) klasörü altındaki MD dosyaları
anlatır. Kayıtlı kodların tam listesi:
[`SuppressionCode`](src/main/java/io/mersel/dss/verify/api/models/enums/SuppressionCode.java)
enum'u.

**Severity seviyeleri**:
- `INFO` — tasarımdan sapma ama güvenlik etkisi yok (örn. üretici Type URI yazım hatası, kriptografi sağlam).
- `WARN` — operatörün dikkat etmesi önerilir.
- `CRITICAL` — operatör eylem almalı.

**Operasyonel kullanım**: `appliedSuppressions[].code` doğrudan Prometheus metric
label, log filter veya support ticket referansı olarak kullanılabilir
(`mersel_dss_suppression_applied_total{code="MDSS-XADES-LEGACY-TR-TYPE-URI"}`).
`appliedSuppressions` boş veya `null` ise: DSS'in kararı aynen kullanıldı, hiçbir
Mersel-spesifik tolerans uygulanmadı.

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

### Revocation Cache Metric Ailesi

`LoggingCachingOCSPSource` ve `LoggingCachingCRLSource` Caffeine cache instance'ları Micrometer aracılığıyla otomatik publish edilir. Cache başına metric isimleri (Micrometer naming) ve `cache` tag'leri:

| Metric | OCSP tag | CRL tag | Anlamı |
|---|---|---|---|
| `cache_size` | `cache="mersel.revocation.ocsp"` | `cache="mersel.revocation.crl"` | Anlık cache entry sayısı |
| `cache_gets_total{result="hit"}` | aynı | aynı | Cache hit sayısı (HTTP fetch atlandı) |
| `cache_gets_total{result="miss"}` | aynı | aynı | Cache miss sayısı (gerçek HTTP fetch tetiklendi) |
| `cache_puts_total` | aynı | aynı | Cache'e konan response sayısı (GOOD/REVOKED; UNKNOWN ve null bilinçli cache'lenmez) |
| `cache_evictions_total` | aynı | aynı | TTL veya size limit kaynaklı evict sayısı |

**Operasyonel sorgu örnekleri** (PromQL):

```promql
# OCSP hit-rate (cache verimliliği)
rate(cache_gets_total{cache="mersel.revocation.ocsp",result="hit"}[5m])
  / rate(cache_gets_total{cache="mersel.revocation.ocsp"}[5m])

# KamuSM endpoint'lerine giden gerçek HTTP fetch yükü
rate(cache_puts_total{cache=~"mersel.revocation.(ocsp|crl)"}[1h])

# Cache büyüklüğü trend (memory baskısı için)
cache_size{cache=~"mersel.revocation.(ocsp|crl)"}
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

