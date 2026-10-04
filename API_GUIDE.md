# Mersel DSS Verify API - Kapsamlı Kullanım Kılavuzu

## Genel Bakış

Bu API, Türkiye e-imza standartlarına uygun dijital imza ve zaman damgası doğrulama hizmeti sunar. DSS (Digital Signature Services) 6.3 kütüphanesi kullanılarak geliştirilmiştir.

## Desteklenen İmza Formatları

### XAdES (XML Advanced Electronic Signatures)
- **XAdES-BES** (Basic Electronic Signature)
- **XAdES-EPES** (Explicit Policy-based Electronic Signature)
- **XAdES-T** (Timestamp)
- **XAdES-C** (Complete)
- **XAdES-X** (eXtended)
- **XAdES-XL** (eXtended Long-term)
- **XAdES-A** (Archival)

### PAdES (PDF Advanced Electronic Signatures)
- **PAdES-B-B** (Basic)
- **PAdES-B-T** (Basic with Timestamp)
- **PAdES-B-LT** (Basic Long-Term)
- **PAdES-B-LTA** (Basic Long-Term with Archive timestamp)

### CAdES (CMS Advanced Electronic Signatures)
- **CAdES-BES** (Basic Electronic Signature)
- **CAdES-EPES** (Explicit Policy-based Electronic Signature)
- **CAdES-T** (Timestamp)
- **CAdES-C** (Complete)
- **CAdES-X** (eXtended)
- **CAdES-XL** (eXtended Long-term)
- **CAdES-A** (Archival)

## API Endpoints

### 1. Birleşik İmza Doğrulama
**Endpoint:** `POST /api/v1/verify/signature`

Tüm imza formatlarını otomatik olarak algılayarak doğrular.

**Request:**
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@signed_document.xml" \
  -F "originalDocument=@original.xml" \
  -F "level=COMPREHENSIVE"
```

**Parameters:**
- `signedDocument` (required): İmzalı doküman dosyası
- `originalDocument` (optional): Orijinal doküman (detached signature için)
- `level` (optional): `SIMPLE` veya `COMPREHENSIVE` (default: SIMPLE)

**Response:**
```json
{
  "valid": true,
  "status": "VALID",
  "signatureType": "XADES",
  "verificationTime": "2025-11-10T10:30:00Z",
  "signatureCount": 1,
  "signatures": [
    {
      "signatureId": "id-1234567890",
      "valid": true,
      "signatureFormat": "XAdES-BES",
      "signatureLevel": "XAdES_BASELINE_B",
      "signingTime": "2025-11-09T15:20:00Z",
      "indication": "TOTAL_PASSED",
      "signerCertificate": {
        "commonName": "John Doe",
        "serialNumber": "123456789",
        "subject": "CN=John Doe, O=Example Corp",
        "issuerDN": "CN=Example CA, O=Example Corp",
        "notBefore": "2024-01-01T00:00:00Z",
        "notAfter": "2026-01-01T00:00:00Z",
        "valid": true,
        "revoked": false
      },
      "timestampInfo": {
        "valid": true,
        "timestampTime": "2025-11-09T15:20:05Z",
        "timestampType": "SIGNATURE_TIMESTAMP",
        "tsaName": "TSA Service"
      },
      "validationErrors": [],
      "validationWarnings": []
    }
  ]
}
```

### 2. Zaman Damgası Doğrulama
**Endpoint:** `POST /api/v1/verify/timestamp`

RFC 3161 uyumlu zaman damgalarını doğrular.

**Request:**
```bash
curl -X POST "http://localhost:8086/api/v1/verify/timestamp" \
  -F "timestampFile=@timestamp.tsr" \
  -F "originalData=@document.pdf" \
  -F "validateCertificate=true"
```

**Parameters:**
- `timestampFile` (required): Zaman damgası dosyası (.tsr)
- `originalData` (optional): Orijinal veri (message imprint doğrulaması için)
- `validateCertificate` (optional): TSA sertifika doğrulaması (default: true)

**Response:**
```json
{
  "valid": true,
  "status": "VALID",
  "timestampTime": "2025-11-09T15:20:05Z",
  "tsaName": "Türkiye Zaman Damgası Merkezi",
  "digestAlgorithm": "SHA-256",
  "messageImprint": "Zm9vYmFy...",
  "tsaCertificate": {
    "commonName": "TSA Signing Certificate",
    "serialNumber": "987654321",
    "notBefore": "2024-01-01T00:00:00Z",
    "notAfter": "2026-01-01T00:00:00Z",
    "valid": true
  },
  "errors": [],
  "warnings": []
}
```

### 3. Legacy Endpoints (Geriye Uyumluluk)

#### XAdES Doğrulama
```bash
POST /api/v1/verify/xades
```

#### PAdES Doğrulama
```bash
POST /api/v1/verify/pades
```

#### CAdES Doğrulama
```bash
POST /api/v1/verify/cades
```

### 4. Etkin Doğrulama Politikası

İmza doğrulamasında kullanılan DSS politikası çalışma anında okunup
değiştirilebilir. Etkinleştirme **global** (sonraki tüm imza doğrulamaları) ve
**bellek içidir** (yeniden başlatma `dss.policy.profile` / `dss.policy.path`
yapılandırmasına döner). POST bir feature flag arkasındadır: yalnız
`POLICY_ACTIVATION_ENABLED=true` (`dss.policy.activation-enabled`, varsayılan
`false`) iken açıktır; evaluation profili veya `REQUEST_TRUST_ENABLED` açmaz.

> **UYARI:** Prod ortamında kesinlikle kullanmayın. Politika etkinleştirme
> yalnız TÜBİTAK Uyum Değerlendirme sürecindeki deployment'lar için
> geliştirilmiştir.

```bash
GET  /api/v1/policy/active
GET  /api/v1/policy/active/xml   # etkin politikanın XML'i (okuma her zaman açık)
POST /api/v1/policy/active   # multipart/form-data
```

| Alan | Açıklama |
|------|----------|
| `mode` | `BUILT_IN`, `CUSTOM_XML` veya `CONFIGURED` (yapılandırmaya dönüş) |
| `profile` | `signer-strict` \| `strict` — yalnız ve zorunlu olarak `BUILT_IN` ile |
| `policyXml` | Politika XML dosyası — yalnız ve zorunlu olarak `CUSTOM_XML` ile (≤ 1 MiB, `POLICY_MAX_BYTES`) |
| `policyName` | `CUSTOM_XML` için görünen ad (opsiyonel, ≤ 120 karakter; varsayılan "Özel politika") |
| `expectedPolicyId` | Zorunlu; GET'ten alınan güncel `policyId` |

```bash
ID=$(curl -s http://localhost:8086/api/v1/policy/active | jq -r .policyId)
curl -X POST http://localhost:8086/api/v1/policy/active \
  -F "mode=CUSTOM_XML" -F "policyXml=@kurum-politikasi.xml" \
  -F "policyName=Kurum politikası" -F "expectedPolicyId=$ID"
```

Yanıt (`ActivePolicy`):
```json
{
  "policyId": "30a90a62-580e-4cfd-9e7e-82349b5b9056:2",
  "profile": "custom",
  "source": "CUSTOM_XML",
  "origin": "API",
  "name": "Kurum politikası",
  "sha256": "8c7bf4912097a7e13fab01906e2b719cdd43a4c32f4301ae0f6390066e859309",
  "activatedAt": "2026-10-03T21:39:14.827Z",
  "fallbackApplied": false,
  "activationEnabled": true
}
```

Özel XML; DOCTYPE/ENTITY içermemeli (XXE-güvenli ayrıştırma), iyi
biçimlendirilmiş olmalı ve DSS `ConstraintsParameters` XSD doğrulamasıyla
yüklenebilmelidir. Hatalar: `400 INVALID_POLICY`, `403 POLICY_ACTIVATION_DISABLED`,
`409 CONFLICT` (eski `expectedPolicyId`), `503 POLICY_UNAVAILABLE` (yapılandırmadaki
`dss.policy.path` yüklenemiyor; gövdedeki `policyId` ile `BUILT_IN` / `CUSTOM_XML` /
`CONFIGURED` etkinleştirilerek kurtarılır). Ayrıntı: [docs/policy-activation.md](docs/policy-activation.md).

#### Etkin politikanın XML'i

`GET /api/v1/policy/active/xml`, sonraki imza doğrulamalarının DSS'e verdiği XML'in
byte'larını yeniden kodlamadan döner (yerleşik profil dosyası, arayüzden yüklenen
özel XML veya `dss.policy.path`). Gövdenin SHA-256'sı `GET /api/v1/policy/active`
yanıtındaki `sha256` ile aynıdır. Okuma `dss.policy.activation-enabled`'dan
bağımsızdır; yanıtta sunucu yolu yer almaz.

| Başlık | Değer |
|--------|-------|
| `Content-Type` | `application/xml;charset=UTF-8` (charset belgenin kendi kodlamasıdır: BOM, yoksa XML bildirimindeki `encoding`, yoksa UTF-8) |
| `X-Policy-Id` | Gövdenin ait olduğu `policyId` |
| `X-Policy-Sha256` | Gövdenin SHA-256'sı (küçük harf hex) |
| `ETag` | `"<sha256>"` |
| `Cache-Control` | `no-store` |
| `Content-Disposition` | `inline; filename="…"` — yerleşik: `kamusm-signer-strict-constraint.xml` / `kamusm-strict-constraint.xml`; özel XML: ASCII'ye indirgenmiş `policyName` (örn. `Mersel-KamuSM-Signer-Strict-Policy.xml`), ad yoksa ve `dss.policy.path` için `active-policy.xml` |

Gövde ve başlıklar aynı değişmez snapshot'tan gelir; eşzamanlı bir etkinleştirme
kimlik ile içeriği karıştırmaz. Yapılandırmadaki `dss.policy.path` yüklenemiyorsa
`GET /api/v1/policy/active` ile aynı `503 POLICY_UNAVAILABLE` JSON gövdesi döner
(`Accept: application/xml` gönderilse de). CORS `X-Policy-Id`, `X-Policy-Sha256`,
`ETag` ve `Content-Disposition` başlıklarını tarayıcıya açar.

Düzenleme: XML'i okuyun, `X-Policy-Id`'yi saklayın, düzenlenen dosyayı
`mode=CUSTOM_XML` ve `expectedPolicyId=<X-Policy-Id>` ile POST edin. Arada başka bir
politika etkinleştirildiyse kayıt `409 CONFLICT` ile reddedilir (üzerine yazılmaz).

```bash
curl -s -D basliklar.txt -o etkin-politika.xml http://localhost:8086/api/v1/policy/active/xml
shasum -a 256 etkin-politika.xml   # X-Policy-Sha256 ile aynı
```

`GET /api/v1/info` → `verificationPolicy` (`profile`, `source`, `fallbackApplied`)
etkin politikayı gösterir; `policyCapabilities` = `{activationSupported, activationEnabled, maxBytes, contentAvailable}`
(`contentAvailable: true` → `GET /api/v1/policy/active/xml` mevcut).

## Doğrulama Seviyeleri

### SIMPLE (Basit)
- İmza geçerliliği
- Temel sertifika bilgileri
- İmza formatı ve seviyesi
- Timestamp bilgisi (varsa)
- Hata ve uyarılar

### COMPREHENSIVE (Kapsamlı)
SIMPLE seviyesindeki tüm bilgilere ek olarak:
- Tam sertifika zinciri
- Detaylı validation bilgileri
- OCSP/CRL revocation durumu
- Cryptographic verification detayları
- Policy identifier (XAdES-EPES için)
- Tüm timestamp bilgileri

## Güvenilir Root Sertifika Yapılandırması

API, üç farklı trusted root sertifika resolver destekler:

### 1. KamuSM Online Resolver (Varsayılan)
```properties
# application.properties
trusted.root.resolver.type=kamusm-online
kamusm.root.url=http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml
```

### 2. KamuSM Offline Resolver
```properties
trusted.root.resolver.type=kamusm-offline
kamusm.root.offline.path=file:/path/to/SertifikaDeposu.xml
```

### 3. Certificate Folder Resolver
```properties
trusted.root.resolver.type=certificate-folder
trusted.root.cert.folder.path=/path/to/certificates
```

Bu klasördeki tüm `.crt`, `.cer`, `.pem` dosyaları güvenilir root sertifika olarak yüklenir.

### Otomatik Yenileme
```properties
# Her gün saat 03:15'te yenile
trusted.root.refresh-cron=0 15 3 * * *
```

## OCSP ve CRL Doğrulaması

API, sertifika revocation kontrolü için OCSP ve CRL destekler:

```properties
# Online validation
verification.online-validation-enabled=true
```

Online validation aktif olduğunda:
- OCSP responder'lardan sertifika durumu sorgulanır
- CRL (Certificate Revocation List) kontrolleri yapılır
- AIA (Authority Information Access) üzerinden sertifika zinciri tamamlanır

## İmza Formatı Özellikleri

### XAdES Seviyelerinin Anlamı

| Seviye | Açıklama | Kullanım |
|--------|----------|----------|
| XAdES-BES | Temel elektronik imza | Basit doğrulama |
| XAdES-EPES | Policy bazlı imza | Belirli politikalar gerektiren durumlar |
| XAdES-T | Zaman damgalı imza | Uzun vadeli koruma başlangıcı |
| XAdES-C | Tam doğrulama bilgisi | CRL/OCSP bilgileri dahil |
| XAdES-X | Genişletilmiş koruma | Ek timestamp'ler |
| XAdES-XL | Uzun vadeli | Sertifika ve revocation bilgileri embedded |
| XAdES-A | Arşiv | En uzun vadeli koruma, periyodik re-timestamping |

### PAdES Seviyelerinin Anlamı

| Seviye | Açıklama | ETSI Standardı |
|--------|----------|----------------|
| PAdES-B-B | Temel PDF imzası | ETSI EN 319 142-1 |
| PAdES-B-T | Timestamp eklenmiş | ETSI EN 319 142-1 |
| PAdES-B-LT | Uzun vadeli | Revocation bilgileri dahil |
| PAdES-B-LTA | Arşiv | Document timestamp ile korumalı |

## Response Model Açıklaması

### VerificationResult
```typescript
{
  valid: boolean,              // Genel doğrulama sonucu
  status: string,              // "VALID", "INVALID", "NO_SIGNATURE_FOUND"
  signatureType: string,       // "XADES", "PADES", "CADES"
  verificationTime: DateTime,  // Doğrulama zamanı
  signatureCount: number,      // İmza sayısı
  signatures: SignatureInfo[], // İmza detayları
  errors: string[],           // Genel hatalar
  warnings: string[],         // Genel uyarılar
  policyContext: {            // Bu doğrulamada kullanılan politika (istek başı snapshot)
    policyId: string, profile: string, source: string, name: string, sha256: string
  }
}
```

### SignatureInfo (Comprehensive Mode)
```typescript
{
  signatureId: string,
  valid: boolean,
  signatureFormat: string,         // Örn: "XAdES-BES"
  signatureLevel: string,          // Örn: "XAdES_BASELINE_B"
  signingTime: DateTime,
  indication: string,              // "TOTAL_PASSED", "INDETERMINATE", "FAILED"
  subIndication: string,           // Detaylı durum
  signerCertificate: CertificateInfo,
  certificateChain: CertificateInfo[], // Tam sertifika zinciri
  timestampInfo: TimestampInfo,
  timestampCount: number,
  policyIdentifier: string,        // XAdES-EPES için
  validationDetails: {
    signatureIntact: boolean,
    certificateChainValid: boolean,
    certificateNotExpired: boolean,
    certificateNotRevoked: boolean,
    trustAnchorReached: boolean,
    timestampValid: boolean,
    cryptographicVerificationSuccessful: boolean,
    revocationCheckPerformed: boolean
  },
  validationErrors: string[],
  validationWarnings: string[]
}
```

## Hata Yönetimi

### HTTP Status Codes
- `200 OK`: Doğrulama tamamlandı (sonuç valid veya invalid olabilir)
- `400 Bad Request`: Geçersiz istek (eksik parametre, hatalı dosya vb.)
- `403 Forbidden` / `409 Conflict` / `503 Service Unavailable`: Politika etkinleştirme (bkz. "Etkin Doğrulama Politikası")
- `500 Internal Server Error`: Sunucu hatası

### Örnek Hata Yanıtı
```json
{
  "timestamp": "2025-11-10T10:30:00Z",
  "status": 400,
  "error": "Bad Request",
  "message": "İmza doğrulama hatası: Geçersiz doküman formatı",
  "path": "/api/v1/verify/signature"
}
```

## Örnek Kullanım Senaryoları

### 1. XAdES-BES İmzası Doğrulama (Enveloped)
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@signed.xml" \
  -F "level=SIMPLE"
```

### 2. XAdES-T İmzası Doğrulama (Detached)
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@signature.xml" \
  -F "originalDocument=@data.xml" \
  -F "level=COMPREHENSIVE"
```

### 3. PAdES PDF İmzası Doğrulama
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@signed.pdf" \
  -F "level=COMPREHENSIVE"
```

### 4. Zaman Damgası + Orijinal Veri Doğrulama
```bash
curl -X POST "http://localhost:8086/api/v1/verify/timestamp" \
  -F "timestampFile=@timestamp.tsr" \
  -F "originalData=@document.pdf" \
  -F "validateCertificate=true"
```

### 5. XAdES-A Arşiv İmzası (Comprehensive)
```bash
curl -X POST "http://localhost:8086/api/v1/verify/signature" \
  -F "signedDocument=@archive_signed.xml" \
  -F "level=COMPREHENSIVE"
```

## Performans ve Optimizasyon

### Cache Yapılandırması
```properties
# Sertifika cache süresi (saniye)
CERT_CACHE_TTL=3600

# CRL cache süresi (saniye)
CRL_CACHE_TTL=3600
```

### Timeout Ayarları
API, OCSP ve CRL sorguları için 10 saniye timeout kullanır. Bu değerler kod içinde yapılandırılabilir.

## Monitoring ve Loglama

### Prometheus Metrics
API, Prometheus metrics export eder:
```
http://localhost:8086/actuator/prometheus
```

### Health Check
```
http://localhost:8086/actuator/health
```

### Log Seviyeleri
```properties
# application.properties
logging.level.io.mersel.dss.verify.api=INFO
```

## Güvenlik Notları

1. **CORS**: Production'da spesifik domain'ler kullanın
2. **File Upload**: Maksimum dosya boyutu 200MB
3. **SSL/TLS**: Production'da HTTPS kullanın
4. **Rate Limiting**: Gerekirse uygulanmalı
5. **Authentication**: Gerekirse eklenebilir

## İletişim ve Destek

- API Dokümantasyonu: http://localhost:8086/api-docs
- Scalar UI: http://localhost:8086/scalar/api-docs

## Lisans

Bu proje, ilgili lisans koşulları altında lisanslanmıştır.

