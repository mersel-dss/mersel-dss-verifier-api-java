# cURL Örnekleri

Bu dizin, Mersel DSS Verify API'nin cURL ile kullanım örneklerini içerir.

## Gereksinimler

- `curl`: HTTP istekleri için
- `jq`: JSON çıktısını formatlamak için (opsiyonel)

```bash
# macOS
brew install curl jq

# Ubuntu/Debian
apt-get install curl jq
```

## Kullanım

Tüm script'ler çalıştırılabilir olmalıdır:

```bash
chmod +x *.sh
```

### PAdES (PDF) Doğrulama

**Basit Doğrulama:**
```bash
./verify-pades-simple.sh signed-document.pdf
# Endpoint: POST /api/v1/verify/pades?level=SIMPLE
```

**Kapsamlı Doğrulama:**
```bash
./verify-pades-comprehensive.sh signed-document.pdf
# Endpoint: POST /api/v1/verify/pades?level=COMPREHENSIVE
```

### XAdES (XML) Doğrulama

**Basit Doğrulama (Enveloped/Enveloping):**
```bash
./verify-xades-simple.sh signed-document.xml
# Endpoint: POST /api/v1/verify/xades?level=SIMPLE
# DSS otomatik olarak imza tipini tespit eder
```

**Detached İmza Doğrulama:**
```bash
./verify-xades-detached.sh signature.xml original-document.xml COMPREHENSIVE
# Endpoint: POST /api/v1/verify/xades?level=COMPREHENSIVE
# Detached imza için originalDocument parametresi gereklidir
```

### Zaman Damgası Doğrulama

**Sadece Timestamp:**
```bash
./verify-timestamp.sh timestamp.tst
```

**Message Imprint ile:**
```bash
./verify-timestamp.sh timestamp.tst original-data.pdf
```

## API URL Değiştirme

Farklı bir API URL'i kullanmak için `API_URL` environment variable'ını ayarlayın:

```bash
export API_URL=https://verify-api.example.com
./verify-pades-simple.sh signed-document.pdf
```

## Çıktı Formatı

Tüm örnekler `jq` kullanarak JSON çıktısını formatlar. `jq` yoksa, pipe'ı kaldırabilirsiniz:

```bash
curl -X POST "$API_URL/api/v1/verify/pades/simple" \
  -F "signedDocument=@$SIGNED_PDF"
```

