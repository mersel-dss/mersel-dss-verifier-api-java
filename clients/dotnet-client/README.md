# MERSEL.Services.DssVerifier.Client

[mersel-dss-verifier-api-java](https://github.com/mersel-dss/mersel-dss-verifier-api-java) mikroservisini HTTP üzerinden çağıran **istemci SDK'sı**.

`netstandard2.0` ve `net8.0` hedeflerini destekler — yani **.NET Framework 4.6.1+**, **.NET Core 2.x+**, **.NET 5 / 6 / 7 / 8 / 9**, **Mono**, **Xamarin** ve **Unity 2018.1+** akışlarında çalışır. Sahadaki on-prem Windows servisleri (klasik .NET Framework) ile modern bulut backend'leri (net8.0 LTS) tek paketten beslenir. Tek satır DI kaydıyla XAdES (BES, EPES, T, C, X, XL, A), PAdES (B-B, B-T, B-LT, B-LTA), CAdES (BES → A) imza doğrulama; RFC 3161 zaman damgası doğrulama; sertifika zinciri ve OCSP/CRL revocation kontrollerini uygulamanıza entegre edin. Servis stateless'tir; istemcide herhangi bir özel state tutulmaz, paket güvenle çoklu instance ile kullanılabilir.

## Kurulum

```bash
dotnet add package MERSEL.Services.DssVerifier.Client
```

## DI Kaydı

```csharp
// Seçenek 1: appsettings.json'dan oku (varsayılan section: "Services:DssVerifier")
builder.Services.AddDssVerifierClient(builder.Configuration);

// Seçenek 2: Kod ile yapılandır
builder.Services.AddDssVerifierClient(o =>
{
    o.BaseUrl = "http://dss-verifier:8086";
    o.Timeout = TimeSpan.FromMinutes(5);
});

// Seçenek 3: Sadece URL belirt
builder.Services.AddDssVerifierClient("http://dss-verifier:8086");
```

**appsettings.json:**

```json
{
  "Services": {
    "DssVerifier": {
      "BaseUrl": "http://dss-verifier:8086",
      "Timeout": "00:02:00"
    }
  }
}
```

> **Not — Authentication:** Sunucu kendisi authentication uygulamaz (internal kullanım / API Gateway arkasında çalıştırın). API Gateway, reverse proxy veya başka bir auth katmanı arkasında çalıştırıyorsanız ekstra header'ları (örn. `X-API-Key`, `Authorization`) standart `IHttpClientFactory` zincirinden ekleyin:
>
> ```csharp
> builder.Services.AddHttpClient(DssVerifierClientOptions.HttpClientName)
>     .ConfigureHttpClient(http =>
>     {
>         http.DefaultRequestHeaders.Add("X-API-Key", "gateway-secret");
>     });
> // veya: .AddHttpMessageHandler<MyAuthDelegatingHandler>();
> ```

DI kaydı sonrası tüketicide:

- `IDssVerifierClient` — tüm domain'lere erişen birleşik cephe
- `ISignatureVerifier` — XAdES / PAdES / CAdES imza doğrulama
- `ITimestampVerifier` — standalone RFC 3161 zaman damgası doğrulama
- `IHealthClient` — sağlık kontrolü ve servis meta-bilgisi

inject edilebilir.

## Kullanım

### İmza Doğrulama (XAdES / PAdES / CAdES — tek API)

Sunucu içeriği inceleyerek format kararını kendisi verir; istemcinin XML / PDF / CMS ayrımı yapmasına gerek yoktur.

```csharp
public class EFaturaDogrulama(IDssVerifierClient verifier)
{
    public async Task<bool> EFaturaImzasiGecerliMi(byte[] imzaliUblXml, CancellationToken ct = default)
    {
        var sonuc = await verifier.Signatures.VerifyAsync(imzaliUblXml, ct: ct);

        // sonuc.Valid       → bütünsel verdict (tüm imzaların AND'i)
        // sonuc.Signatures  → her bir imza için detay
        // sonuc.Status      → "VALID" / "INVALID" / "INDETERMINATE"
        return sonuc.Valid;
    }
}
```

### COMPREHENSIVE Mod — Tam Sertifika Zinciri + Per-CA OCSP/CRL

Audit / compliance akışları için tam detayı çekin:

```csharp
var sonuc = await verifier.Signatures.VerifyAsync(new VerifySignatureRequest
{
    SignedDocument = imzaliPdf,
    Level          = VerificationLevel.COMPREHENSIVE
});

foreach (var imza in sonuc.Signatures)
{
    Console.WriteLine($"Imzacı: {imza.SignerCertificate?.CommonName}");
    Console.WriteLine($"Seviye: {imza.SignatureLevel}");
    Console.WriteLine($"Qualification: {imza.QualificationDetails?.QualificationLevel}");
    Console.WriteLine($"Zincir revocation: {imza.ChainRevocationStatus}");

    foreach (var cert in imza.CertificateChain ?? new())
    {
        Console.WriteLine($"  CN={cert.CommonName}  revocation={cert.Revocation?.Status}");
    }
}
```

### Detached İmza (CAdES detached / external XAdES)

```csharp
var sonuc = await verifier.Signatures.VerifyDetachedAsync(
    signedDocument:   detachedP7s,     // sadece imza
    originalDocument: orijinalDosya    // hash karşılaştırması için
);
```

### Türkiye'ye Özgü Tanı Kodları (Suppression / Rejection)

Sunucu, DSS upstream'ın jenerik kararlarını Türkiye e-imza ekosistemine özgü kataloglu kodlarla zenginleştirir. Bu kodlar API kontratı olarak kararlıdır:

```csharp
var sonuc = await verifier.Signatures.VerifyAsync(imzaliUblXml);

foreach (var imza in sonuc.Signatures)
{
    // 1) Suppression — DSS INVALID dedi, biz VALID elevate ettik (override).
    //    İmza geçerli sayıldı, ama hangi tolerans uygulandı audit edilebilir.
    foreach (var s in imza.AppliedSuppressions ?? new())
    {
        Console.WriteLine($"[SUPPRESSION] {s.Code} — {s.Title}");
        Console.WriteLine($"  Sebep: {s.Reason}");
        Console.WriteLine($"  Docs : {s.DocsUrl}");
    }

    // 2) Rejection — DSS INVALID dedi, biz de INVALID diyoruz, AMA neden
    //    invalid olduğunu Türkiye-spesifik bir tanı koduyla açıklıyoruz.
    foreach (var r in imza.AppliedRejections ?? new())
    {
        Console.WriteLine($"[REJECTION] {r.Code} — {r.Title}");
        Console.WriteLine($"  Sebep: {r.Reason}");
        Console.WriteLine($"  Docs : {r.DocsUrl}");
    }
}
```

> **Kararlı kod listesi**: `MERSEL.Services.DssVerifier.Client.Models.Enums.SuppressionCode` ve `RejectionCode` enum'ları tüm yayınlanmış kodları içerir; yeni sürümlerde değer eklenir, mevcut kod renaming yapılmaz. Wire format kanonik kod stringi `MDSS-…` formatındadır (örn. `MDSS-XADES-LEGACY-TR-TYPE-URI`); enum ile dönüşüm için `SuppressionCodeExtensions.GetCode()` / `TryParse()` yardımcılarını kullanın.

### RFC 3161 Zaman Damgası Doğrulama (Standalone)

İmzanın içine gömülü zaman damgaları otomatik olarak `VerifyAsync` akışında doğrulanır ve `SignatureInfo.TimestampInfo` alanında raporlanır. Tek başına gelen `.tsr` dosyaları için:

```csharp
// 1) Yalnız token doğrula (TSA sertifika zinciri kontrol edilir).
var ts = await verifier.Timestamps.VerifyAsync(tsrBytes);

// 2) Orijinal veri ile message imprint karşılaştırması da yap.
var tsWithData = await verifier.Timestamps.VerifyAsync(
    timestampToken: tsrBytes,
    originalData:   orijinalBelge);

Console.WriteLine($"Geçerli mi: {tsWithData.Valid}");
Console.WriteLine($"TSA       : {tsWithData.TsaName}");
Console.WriteLine($"Zaman     : {tsWithData.TimestampTime:O}");
Console.WriteLine($"Algoritma : {tsWithData.DigestAlgorithm}");
```

### Sağlık Kontrolü

```csharp
var health = await verifier.Health.GetHealthAsync();
// health.Status      → "UP" / "DOWN"
// health.Application → "mersel-dss-verify-api"
// health.Version     → "0.5.1"

var info = await verifier.Health.GetInfoAsync();
// info.Features → ["XAdES Verification", "OCSP/CRL Revocation Check", ...]
```

## Hata Yönetimi

> **Önemli ayrım**: İmzanın geçersiz çıkması bir HTTP hatası **değildir**. Sunucu doğrulamayı başarıyla *icra* ettiği sürece HTTP 200 ile `VerificationResult.Valid = false` döner; karar için bu alanı inceleyin.

Yalnız taşıma katmanı / sunucu hataları (4xx/5xx) için `DssVerifierApiException` fırlatılır. Sunucunun yapılandırılmış hata gövdesi (`error` + `message`) varsa `ApiError` üzerinden erişilir:

```csharp
try
{
    var sonuc = await verifier.Signatures.VerifyAsync(imzaliBelge);
    if (!sonuc.Valid)
    {
        // İmza fiilen geçersiz — exception değil.
        foreach (var hata in sonuc.Errors) Console.Error.WriteLine($"  - {hata}");
        foreach (var s in sonuc.Signatures)
            foreach (var r in s.AppliedRejections ?? new())
                Console.Error.WriteLine($"  - [{r.Code}] {r.Reason}");
    }
}
catch (DssVerifierApiException ex)
{
    // Sunucu hatası (örn. parse failure, 500).
    Console.Error.WriteLine($"[{(int)ex.StatusCode}] {ex.ApiError?.Error}: {ex.ApiError?.Message}");
}
```

## Polly / Retry / Logging

Paket altta `Microsoft.Extensions.Http` ve `IHttpClientFactory` üzerinde çalışır; standart retry/policy/logging genişletmeleri için kayıt sonrası `IHttpClientBuilder`'a kolayca eklenir:

```csharp
builder.Services.AddDssVerifierClient(builder.Configuration);

builder.Services.AddHttpClient(DssVerifierClientOptions.HttpClientName)
    .AddPolicyHandler(Policy<HttpResponseMessage>
        .Handle<HttpRequestException>()
        .OrResult(r => (int)r.StatusCode >= 500)
        .WaitAndRetryAsync(3, attempt => TimeSpan.FromSeconds(Math.Pow(2, attempt))));
```

## SIMPLE vs COMPREHENSIVE — Hangisini Kullanmalıyım?

| Senaryo                                           | Önerilen Mod      | Neden?                                                                                |
| ------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------- |
| ApplicationResponse / yüksek hacimli akış         | `SIMPLE`          | Tek istek başına milisaniyeleri kurtarır; verdict + zincir özet sinyali yeterli.       |
| Mali müşavir / denetim arayüzü                    | `COMPREHENSIVE`   | Her CA için OCSP/CRL detayı + qualification (QES/AdES/QC) gösterimi gerek.            |
| Otomatik karar (kabul/red) sistemleri             | `SIMPLE`          | `Valid` + `ChainRevocationStatus` + `AppliedRejections` karar için yeterli payload.   |
| Adli inceleme / chain-of-custody raporu          | `COMPREHENSIVE`   | `ValidationDetails`, `AppliedSuppressions.Evidence` ve tam zincir audit için gerek.   |

## Gereksinimler

| Çalışma Ortamı                                  | Desteklenen Sürüm                   |
| ----------------------------------------------- | ----------------------------------- |
| **.NET (modern)**                               | net8.0 (LTS) — özel optimize asset  |
| **.NET 5 / 6 / 7 / 9**                          | netstandard2.0 üzerinden            |
| **.NET Core**                                   | 2.0, 2.1, 2.2, 3.0, 3.1             |
| **.NET Framework (Windows)**                    | 4.6.1, 4.6.2, 4.7.x, 4.8, 4.8.1     |
| **Mono**                                        | 5.4+                                |
| **Xamarin** (iOS / Android / Mac)               | tüm güncel SDK'lar                   |
| **Unity** (IL2CPP / Mono backend)               | 2018.1+                             |

- Çalışan bir [mersel-dss-verifier-api-java](https://github.com/mersel-dss/mersel-dss-verifier-api-java) mikroservisi (varsayılan port: `8086`)

> **Eski .NET Framework için not**: `System.Net.Http.HttpClient` 4.5.2+ ile gelir; ekstra paket gerekmez. `appsettings.json` + DI senaryosu için klasik .NET Framework projelerinde `Microsoft.Extensions.Hosting` veya `Microsoft.Extensions.DependencyInjection` + `Microsoft.Extensions.Configuration.Json` paketlerini eklemeniz yeterli — istemci SDK'sı kendi bağımlılıklarını (`Microsoft.Extensions.Http` 8.0.x) zaten getirir.

## Bağlantılar

- [Sunucu projesi](https://github.com/mersel-dss/mersel-dss-verifier-api-java)
- [API rehberi](https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/API_GUIDE.md)
- [Suppression kodları katalogu](https://github.com/mersel-dss/mersel-dss-verifier-api-java/tree/main/docs/suppressions)
- [Rejection kodları katalogu](https://github.com/mersel-dss/mersel-dss-verifier-api-java/tree/main/docs/rejections)
