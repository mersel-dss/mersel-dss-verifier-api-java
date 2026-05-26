# Changelog

Tum onemli degisiklikler bu dosyada dokumante edilmektedir.

Format [Keep a Changelog 1.0.0](https://keepachangelog.com/en/1.0.0/) standardina dayanir,
ve bu proje [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) kullanir.

## [Unreleased]

## [0.4.2] - 2026-05-26

### Added
- **INVALID imza bildirimleri `x-log-*` korelasyon header'larını taşıyor** —
  Request thread'inde `LogHeadersFilter`'ın MDC'ye koyduğu tüm `x-log-*`
  prefix'li header'lar (request ID, tenant, kullanıcı, trace), notifier'ın
  sync kısmında snapshot edilip async dispatch yolundaki **her kanala**
  taşınır:
  - **Generic webhook JSON payload** — yeni `logHeaders: { "x-log-id":
    "...", "x-log-tenant": "...", ... }` alanı. Anahtarlar deterministik
    olsun diye sözlük sıralı (TreeMap); hiç header yoksa alan `null`
    serializasyon hariciyle JSON'a düşmez (schema kararlı).
  - **Webhook pass-through HTTP header'ları** — receiver kendi log
    aggregator'ında istek bazlı korelasyon kurabilsin diye her header
    HTTP header olarak da iletilir. HMAC imza sözleşmesi BOZULMAZ —
    `X-Mersel-Signature` hala yalnız `timestamp + "." + rawBody` üzerine
    hesaplanır (header'lar imzaya dahil edilmez; receiver doğrulama yolu
    aynı kalır, geriye uyumlu).
  - **Slack mesaj** — özet field bloğundan sonra yeni bir "*Korelasyon
    (x-log-*):*" section'ı; 10'a kadar header listelenir, fazlası
    "+N daha" satırıyla özetlenir (Block Kit 3000-char/section limiti
    için sertleştirme). Hiç header yoksa blok eklenmez (chat'i gürültüye
    sokmayız).
  - **Slack bot file upload `initial_comment`** — aynı x-log-* listesi
    plain mrkdwn satırı olarak dosyanın altında görünür.
  - **Async-safe snapshot**: MDC thread-local; OkHttp dispatcher'a
    geçtikten sonra MDC erişimi YOK. Notifier `MDC.getCopyOfContextMap()`'i
    sync kısımda alıp dispatch zincirine immutable bir kopya geçirerek
    bu boşluğu kapatır. Tüm dispatch metodları null-safe.
- **`.NET istemci — per-request custom header desteği** — `VerifySignatureRequest`
  ve `VerifyTimestampRequest` üzerine yeni `Headers: IDictionary<string,
  string>?` alanı. `DssVerifierHttpBase` artık `HttpClient.PostAsync(...)`
  yerine `HttpRequestMessage` + `SendAsync(...)` kullanarak isteğe
  request-level header ekleyebilir; verifier sub-client'ları
  `request.Headers`'ı buraya iletir. `TryAddWithoutValidation` ile
  eklenir (içerik header validation şikayetlerini by-pass eder); tek
  bir bozuk header diğer header'ların eklenmesini bozmaz. Tipik
  kullanım: upstream akıştan gelen `x-log-id / x-log-tenant / x-log-user
  / x-log-trace` gibi korelasyon başlıklarını DSS Verifier log/alarm
  akışına aktarmak — sunucu tarafında otomatik olarak MDC'ye taşınır,
  log satırlarına JSON olarak iliştirilir ve INVALID imza
  webhook/Slack bildirimlerine de propagate edilir. README'ye uçtan
  uca örnek eklendi.

## [0.4.1] - 2026-05-26

### Added
- **`.NET / NuGet istemci SDK'sı: `MERSEL.Services.DssVerifier.Client`** —
  Verifier API'yi HTTP üzerinden tüketen, tek satır DI kaydıyla
  uygulamaya entegre olabilen resmi .NET istemcisi
  (`clients/dotnet-client/`).
  - **Motivasyon**: Türkiye'deki muhasebe / mali müşavir / ön muhasebe
    yazılım evlerinin önemli bir kısmı .NET ekosisteminde — klasik
    .NET Framework 4.6.1+ on-prem WinForms/WPF kurulumlarından, modern
    ASP.NET Core 8 bulut backend'lerine kadar. Bu kullanıcıların imza
    doğrulama akışlarını entegre etmesi için iki yol vardı: (a) ham
    `HttpClient` ile multipart isteklerini elle inşa etmek (her
    upgrade'de breaking pattern, model evrimi izlenemiyor); (b) Swagger
    Codegen ile otomatik istemci üretmek (jenerik, idiomatic değil,
    Türkiye-spesifik `MDSS-*` suppression/rejection alanlarının
    semantiği üreticinin elinde kayboluyor). Resmi tipli SDK ile her
    iki problemi de çözüyoruz: response sözleşmesi (`SignatureInfo`,
    `AppliedSuppression`, `AppliedRejection`, `ChainRevocationStatus`)
    Java tarafıyla 1:1 senkron, evrim API kontratıyla koordineli.
  - **TFM stratejisi — `netstandard2.0` + `net8.0`**: Sahadaki tüm
    runtime'ları kapsamak ve modern LTS'in optimizasyonlarını birlikte
    sunmak için iki-hedefli paket. `netstandard2.0` ile yakalananlar:
    .NET Framework 4.6.1+, .NET Core 2.x/3.x, .NET 5/6/7/9, Mono 5.4+,
    Xamarin (iOS / Android / Mac), Unity 2018.1+. `net8.0` ile modern
    runtime'lar source-gen JSON, JIT iyileştirmeleri ve HTTP/2 keep-alive
    optimizasyonlu özel asset alır. Ara TFM'lere (net6/7/9) gerek yok —
    netstandard2.0 hepsini zaten karşılıyor; ekstra hedef yalnız paket
    boyutunu büyütür ve CI matrix'ini şişirir. Pazardaki yerleşik
    rakiplerin SDK'larının çoğu yalnız `netstandard2.1` ya da `net6+`
    veriyor; bu, klasik .NET Framework 4.7/4.8 entegrasyonlarında "REST'i
    elle çağır" denilmesine yol açıyor — biz sahada bu engeli kaldırdık.
  - **Mimari**: Aggregator pattern + `IHttpClientFactory`. Tüketici
    tarafta birleşik `IDssVerifierClient` cephesinin yanı sıra
    `ISignatureVerifier`, `ITimestampVerifier`, `IHealthClient`
    sub-interface'leri bağımsız inject edilebilir (slim consumer ihtiyacı
    için). Tüm sub-client'lar tek bir named `HttpClient`
    (`DssVerifierClientOptions.HttpClientName`) paylaşır — `Polly`,
    `AddHttpMessageHandler`, gateway auth header'ları gibi cross-cutting
    eklentiler tek noktadan zincire eklenebilir. Sunucu auth uygulamaz
    (internal / gateway-arkası mimari); kullanıcı extra header'larını
    standart `IHttpClientBuilder.ConfigureHttpClient` zinciri ile ekler.
  - **DI kaydı — üç overload**: (a) `AddDssVerifierClient(IConfiguration,
    sectionName)` — `appsettings.json` (`Services:DssVerifier` default
    section) bağlama; (b) `AddDssVerifierClient(Action<Options>)` — kod
    ile yapılandırma; (c) `AddDssVerifierClient(string baseUrl)` — hızlı
    yol. `Options.Validate(...)` ile `BaseUrl` boş bırakılırsa DI build
    aşamasında fail-fast.
  - **Endpoint kapsamı**: `POST /api/v1/verify/signature` (XAdES /
    PAdES / CAdES tek API — sunucu format kararını içeriği inceleyerek
    verir; istemci tarafında ayrım gerekmez), `POST /api/v1/verify/timestamp`
    (standalone RFC 3161), `GET /api/v1/health`, `GET /api/v1/info`.
    Detached imza akışları için `VerifyDetachedAsync(signed, original)`
    kısa-yol overload'ı.
  - **`MDSS-*` kataloğunun tipli expose'u**: `Models/Enums/SuppressionCode`
    ve `RejectionCode` enum'ları Java tarafındaki kararlı kod kataloğunu
    birebir yansıtır. `Extensions.GetCode()` ile enum→kanonik kod string
    dönüşümü (`MDSS_XADES_LEGACY_TR_TYPE_URI` → `MDSS-XADES-LEGACY-TR-TYPE-URI`),
    `TryParse(string)` ile wire format → enum dönüşümü; bilinmeyen kodlar
    `null` döner (forward-compatible — yeni kod eklendikçe eski client
    crash etmez, sadece `string Code` alanı dolu kalır). Bu, audit /
    compliance / Prometheus metric label akışlarında "kod ile branch
    etmek" senaryosunu net şekilde çözer.
  - **Hata sözleşmesi — semantic ayrım**: İmza geçersiz çıkması bir HTTP
    hatası **değildir** — sunucu HTTP 200 + `VerificationResult.Valid =
    false` döner; çağıran kod bu alanı + `AppliedRejections` listesini
    inceler. Yalnız transport / sunucu hataları (4xx/5xx) için
    `DssVerifierApiException` fırlatılır; `ApiError` üzerinden sunucunun
    yapılandırılmış `ErrorResponse` gövdesi (`error`, `message`,
    `details`, `timestamp`, `path`) erişilebilir. `Internal/DssVerifierHttpBase`
    içinde JSON parse heuristic'i Content-Type yokken bile gövdeyi
    deşifre etmeye çalışır (defansif).
  - **Multi-TFM uyumluluk detayları**: `await using` ve `CancellationToken`
    almak isteyen `ReadAsStringAsync(ct)` / `ReadAsStreamAsync(ct)`
    overload'ları `#if NET6_0_OR_GREATER` guard'ı ile koşullu; netstandard2.0
    build'inde fallback `using` + parametre-yok varyantları kullanılır.
    `ImplicitUsings` kapatıldı; `GlobalUsings.cs` tek noktada her iki TFM
    için aynı namespace set'ini ilan eder — TFM'ler arası subtle import
    kayması riski yok.
  - **NuGet release otomasyonu — `.github/workflows/nuget.yml`**: Aynı
    `v*` tag push'unda `release.yml` (JAR + SBOM + checksum) ve
    `docker-publish.yml` ile **paralel** koşan, birbirinden bağımsız
    workflow. Tag'i SemVer 2.0.0 olarak parse edip
    `dotnet pack -p:Version=...` ile csproj'daki `0.0.0-dev` placeholder'ı
    override eder; `-SNAPSHOT` reddedilir; `--skip-duplicate` ile re-run
    idempotent. Manuel `workflow_dispatch` ile `dry_run` modu (artifact
    üret, push etme) smoke test için açık. Çıktılar: `.nupkg` +
    SourceLink + symbols (`.snupkg`) — NuGet'e push edilen paket her
    zaman sunucu release tag'iyle senkron (`dotnet add package
    MERSEL.Services.DssVerifier.Client --version 0.5.1` dediğinde aynı
    sürümün Docker imajı + GitHub Release JAR'ı birebir eşleşir).
    `setup-dotnet` sadece `8.0.x` SDK'yı kurar — Roslyn cross-targets ile
    netstandard2.0 build'i için ayrıca SDK kurmaya gerek yok.
  - **Build doğrulaması**: `dotnet build -c Release` her iki TFM için
    de **0 warning, 0 error**; `dotnet pack` `lib/netstandard2.0/` +
    `lib/net8.0/` asset'leri ile yaklaşık 80 KB `.nupkg` üretir
    (sade payload, hızlı restore).
  - **NuGet yayın ön koşulu**: Repo `Settings → Secrets → Actions`
    altına `NUGET_API_KEY` secret'i ve `nuget` adında bir GitHub
    environment (opsiyonel ama önerilir — production protection rule
    için) tanımlanmalı.

## [0.4.0] - 2026-05-25

### Added
- **`x-log-*` request header'ları artık tüm log satırlarında JSON olarak
  otomatik görünür — opt-in correlation/trace observability sözleşmesi.**
  - **Motivasyon**: Operatör, çağıran sistemden gelen takip metadatasını
    (örn. `X-Log-Id: abc`, `X-Log-Kimlik: kajsdh`) controller / service
    kodunda elle parametre olarak taşımadan, GİB submission ID'si veya
    müşteri tarafı correlation key'lerini doğrulama akışlarının (XAdES /
    CAdES / PAdES verify, certificate inspection, vb.) info / warn / error
    satırlarının hepsinde gözleyebilmeli. Manuel
    `LOGGER.info("[{}]", traceId, ...)` pattern'i controller, ~servis ve
    `GlobalExceptionHandler` arasında çoğaltılması anlamsız boilerplate
    olurdu.
  - **Mekanizma**: Yeni `LogHeadersFilter`
    (`Ordered.HIGHEST_PRECEDENCE + 50`) request başında `x-log-` prefix'li
    tüm header'ları (case-insensitive) yakalayıp SLF4J `MDC`'ye
    `xlog.<lower-case-name>` formunda yazar; request bitince (exception
    path dahil) sadece kendi yazdığı anahtarları temizler — başka kodun
    MDC'sine dokunmaz. Yeni `LogHeadersConverter` Logback
    `ClassicConverter`'ı pattern içinde `%xLogHeaders` olarak kayıtlı;
    her log event'inde `xlog.*` MDC entry'lerini alfabetik sırada JSON
    nesnesine serialize eder. Hiç header yoksa boş string döner — mevcut
    log gürültüsü artmaz.
  - **Çıktı formatı**: `xlog={"x-log-id":"abc","x-log-kimlik":"kajsdh"}`.
    Konum: standart pattern'in sonunda (`%msg` sonrası, `%n` öncesi).
    `logback-spring.xml` içindeki CONSOLE / `application.log` /
    `error.log` / `verification.log` appender'larının hepsi yeni
    pattern'i kullanır.
  - **Güvenlik sertleştirmesi**: (a) request başına en fazla
    20 `x-log-*` header işlenir — şişirilmiş header bombasına karşı
    sınır; (b) her değer 512 karaktere kırpılır; (c) CR/LF + diğer
    ASCII kontrol karakterleri boşluğa çevrilir — klasik CRLF log
    injection vektörü kapatılır; (d) converter ikinci savunma hattı
    olarak `<0x20` kontrol karakterlerini RFC 8259 JSON kaçışına uğratır.
  - **Async sınırlama**: SLF4J MDC thread-local'dir; `@Async`
    dispatch'lerinde context otomatik propagate olmaz.
    `InvalidSignatureNotifier` gibi fire-and-forget async bildirim
    yollarında correlation header'ı async task içinden görünmez (request
    thread'inde sync atılan log'larda zaten görünür). Bu davranış
    bilinçli — async pipeline'ın MDC kopyalamasını isteyen kullanıcı
    explicit `MDC.getCopyOfContextMap()` taşımalı.
  - **Geriye dönük uyumluluk**: Mevcut log analiz/parse araçları için
    breaking değil — log satırının yapısı korunur, `xlog={...}` bloğu
    sadece request thread'inde ve sadece `x-log-*` header gönderildiğinde
    eklenir. Header gelmeyen istekler aynı çıktıyı üretir.
  - Üç yeni test sınıfı: `LogHeadersFilterTest` (MDC propagation,
    cleanup, CRLF sanitization, max headers / max value length, exception
    cleanup), `LogHeadersConverterTest` (boş MDC, alfabetik sıralama,
    JSON kaçışları), `LogHeadersEndToEndTest` (gerçek Logback pattern
    içinden uçtan uca emisyon — INFO / WARN / ERROR seviyeleri ve
    request-context dışı izolasyon).
- **İmza doğrulama yanıtında kriptografik algoritma görünürlüğü
  (`signatureAlgorithm` + `digestAlgorithm`)**: Daha önce
  `SignatureInfo` modelinde bu iki alan tanımlıydı ancak servis
  doldurmuyor, JSON'da hiç görünmüyordu — operatör "belge nasıl
  özetlenmiş, nasıl imzalanmış?" sorusuna cevap için ya
  COMPREHENSIVE moda geçip sertifikanın `signatureAlgorithm`'ına
  bakıyor (yanlış; o CA→leaf algoritması) ya da DSS DetailedReport'u
  manuel parse ediyordu. Artık her doğrulama yanıtında imzanın
  kendisinin kompozit algoritması (örn. `RSA_SHA256`, `ECDSA_SHA384`)
  ve `ds:SignedInfo` özet algoritması (örn. `SHA256`) tek bakışta
  görünür.
  - `AdvancedSignatureVerificationService.processSignatureWrapper`
    DSS `SignatureWrapper.getSignatureAlgorithm()` /
    `getDigestAlgorithm()` üzerinden iki alanı set eder; alanlar
    SIMPLE ve COMPREHENSIVE modlarda eşit görünür (audit/kriptografik
    politika kontrolü için seviye-bağımsız sözleşme).
  - `signatureAlgorithm` DSS `SignatureAlgorithm` enum sabit adıyla
    (`RSA_SHA256`) raporlanır — machine-readable, stabil. DiagnosticData
    kompozit dönemediği nadir durumlarda encryption+digest enum'ları
    birleştirilerek aynı formatta gösterilir (defansif fallback);
    her ikisi de yoksa alan `null` kalır ve `@JsonInclude(NON_NULL)`
    sayesinde JSON'a hiç düşmez (geriye dönük uyumluluk).
  - `digestAlgorithm` DSS `DigestAlgorithm.getName()` ile insan-okur
    formda (`SHA256`) raporlanır; aynı `NON_NULL` sözleşmesiyle
    korunur.
  - `SignatureInfo` üzerindeki bu iki alanın artık dış API
    kontratının parçası olduğunu kayıt altına alan iki yeni
    `SignatureInfoTest` testi eklendi (set→JSON round-trip + null
    elision). Aktif kullanımda olmayan legacy `SignatureVerificationService`
    bilinçli olarak değiştirilmedi (controller'a bağlı değil; ileride
    aktive edilirse aynı blok oraya da taşınmalı).
- **INVALID imza bildirim altyapisi (webhook + Slack mesaj + Slack dosya
  upload + HMAC imza)**: Bir imza dogrulama sonucu `INVALID` oldugunda
  konfigure edilmis hedeflere <em>async, best-effort, fire-and-forget</em>
  bildirim gondererek mukellef tarafinin saatlerce sonra fark ettigi
  Mali Muhur anomalilerini saniyeler icinde alarm kanalina dusurur.
  Tum kanallar bagimsiz aktivasyona sahip; sifirli env durumunda heap/IO
  maliyeti tamamen sifirdir. Yerlesik bulut cozumlerinin UI bildirimi +
  gunluk cron rapor modelinin <strong>aksine</strong> olay-tabanli
  push-arkitektur.
  - Yeni paket: `services/notification` — `InvalidSignatureNotifier`
    orkestrator, `SlackFileUploader` 3-adimli Slack file API sarmali,
    `InvalidSignatureWebhookPayload` JSON schema (`event` / `source` /
    `notificationTime` / `file{name,sizeBytes,contentType,sha256Hex,
    base64Content,contentOmittedReason}` / `originalDocument` /
    `result`).
  - Yeni konfigurasyon: `config/InvalidSignatureNotificationConfiguration`
    (env-driven, tek env var ile aktivasyon prensibi — operator URL set
    eder etmez kanal acilir).
  - **Generic webhook kanali** — operatorun kendi alert/ticket/audit
    sistemine JSON POST. Payload `result` alaninda **DSS dogrulama
    sonucunun tamami** (signatures, certificateChain, validationDetails,
    appliedRejections, appliedSuppressions) gomulur — receiver ayri bir
    kisaltma kontrati parse etmek zorunda degildir. Dogrulanan dosya
    base64 olarak `file.base64Content` icine, dosyanin SHA-256 hash'i
    `file.sha256Hex` icine gomulur (icerik <em>opsiyonel</em>, hash
    her zaman).
  - **Slack incoming webhook kanali** — Slack kanalinda Block Kit
    formatinda zenginlestirilmis alarm mesaji. Mesaj `attachments`
    legacy field'i icine gomulur (`color: "#A30200"`) — boylece mesajin
    sol kenarinda <strong>kirmizi dikey serit</strong> olusur, INVALID
    alarmi bir bakista ayirt edilir. Block Kit kendi basina renk
    desteklemediginden Slack'in danger sinyallemesi icin tek desteklenen
    yol budur. Icerik: header + summary fields (dosya/status/imza tipi/
    sayi) + hata listesi (max 5, kalanlar ozetlenir) + per-signature
    blok (indication / subIndication / imzaci CN + Mersel rejection
    kodu). Base64 icerik chat kanalina ASLA gitmez.
  - **Slack bot file upload kanali** — alarm mesajina ek olarak
    dogrulanan dosyayi Slack kanalina <strong>indirilebilir ek</strong>
    olarak yukler. Slack `files.upload` Kasim 2025'te sunset edildigi
    icin yeni zorunlu 3-adimli flow kullanilir:
    `files.getUploadURLExternal` → upload_url'e raw byte POST →
    `files.completeUploadExternal`. Hem `INVALID_SIGNATURE_SLACK_BOT_TOKEN`
    (xoxb-… Bot User OAuth Token, scope: `files:write`) hem
    `INVALID_SIGNATURE_SLACK_CHANNEL` (kanal ADI degil ID, `C0123…`
    formati) set edilmedikce upload tetiklenmez. Dosya
    `MAX_CONTENT_SIZE_BYTES` esigini aliyorsa upload atlanir; webhook
    payload zaten metadata + omittedReason tasidigindan veri kaybi yok.
  - **Slack-only / single-URL dagitim modu — inline base64** — Operatorun
    Slack uygulamasi + bot token + `files:write` scope yonetmek
    istemedigi/kuramayacagi senaryolar icin (kurumsal IT politikasi,
    hizli POC, kucuk ekip): dogrulanan dosya Slack chat mesajinin ICINE
    base64 + triple-backtick code block olarak gomulur. Boylece operator
    yalniz tek bir Slack incoming webhook URL'i set eder, harici depo
    veya bot/scope kurulumu gerekmez — pazardaki yerlesik cozumlerin
    "linke tikla, login ol, dosyayi indir" akisindan farkli olarak
    dosya tam Slack mesajinin icinde, **chat'ten cikmadan**. Davranis:
    - **Opt-in**, default `false`. Operator bilincli olarak
      `INVALID_SIGNATURE_SLACK_INLINE_BASE64_ENABLED=true` yapmadikca
      Slack mesaji sade kalir (chat'i base64 ile kirletme riski yok).
    - **Default 8KB boyut sinir**i — base64 expansion 4/3x ile 8KB
      binary ≈ 10.9KB string; Slack mesaj toplam 40KB sinirin altinda
      rahatca yasar. Sinir asilirsa inline atlanir; mesajda "boyut
      limit asildi" notice satiri belirir (sessiz drop YOK).
    - **Otomatik chunk**ing — Block Kit per-section text limiti 3000
      char (toplam 40KB sinirindan ONCE vuran constraint).
      `chunkForSlackSection()` static helper'i base64 string'i ~2700
      char'lik parcalara boler ve birden fazla section block'a basar.
      8KB icin ~5 blok; Block Kit per-message 50 blok izninin cok
      altinda. Round-trip garantisi: `String.join("", chunks)` her
      zaman orijinal base64'e esit — tek char drift bile dosyayi
      bozar, dedicated test ile korunur.
    - **Bot upload'dan bagimsiz** — iki kanal ayni anda da set
      edilebilir (ikisi de tetiklenir, kanallar birbirini bastirmaz).
      Operator trade-off'u: bot upload daha kaliteli UX
      (gercek download'lanabilir dosya), inline base64 ise tek URL'le
      ayakta kalir.
    - **Alici tarafi decode** — mesajdaki code block icerigini secip
      `pbpaste | base64 -d > signed.bin` (macOS) veya
      `xclip -o | base64 -d > signed.bin` (Linux); multi-chunk
      durumunda tum code block'lar concat edilip ayni komuta verilir.
  - **HMAC webhook imzasi (kaynak dogrulama)** —
    `INVALID_SIGNATURE_WEBHOOK_SECRET` set edilirse her generic webhook
    POST'una su header'lar eklenir (kararli API kontrati):
    - `X-Mersel-Event: invalid-signature` — event tipi
    - `X-Mersel-Webhook-Id: <uuid>` — her delivery icin essiz (receiver
      idempotency icin)
    - `X-Mersel-Webhook-Timestamp: <unix-epoch-seconds>` — replay
      protection
    - `X-Mersel-Signature: sha256=<hex>` —
      HMAC-SHA256(`"<timestamp>.<rawBody>"`, secret) lowercase hex
    
    Signing string'e timestamp dahil etmek (Stripe-style) sadece body
    imzalamak yerine replay vektorunu kapatir. Receiver tarafinda
    constant-time karsilastirma ZORUNLU (timingSafeEqual / MessageDigest.isEqual);
    `==` veya `equals()` timing saldirilarina acik. Slack incoming
    webhook icin HMAC YOK — Slack URL'in kendisi resmi secret
    modelidir; HMAC header'i Slack tarafinda parse edilemez. Slack bot
    token zaten kendi auth katmanini saglar.
  - **Best-effort + async + defense-in-depth** — Tum kanallar OkHttp
    `Call.enqueue()` ile arka plana atilir; verifier thread'i HTTP'yi
    beklemez. Bildirim hatasi dogrulama akisini ASLA bozmaz, asla
    `valid` field'ini etkilemez. UC KATMAN exception kalkani:
    1. `AdvancedSignatureVerificationService` <strong>VE</strong>
       `SignatureVerificationService` (lite verifier) — her ikisinde
       de `notifyIfInvalid()` cagrisi `Throwable` catch'iyle saril
       (verifier'in son perdesi); ayrica `originalDocument.getBytes()`
       ayri try/catch'te (temp-file IO hatasinda bildirim signedBytes
       ile yine gider). Lite verifier'a entegrasyon defansif:
       `UnifiedVerificationController` su an yalniz advanced verifier'i
       kullaniyor, ama gelecekte lite endpoint baglanirsa bildirim
       <em>otomatik</em> aktif olur — sessiz kaybolan INVALID notification
       riski yok.
    2. `InvalidSignatureNotifier.notifyIfInvalid()` outer `Throwable`
       catch + her dispatch kanali (webhook / Slack mesaj / Slack file
       upload) <strong>bagimsiz</strong> try/catch'te — birinin patlamasi
       digerini engellemez (operator izolasyon talep ediyor).
    3. OkHttp callback'lerinde `onResponse` ve `onFailure` ayri ayri
       `Throwable` catch; SlackFileUploader'in 3 step'inde Request build
       + JSON parse ayri guard'larla; HMAC hesabi `null` doner
       (header silinir, throw etmez).
    
    Receiver 500/timeout/yanlis URL/malformed apiBase/connection refused
    hepsi WARN log + akis devam. Retry yok (idempotency receiver
    tarafinda); cunku dogrulama bir kez yapildi, bildirim ikinci sinif
    audit kanali.
  - **Lazy OkHttpClient init — gercek zero-overhead** — Onceki
    implementasyon @PostConstruct'ta KOSULSUZ bir OkHttpClient kurar,
    dispatcher thread pool + connection pool yaratirdi (URL set
    edilmemis olsa bile ~birkac MB heap + 2-3 idle thread yasardi).
    Yeni davranis: `config.isEnabled()` false VEYA
    `config.hasAnyDestination()` false ise OkHttpClient YARATILMAZ;
    `httpClient` null kalir, "zero-overhead" iddasi gercek anlamiyla
    tutulur. `fireWebhookPost` ve `fireSimplePost` metodlarinda null
    guard'lar var — runtime'da config setter ile destination set
    edilse ama bean refresh atlansa bile NPE atmaz, WARN log + sus
    + verifier akisi temiz.
  - **Gizlilik kontrolu** — `INCLUDE_CONTENT=false` ile base64 icerik
    payload'dan dusurulebilir; SHA-256 hash yine gider, dolayisiyla
    receiver dosyayi kendi arsivinden eslestirebilir. Dosya
    `MAX_CONTENT_SIZE_BYTES` (default 10MB) ustundeyse otomatik atlanir
    ve `contentOmittedReason` alanina (`EXCLUDED_BY_CONFIG` veya
    `EXCEEDED_MAX_SIZE`) yazilir — receiver "icerik gelmedi, neden?"
    sorusunun cevabini payload'dan goruyor.
  - 13 yeni env var (hepsi opsiyonel, default'lar `application.properties`
    icinde yorumlu): `INVALID_SIGNATURE_NOTIFICATION_ENABLED`,
    `INVALID_SIGNATURE_WEBHOOK_URL`, `INVALID_SIGNATURE_WEBHOOK_SECRET`,
    `INVALID_SIGNATURE_SLACK_WEBHOOK_URL`,
    `INVALID_SIGNATURE_SLACK_BOT_TOKEN`, `INVALID_SIGNATURE_SLACK_CHANNEL`,
    `INVALID_SIGNATURE_SLACK_INLINE_BASE64_ENABLED`,
    `INVALID_SIGNATURE_SLACK_INLINE_BASE64_MAX_BYTES`,
    `INVALID_SIGNATURE_NOTIFICATION_INCLUDE_CONTENT`,
    `INVALID_SIGNATURE_NOTIFICATION_MAX_CONTENT_SIZE_BYTES`,
    `INVALID_SIGNATURE_NOTIFICATION_CONNECT_TIMEOUT_MS`,
    `INVALID_SIGNATURE_NOTIFICATION_READ_TIMEOUT_MS`.
  - Yeni test bagimliligi (sadece test scope):
    `okhttp3:mockwebserver:4.2.2` — InvalidSignatureNotifier ve
    SlackFileUploader'in 3-adimli akisini in-process gercek bir TCP
    server'la birebir dogrular; HTTP davranisi mock'lanmadi, asil
    OkHttp pipeline'i kullanildi.
  - 36 yeni unit test (`InvalidSignatureNotifierTest`): gate
    davranislari (null/VALID/disabled/no-destination), generic webhook
    full payload + base64 content + sha256 hex, `includeContent=false`
    + `maxSize` override'lari, detached imza icin `originalDocument`
    alani, receiver 500 + malformed URL toleransi, Slack `attachments`
    color sidebar + Block Kit format + base64 sizmamasi, Slack hata
    listesi truncation, per-signature Mersel rejection kodlari, HMAC
    header'larinin secret olmadan/varken davranisi, HMAC'in body ve
    timestamp degisikliklerine duyarliligi, blank secret guvenligi,
    payload.result alaninin tum `VerificationResult` JSON kontrati,
    Slack 3-step file upload end-to-end (getUploadURLExternal → CDN
    binary POST → completeUploadExternal), file upload boyut sinirinda
    atlanma davranisi, Slack step 1 `ok:false` durumunda zincir
    kesilmesi. <strong>Slack inline base64 (Slack-only mod) testleri</strong>:
    default opt-out (chat kirletmeme), opt-in tek-chunk roundtrip,
    8KB icerigin coklu Block Kit section'larina chunk'lanmasi (her
    section ≤2900 char + drift'siz reassemble + decode roundtrip
    orijinal byte'lara dogru donus), boyut cap'i asildiginda
    omission notice + decode hint suppression, MockWebServer
    uzerinden end-to-end transfer.
    <strong>Defense-in-depth/async sozlesme testleri</strong>:
    malformed webhook URL, tum hedeflerin patolojik olmasi, bozuk
    serializer, receiver hang (caller HTTP'yi beklemiyor: elapsed <1s),
    async tetikleme (receiver 800ms delay'lerken caller <500ms doner),
    kanal izolasyonu (webhook patladiginda Slack yine tetikleniyor).
    <strong>Lazy init + null guard testleri</strong>: destination
    yokken OkHttpClient kurulmamasi, feature disabled iken aynisi,
    runtime config degisiminde null httpClient'a karsi NPE'siz davranis.
  - Yeni dokumantasyon: `docs/notifications/HOW_TO_USE.md` — operator
    rehberi (aktivasyon matrisi, webhook payload semasi, Node.js/Python/
    Java icin HMAC verification ornekleri, Slack bot kurulum adimlari,
    sorun giderme tablosu, pazardaki yerlesik cozumlere kiyas).

- **AIA (Authority Information Access) normalizing + caching katmani**:
  Eimzatr ekosistemindeki bazi ESHS'ler (ornek
  `http://depo.e-imzatriptal.com/sertifika/neshs-v3.cer`) ara CA sertifikasini
  `Content-Type: application/pkix-cert` ile servis ederken **raw DER yerine
  naked base64-encoded text** donuyor. Java `CertificateFactory` raw DER veya
  BEGIN/END header'li PEM kabul eder; naked base64'u reddeder ve DSS
  `NO_CERTIFICATE_CHAIN_FOUND` doner — gercerli bir imza zinciri ZINCIRSIZ
  goruluyordu. Yeni `NormalizingCachingAiaDataLoader` bu naked base64
  payload'larini decode edip DER'e cevirir; ayrica Caffeine cache ile ayni
  ara CA URL'ine yalnizca bir kez gidilir.
  - Yeni sinif: `NormalizingCachingAiaDataLoader implements DataLoader`
    (`services/aia` paketinde). Bir delegate DataLoader'i (tipik
    `CommonsDataLoader`) sarar. Normalize sirasi (idempotent — zaten DER
    veya PEM olana dokunmaz):
    1. DER mi? (`0x30 0x82` prefix — X.509 long-form length tag) → as-is.
    2. PEM mi? (`-----BEGIN` marker'i ilk 64 byte icinde) → as-is.
    3. Naked base64 mi? Whitespace strip + MIME decode + DER prefix
       kontrolu → decoded DER doner.
    4. Hicbiri eslesmezse orijinali doner (WARN log + hex prefix dump);
       DSS kendi hatasini raporlasin, biz maskeleyip yanlis bir sey
       uretmiyoruz.
  - Negative caching: bos response veya null da cache'lenir (kisa TTL'de
    ayni patolojik URL'i tekrar fetch etmek yerine memo'dan null doner).
    Exception ise cache'lenmez — transient olabilir, DSS retry'a aciktir.
  - Cache wiring: `RevocationServicesConfiguration` artik AIA icin bu
    decorator'i kuruyor; Caffeine cache Spring Boot Actuator uzerinden
    Prometheus'a publish ediliyor (`cache_size{cache="mersel.aia.fetch"}`,
    `cache_gets_total{cache="mersel.aia.fetch", result="hit|miss"}`,
    `cache_puts_total`, `cache_evictions_total`).
  - 2 yeni parametre (env var ile override edilebilir):
    - `verification.aia.cache.max-size` (default `256` — KamuSM
      ekosisteminde aktif ara CA sayisi <=20, 256 haftalarca rahat
      yeter).
    - `verification.aia.cache.ttl-seconds` (default `86400` = 24 saat —
      ara CA sertifikalarinin gecerlilik suresi yillarca oldugu icin
      gunluk TTL guvenli).
  - Serialization opt-out: `DataLoader` interface'i Serializable extends
    ettigi icin compiler `NormalizingCachingAiaDataLoader`'a da
    Serializable ekliyor; ancak canli durumu (HTTP delegate + Caffeine
    cache) transient — deserialize'da her ikisi de null olur ve sonraki
    cagri NPE atar. Bu durumu erkenden yakalamak icin sinifa `writeObject`
    ve `readObject` eklendi; her ikisi de `NotSerializableException`
    firlatir. Spring singleton bean yanlislikla session replication /
    distributed cache'e girerse runtime'da net hata alinir.
  - 24 yeni unit test (`NormalizingCachingAiaDataLoaderTest`): DER
    passthrough, PEM passthrough, naked base64 decode (sentetik 1500+ byte
    X.509 sertifikasi ile), Eimzatr endpoint regresyon repro'su,
    cache-hit-miss-eviction davranisi, negative caching, exception
    transient'ligi, multi-URL `get(List)` delegasyonu, `setContentType`
    passthrough, constructor invariant'lari (null delegate / negative
    cache size / negative TTL), serialization opt-out.

- **XAdES tek referansli imza patolojisi icin `RejectionCode` framework'u**:
  Mersel DSS Verifier artik DSS verdict'i `INVALID` olan imzalar icin de
  Turkiye ekosistemine ozgu **kataloglu tani kodu** raporlayabiliyor.
  `AppliedSuppression` (DSS INVALID → biz VALID, override) ile semantik
  olarak farkli yeni bir konsept: `AppliedRejection` (DSS INVALID → biz de
  INVALID, ama "neden" sorusuna kataloglu kod + somut kanit ile cevap
  veririz). Verdict degismez; yalniz tani kanali zenginlestirilir.
  - Yeni enum: `RejectionCode` (`models/enums` paketinde). Naming
    convention `MDSS-{LAYER}-{DESCRIPTIVE-SLUG}` — `SuppressionCode` ile
    ayni semayi paylasir; ayni kod hem suppression hem rejection olarak
    gorunmez (ekleme sirasinda calisma kontrolu yapilir).
  - Yeni model: `AppliedRejection` (`@JsonInclude(NON_NULL)`). Alanlar
    `code`, `title`, `reason`, `severity`, `originalIndication`,
    `originalSubIndication`, `evidence` (immutable map), `docsUrl`. Audit/
    compliance icin DSS'in *gercek* kararini (override oncesi) muhafaza
    eder — denetleyici "DSS aslinda ne demisti, biz neden bu kodu
    ekledik?" sorusuna kesin cevap alir.
  - Yeni alan: `SignatureInfo.appliedRejections` (List). Bos veya null ise
    DSS'in jenerik subIndication'i tek basina yeterli kabul edildi
    demektir.
  - Ilk kayitli kod: **`MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE`** —
    XAdES imza yalnizca bir `<ds:Reference>` tasiyor; `<xades:SignedProperties>`
    elementi XML icinde mevcut fakat hicbir Reference ona pointing degil.
    ETSI EN 319 132-1 (XAdES-BES) iki referans (biri belge body'si, biri
    SignedProperties) zorunlulugu ihlali. Sonuc: `SigningTime`,
    `SigningCertificate` digest, `SignaturePolicyIdentifier`,
    `SignerRole`, `CommitmentTypeIndication` gibi imzanin anlamini
    tasiyan alanlar imza kapsami disinda kalir; post-signing modifiye
    edilebilir ve imza yine matematik olarak dogrulanir. Yapisal hata
    imzayi ureten yazilimda; iki referans uretilmelidir.
  - Severity `ERROR`. Verdict her zaman `INVALID`; rejection objesi
    yalnizca tani kanalidir. Operator DSS'in jenerik
    `SIG_CONSTRAINTS_FAILURE`'i yerine spesifik Mersel kodu ile yapisal
    nedeni gorur, log/grep ile filtreleyebilir.
  - Konfigurasyon flag'i: **`verification.tr-legacy-xades-rejection-enrichment-enabled`**
    (default `true`). Bu flag yalnizca tani kanalini kontrol eder; imzanin
    `valid=false` davranisini DEGISTIRMEZ. Operator enrichment'i kapatmak
    isterse Mersel kodu uretilmez, DSS'in jenerik subIndication'i tek
    basina raporlanir.
  - Detector genisletmesi (`LegacyTurkishXadesTypeUriDetector`): yeni P3
    patolojisi (MISSING_SP_REFERENCE) eklendi. P1/P2 (TYPE_URI varyantlari,
    suppression) onceligini korur — ilk eslesme doner. Detector artik
    `LegacyTurkishXadesAnomaly` immutable kayit doner (kind + evidence);
    eski `String detect(byte[])` API'si yeni `LegacyTurkishXadesAnomaly
    detectAnomaly(byte[])` ile yer degistirdi (canonical API).
  - **Per-SignedProperties-Id evaluation**: P3 mantigi multi-signature
    senaryolarini da dogru ele alir. Tek SP varsa konservatif Type-only
    fallback korunur (geriye donuk uyum); birden fazla SP varsa her Id
    icin ayri URI fragment kontrolu yapilir, Type-only fallback
    uygulanmaz (hangi SP'ye isaret ettigi belirsiz). "A bagli, B degil"
    senaryosunda B artik dogru flag edilir.
  - 16 yeni unit test (`LegacyTurkishXadesTypeUriDetectorTest` P3
    bolumu): standart XAdES'te P3 atlanmasi, sadece URI fragment ile
    bagli SP, sadece Type ile bagli SP (konservatif fallback), multi-sig
    tum bagli, multi-sig mixed (A bagli + B bagsiz → B flag), multi-sig
    her ikisi de bagsiz (ilk dokuman sirasinda flag), Type URI varyanti
    onceligi (P1/P2 P3'ten once kazanir), SignedProperties yok, prefixsiz
    namespace.
  - 9 yeni unit test (`AppliedRejectionTest`): code/severity sabitleri,
    docs URL sabiti, immutability, SignatureInfo exposure, JSON
    serialization, `@JsonInclude(NON_NULL)` davranisi, RejectionCode
    namespace'inin SuppressionCode ile carismamasi.

- **`docs/rejections/` dokumantasyon klasoru**: Her kayitli `RejectionCode`
  icin detayli MD sayfasi.
  - [`docs/rejections/README.md`](docs/rejections/README.md) — index +
    naming convention + kararlilik kurallari + severity rehberi +
    contributor guide.
  - [`docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md`](docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md)
    — sorun ozeti, dogru iki-referansli yapi vs. tek-referansli regresyon,
    saldiri yuzeyi tablosu (SigningTime / SigningCertificate /
    SignaturePolicyIdentifier / SignerRole / CommitmentTypeIndication
    icin tahrifat senaryolari ve pratik etkileri), yasal uyumluluk
    cercevesi (eIDAS / 5070 sayili kanun / ETSI EN 319 132-1), cozum
    (imzayi ureten yazilimin sorumlulugu — iki referans uretmelidir),
    tetik kosullari, API yanit ornegi, log ornegi.
  - [`docs/suppressions/README.md`](docs/suppressions/README.md) altina
    rejection klasorune cross-reference notu eklendi.

### Changed
- **`SignatureVerificationService` (lite verifier) — INVALID
  bildirim entegrasyonu eklendi**: Onceden yalniz
  `AdvancedSignatureVerificationService` notifier'a baglanmisti;
  `SignatureVerificationService` da `INVALID` doneriyordu ama
  bildirim sessizce atlaniyordu. `UnifiedVerificationController` su
  an yalniz advanced verifier'i kullandigi icin production'da sorun
  degildi, ama gelecekte birisi lite verifier'i bir endpoint'e
  baglarsa bildirim akisinin <em>otomatik</em> aktif olmasi icin
  defansif integration eklendi. Ayni 3-katmanli try/catch pattern:
  `@Autowired(required=false)` (bean yoksa verifier yine calisir),
  `Throwable` outer catch (verifier'in son perdesi),
  `originalDocument.getBytes()` ayri try/catch (temp-file IO
  izolasyonu).

- **`AdvancedSignatureVerificationService.processSignature(...)` —
  TR-ozel patoloji degerlendirmesi tekleştirildi**: gate kontrolu ve
  detector cagrisi tek bir noktada yapiliyor; sonuc (anomaly objesi) iki
  evaluate metodu arasinda paylasiliyor. Eskiden `evaluateTrLegacyXadesTolerance`
  ve `evaluateTrLegacyXadesRejection` ayri ayri `matchesTrLegacyXadesGate`
  + `detectAnomaly` cagiriyordu — buyuk UBL faturalarda (100KB+) ayni XML
  iki kez regex parse ediliyordu. Yeni akis tek pass.
  - Evaluate metodlarinin imzalari sadelesti: `signatureWrapper`,
    `detailedReport`, `originalXmlBytes` parametreleri cikarildi; yerine
    onceden tespit edilmis `LegacyTurkishXadesAnomaly` objesi geliyor.
- **`AdvancedSignatureVerificationService.collectErrorsAndWarnings(...)` —
  rejection enrichment iken cift hata satiri kaldirildi**: Rejection
  devredeyken `validationErrors` icine iki ayri satir ekleniyordu:
  - `[MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE] <reason>` (Mersel
    kataloglu).
  - `Imza uyarisi: SIG_CONSTRAINTS_FAILURE (Kritik hata)` (DSS jenerik).
  API tuketicileri "kac hata var?" sorusunda iki cevap aliyordu, ayni
  yapisal sorun icin tekrarli bilgi. Artik rejection devredeyken jenerik
  satir atlanir; Mersel kataloglu satir tek ana hata olarak kalir.
- **`LegacyTurkishXadesTypeUriDetector` API canonical'i degisti**:
  `detect(byte[])` (eski) → `detectAnomaly(byte[])` (yeni). Eski API
  P3 patolojisini raporlayamadigi icin yeni canonical metoda gecis
  yapildi; her caller `LegacyTurkishXadesAnomaly` objesini alir.

### Fixed
- **Multi-signature `MISSING_SP_REFERENCE` false-negative'i**: Detector'in
  onceki fast-negative gate'i ("XML'de herhangi bir Type=SP Reference
  varsa P3'u atla") multi-signature senaryosunda Signature-B'nin
  bagsiz SignedProperties'ini kaciriyordu (Signature-A'nin dogru
  Reference'i butun XML icin gate'i kapatiyordu). Yeni per-SP-Id mantik
  her Id'yi bagimsiz degerlendirir.
  Once SIMPLE mod tuketicisi yalniz `signerCertificate.revocation`'i goruyordu
  — "leaf GOOD ama bir ara CA REVOKED" gibi senaryolar yalniz COMPREHENSIVE
  modda `certificateChain[].revocation` alt nesneleriyle ifsa ediliyordu.
  Yeni alan `SignatureInfo.chainRevocationStatus` her iki modda dolar; tek
  bir enum string ile tuketicinin zincirin geneline dair tek bakista dogru
  karari vermesini saglar. Detay icin yine `level=COMPREHENSIVE` gerekir.
  - Yeni enum: `ChainRevocationStatus` (`models/enums` paketinde) — 5 deger:
    - `ALL_GOOD` — leaf + tum ara CA'lar GOOD.
    - `LEAF_REVOKED` — leaf REVOKED (CA durumuna bakilmaz, en kritik sinyal).
    - `LEAF_GOOD_CA_REVOKED` — leaf GOOD ama bir ara CA REVOKED. `signer-strict`
      profilinde imza yine `valid: true` (CA icin `NotRevoked=WARN`); `strict`
      profilinde `valid: false` + `REVOKED_CA_NO_POE` sub-indication.
    - `UNKNOWN` — leaf UNKNOWN, ya da leaf GOOD ama zincirde UNKNOWN var.
    - `NOT_CHECKED` — hicbir cert icin revocation kontrolu yapilmadi
      (cevrimdisi mod, B-level imza, responder hep down).
  - Oncellendirme: leaf REVOKED > leaf UNKNOWN > CA REVOKED > CA UNKNOWN
    > ALL_GOOD. Leaf'in durumu CA'dan once kazanir — guvenlik-first.
  - Yeni metod: `RevocationInfoExtractor.computeChainStatus(List<CertificateWrapper>)`
    — DSS DiagnosticData zinciri uzerinden enum'u hesaplar. Root cert icin
    DSS revocation token uretmedigi (`null`) durumda sessizce atlar.
  - `AdvancedSignatureVerificationService.populateSignatureInfo(...)` her
    iki modda da bu metodu cagiriyor — SIMPLE'da da gorunur.
  - 14 yeni unit test: `RevocationInfoExtractorTest` (10 yeni — `computeChainStatus`
    icin null/empty, ALL_GOOD, LEAF_REVOKED, leaf UNKNOWN > CA REVOKED,
    LEAF_GOOD_CA_REVOKED, leaf GOOD + CA UNKNOWN, leaf missing + CA var,
    nothing checked, CA REVOKED > CA UNKNOWN, tek elemanli zincir),
    `SignatureInfoTest` (4 yeni — setter/getter round-trip, null default,
    JSON enum adi, NON_NULL omit).
  - **Onemli kavramsal not**: Bu alan dogrulama kararini DEGISTIRMEZ.
    DSS policy zincirin tamamini `SigningCertificate` + `CACertificate`
    bloklari uzerinden kendi kurallari cercevesinde kontrol eder.
    `chainRevocationStatus` yalniz UI/audit gorunurlugu icin bir ozet
    sinyal — `signatures[].valid` hep DSS policy karariyla belirlenir.

- **OCSP/CRL sonuclari artik response'a yansiyor** (`signerCertificate.revocation`
  + `tsaCertificate.revocation`):
  Daha once `CertificateInfo.revoked` hardcoded `false`, `revocationReason` /
  `revocationDate` / `revocationTime` hicbir zaman set edilmiyordu —
  REVOKED bir sertifika icin bile response'da `"revoked": false` goruluyordu.
  Yeni davranis: DSS DiagnosticData'daki revocation token'larindan en uygun
  olani secilip zengin bir `RevocationInfo` alt nesnesi olarak response'a
  eklenir; geriye donuk alanlar (`revoked`, `revocationReason`,
  `revocationDate`, `revocationTime`) da gercek degerle dolar.
  - Yeni model: `RevocationInfo` (`@JsonInclude(NON_NULL)`); alanlar
    `source` (OCSP|CRL), `status` (GOOD|REVOKED|UNKNOWN), `revocationDate`,
    `revocationReason`, `producedAt`, `thisUpdate`, `nextUpdate`,
    `responderUrl`, `origin` (EXTERNAL|CACHED|REVOCATION_VALUES|...).
  - Yeni alan: `CertificateInfo.revocation`. Revocation token hic yoksa
    (`null`) JSON'a dusmez — `@JsonInclude(NON_NULL)` ile sessiz omit.
  - Yeni component: `RevocationInfoExtractor` (`services/util` paketinde).
    SRP gozeterek `AdvancedSignatureVerificationService`'ten ayri tutuldu;
    REVOKED varsa onu, yoksa en guncel `productionDate`'li token'i secer
    (security-first policy). Tum DSS exception'lari defensive yutulur.
    - `extractFor(CertificateWrapper)` — DSS DiagnosticData'dan extraction
      (imza dogrulama akisi).
    - `fromToken(RevocationToken<?>)` — ham OCSP/CRL token'larindan
      extraction (standalone timestamp dogrulama akisi). Generic API:
      hem OCSPToken hem CRLToken icin tek arayuz.
    - `isNotRevoked(CertificateWrapper)` — `ValidationDetails` icin
      hizli kontrol.
  - Origin bilgisi LT-level imzalarda gomulu revocation'i ayirt etmeyi
    saglar: `EXTERNAL` = canli sorgu, `CACHED` = Caffeine hit,
    `REVOCATION_VALUES` / `CMS_SIGNED_DATA` = imzanin icinde gomulu kanit.
  - `ValidationDetails.certificateNotRevoked` artik hardcoded `true` degil;
    DSS DiagnosticData'dan gercek durum okunur. Cevrimdisi mod / revocation
    verisi yok durumunda `true` doner (strict policy bunu zaten
    `RevocationDataAvailable=FAIL` ile yakalar).
  - **Timestamp dogrulama akisinda da simetri**:
    - `AdvancedTimestampVerificationService.checkRevocation(...)` artik
      sorgu sonucundaki OCSPToken/CRLToken'i `RevocationInfo`'ya cevirip
      `RevocationCheckResult.revocationInfo`'ya koyar; caller bunu
      `applyRevocationToCertInfo(certInfo, info)` static helper'i ile TSA
      sertifika response'una yansitir. Eskiden `tsaCertificate.revoked`
      hardcoded `false` goruluyordu — artik gercek durum.
    - `TimestampVerificationService` (basit `/timestamp/verify` endpoint)
      eskiden TSA cert icin hicbir revocation kontrolu yapmiyordu; artik
      `online-validation-enabled=true` iken OCSP/CRL'i sorgulayip ayni
      `applyRevocationToCertInfo(...)` ile TSA cert info'sunu zenginlestiriyor.
      Online validation kapaliysa eski davranis korunur.
  - 27 yeni unit test: `RevocationInfoTest` (6), `CertificateInfoRevocationTest`
    (4), `RevocationInfoExtractorTest` (17 — `extractFor` icin 10 + `fromToken`
    icin 7 senaryo: GOOD/REVOKED/UNKNOWN, OCSP/CRL, alan-bazli exception
    toleransi, bos sourceURL, subtyping), `AdvancedTimestampVerificationServiceTest`
    (5 — `applyRevocationToCertInfo` static helper'inin GOOD/REVOKED/UNKNOWN
    /null davranisi).

- **Revocation retry — anlik flake toleransi (strict-safe)**:
  Strict policy (signer-strict / strict) revocation verisini ZORUNLU
  isaretler; tek bir KamuSM 503 / connection reset / TLS glitch gecerli
  bir e-Faturayi <code>INDETERMINATE/NO_REVOCATION_DATA</code>'ya
  dusururdu. Yeni decorator katmani anlik flake'i gercek kesintilerden
  ayirir — anlik flake'te retry basarili, gercek kesintide tum retry
  tukenince hala FAIL doner (yani "iptal mi belli degil"i asla VALID
  gostermez).
  - Yeni sinif: `RetryPolicy` — immutable deger nesnesi. Field invariant'i
    constructor'da fail-fast: <code>maxAttempts >= 1</code>,
    <code>maxBackoffMs >= initialBackoffMs</code>,
    <code>backoffMultiplier >= 1.0</code>,
    <code>0 <= jitterRatio <= 1.0</code>.
  - Yeni interface: `Sleeper` — `Thread.sleep` abstraction'i (test
    deterministik kalsin diye); production'da `Sleeper.threadSleep()`.
  - Yeni sinif: `RetryExecutor` — generic exponential backoff + jitter
    runner. Davranis sozlesmesi: supplier `null` donerse retry YAPILMAZ
    (transient degil); `RuntimeException` firlatirsa policy tukene kadar
    dener, son exception caller'a yeniden firlatilir. Sleep sirasinda
    `InterruptedException` -> interrupt flag restore + retry'larin
    agresif sonlanmasi.
  - Yeni decorator: `RetryingOCSPSource implements OCSPSource` —
    `OnlineOCSPSource` ile `LoggingCachingOCSPSource` arasinda konumlanir
    (cache hit retry'a girmez, sadece HTTP fetch hatalarinda devreye girer).
  - Yeni decorator: `RetryingCRLSource implements CRLSource` — ayni mantik.
  - Wiring: `RevocationServicesConfiguration` buildRetryPolicy()
    helper'i ile config'i policy'ye cevirir. `policy.maxAttempts > 1`
    ise decorator devreye girer, aksi halde direkt online source.
    Decorator sirasi: `Online -> Retrying -> LoggingCaching ->
    CertificateVerifier`.
  - 6 yeni parametre (tamami env var ile override edilebilir):
    - `verification.revocation.retry.enabled` (default `true`)
    - `verification.revocation.retry.max-attempts` (default `3`)
    - `verification.revocation.retry.initial-backoff-ms` (default `200`)
    - `verification.revocation.retry.max-backoff-ms` (default `2000`)
    - `verification.revocation.retry.backoff-multiplier` (default `2.0`)
    - `verification.revocation.retry.jitter-ratio` (default `0.2`)
  - 30 yeni unit test: `RetryPolicyTest` (10), `RetryExecutorTest` (9),
    `RetryingOCSPSourceTest` (6), `RetryingCRLSourceTest` (5).
    Mock'lanan `Sleeper` ile retry sayilarini, sleep progression'unu
    ve interrupt davranisini saniyelerce yavaslamadan dogruluyoruz.
  - Worst-case latency hesabi (audit icin): bir token icin
    `maxAttempts * httpTimeout + Σ backoffs`. Default'larla
    `3 * 10s + (0.2s + 0.4s) ~ 30.6s`. Tipik flake yalniz 0.2-0.4s ekler.

- **Revocation cache observability — Prometheus metrics**:
  `LoggingCachingOCSPSource` ve `LoggingCachingCRLSource` icindeki Caffeine
  cache instance'lari artik Spring Boot Actuator uzerinden Prometheus'a
  publish ediliyor. `/actuator/prometheus` endpoint'inde gorunen metric
  aileleri (her ikisi de hem `mersel.revocation.ocsp` hem
  `mersel.revocation.crl` tag'iyle ayni anda):
  - `cache_size` — anlik cache entry sayisi.
  - `cache_gets_total{result="hit"|"miss"}` — fetch istegi sayilari;
    hit-rate buradan turetilir.
  - `cache_puts_total` — cache'e girilen response sayisi (REVOKED/GOOD;
    UNKNOWN ve null bilincli olarak cache'lenmez).
  - `cache_evictions_total` — TTL veya size limit kaynakli evict sayisi.
  - Operatorel kullanim: KamuSM responder yavasligini izlemek icin
    `rate(cache_gets_total{result="miss"}[5m])`; gercek HTTP yuku icin
    `rate(cache_puts_total[1h])`.
  - Implementasyon: `RevocationServicesConfiguration` bean yaratimi
    sirasinda `CaffeineCacheMetrics.monitor(registry, cache, name)` cagrisi
    yapiyor. {@link io.micrometer.core.instrument.MeterRegistry}
    `ObjectProvider` ile inject ediliyor — graceful degradation: registry
    yoksa (orn. minimal test slice) metric kaydi atlanir, cache calismaya
    devam eder.
  - Wrapper'lara minimal eklenti: `public Cache<String, ?> caffeineCache()`
    accessor — Spring tarafinda metric binding icin; Micrometer bagimliligi
    bilincli olarak wrapper'a sizmaz (dependency yonu tek istikamette).

### Fixed
- **Sertifika iptal durumu response'a yansimiyordu** (kritik audit/compliance
  bug'i): `AdvancedSignatureVerificationService.extractCertificateInfo(...)`
  icindeki <code>boolean isRevoked = false; // DSS 6.3'te revocation bilgisi
  farkli sekilde aliniyor</code> hardcoded'u ve
  `createComprehensiveValidationDetails` icindeki <code>setCertificateNotRevoked(true);
  // DSS 6.3'te farkli kontrol</code> hardcoded'u temizlendi. Imzanin
  `valid` field'i zaten DSS policy tarafindan dogru raporlaniyordu (REVOKED
  sertifikalar `INDETERMINATE` veya `TOTAL_FAILED` doneriyordu), ancak
  `signerCertificate.revoked`, `revocationReason`, `revocationDate`,
  `validationDetails.certificateNotRevoked` alanlari hep "iptal degil"
  goruluyordu — UI ve audit tooling'i yaniltici. Artik tum bu alanlar DSS
  DiagnosticData'dan dogru sekilde dolduruluyor.
- **`CertificateInfoExtractor` icinde yaniltici hardcoded `setRevoked(false)`
  satiri temizlendi**: Bu extractor ham `CertificateToken`'dan calisir ve
  DSS DiagnosticData yoktur; revocation bilgisi uretemez. Eski kodda hardcoded
  `false` set ediliyordu — caller bunu override etmediyse REVOKED bir TSA cert
  bile "iptal degil" goruluyordu. Artik bu satir kaldirildi (primitive boolean
  default'u olan `false` zaten korunur), revocation alanlarinin set edilmesi
  sorumlulugu caller'a (timestamp dogrulama akisina) verildi.
- **Davranis degisikligi — `CertificateInfo.valid` artik revocation'i da hesaba
  katar**: Eskiden `valid = !expired` formulu kullaniliyordu (`isRevoked` hep
  hardcoded `false` oldugu icin). Yeni formul: `valid = !expired && !revoked`.
  Pratik sonuc: suresi gecmemis fakat REVOKED bir sertifika eskiden
  `valid: true` raporlaniyordu, artik `valid: false` doner. Bu davranissal
  dogru hareket; sadece API tuketicileri eski yanilgiya gore ozel bir
  ozumleme yaptilarsa fark edebilir.

## [0.3.1] - 2026-05-23

### Added
- **XAdES paketleme tipi raporlamasi** (`SignatureInfo.signaturePackaging`):
  Her XAdES imzasi icin paketleme tipi W3C XMLDSig terminolojisiyle
  raporlaniyor — `ENVELOPED` (imza belgenin icinde, UBL e-Fatura kalibi),
  `ENVELOPING` (data `ds:Object` icinde) veya `DETACHED` (data ayri). DSS
  6.3 bu bilgiyi verification akisinda hicbir reports/diagnostic alaninda
  expose etmiyor (sadece imza URETIRKEN parametre aliyor); biz DOM
  seviyesinde `ds:SignedInfo/ds:Reference` yapisini okuyarak tespit
  ediyoruz.
  - Yeni enum: `SignaturePackaging` — sabit isimleri DSS upstream
    `eu.europa.esig.dss.enumerations.SignaturePackaging` ile birebir ayni
    (istemcide mapping katmani gerekmez).
  - Yeni utility: `XadesSignaturePackagingDetector` — tip-bazli,
    sira-bagimsiz algoritma. `Reference.Type` attribute'una gore meta
    referanslari (SignedProperties, KeyInfo/X509Data, KamuSM legacy
    `…/v1.3.2/XAdES.xsd#SignedProperties` varyanti dahil) paketleme
    kararindan disliyor, kalan data ref(ler)i icin
    `enveloped-signature` transform / bos URI / `#objId` -> internal
    `ds:Object` ayrimini yapiyor.
  - `AdvancedSignatureVerificationService` wiring: validator'dan
    `AdvancedSignature` listesi alinip her imza icin paketleme
    hesaplaniyor; `signatureId -> packaging` map'i `processSignature`'a
    aktariliyor. CAdES/PAdES icin alan `null` -> `@JsonInclude(NON_NULL)`
    sayesinde JSON'a dusmuyor.
  - Best-effort: DOM tespit hatasi verification akisini bloklamaz, WARN
    log dusup paketleme alani null geri doner.
  - 13 unit test (`XadesSignaturePackagingDetectorTest`): TUBITAK BES
    sirasi (SignedProperties once), DSS-orijinal sirasi (data once),
    URI=#objId iC ds:Object, external URI, AXA SIGORTA e-Fatura
    ApplicationResponse regresyon testi, KamuSM legacy SignedProperties
    Type URI meta-filtreleme, UnsignedSignatureProperties altindaki
    nested Reference'larin yoksayilmasi.
  - 4 unit test (`SignatureInfoTest`): setter/getter round-trip, null
    default, JSON enum sabit-adi serializasyonu, `NON_NULL` davranisi.
  - 2 unit test (`SignaturePackagingTest`): enum sabit isimleri W3C/DSS
    upstream uyumu, arity guard.
- **Applied Suppressions / audit trail**: Mersel DSS Verifier'in DSS karari
  uzerine *override* uyguladigi her durum artik response icinde yapilandirilmis
  olarak raporlaniyor. Yeni `signatures[i].appliedSuppressions` alani:
  - `code` — kararli, public API kontrati olan tanimlayici (ornek:
    `MDSS-XADES-LEGACY-TR-TYPE-URI`).
  - `title`, `reason`, `severity` (`INFO` / `WARN` / `CRITICAL`).
  - `originalIndication`, `originalSubIndication` — DSS'in *gercek* karari
    (override oncesi). "DSS aslinda ne demisti, biz ne yaptik" sorusuna kesin
    cevap; audit/compliance icin kritik.
  - `evidence` — override'i tetikleyen somut delil (free-form key/value;
    her kod icin sema farklilasir).
  - `docsUrl` — GitHub repo altinda `docs/suppressions/<CODE>.md` dosyasina
    isaret eder; operatore tek tikla detayli sebep + tolerans kurali +
    severity gerekcesi + kapatma yonergesi.
  - Yeni model siniflari: `AppliedSuppression`, `SuppressionCode` (enum;
    naming: `MDSS-{LAYER}-{DESCRIPTIVE-SLUG}`).
  - Ilk kayitli kod: `MDSS-XADES-LEGACY-TR-TYPE-URI` — TR-legacy XAdES
    SignedProperties Type URI toleransinda otomatik atanir.
  - 6 unit test (`AppliedSuppressionTest`): naming convention guard,
    kararli code string'leri, JSON serializasyon, `@JsonInclude(NON_NULL)`
    davranisi, immutable `evidence` map'i.
- **Suppression dokumantasyon klasoru**: [`docs/suppressions/`](docs/suppressions/)
  altinda her kayitli kod icin detayli MD sayfasi.
  - [`docs/suppressions/README.md`](docs/suppressions/README.md) — index +
    naming convention + kararlilik + severity rehberi + contributors guide.
  - [`docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md`](docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md)
    — TR-legacy XAdES Type URI toleransinin tam dokumani: sorun aciklamasi,
    6 tetik kosulu, sonuc tablosu, ornek audit kaydi, risk degerlendirmesi.

### Changed
- `validationWarnings` icindeki TR-toleransi mesajinin onune kod prefix'i
  eklendi (ornek: `[MDSS-XADES-LEGACY-TR-TYPE-URI] ...`); operatorler log
  uzerinde grep edebilir.
- `AdvancedSignatureVerificationService.applyTrLegacyXadesToleranceIfApplicable`
  artik `evaluateTrLegacyXadesTolerance` adina sahip; boolean yerine
  `AppliedSuppression` dondurur ki audit kaydi tek noktadan uretilsin.

## [0.3.0] - 2026-05-22

### Added
- **TR-Legacy XAdES SignedProperties Type URI toleransi**: KamuSM / GIB
  ekosistemindeki bazi imzalama araclari, XAdES `Reference` Type URI'sini
  standart disi yaziyor (ornek: `http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties`,
  standartta olmasi gereken `http://uri.etsi.org/01903#SignedProperties`).
  Eclipse DSS spec'e harfiyen uydugu icin bu imzalari `INDETERMINATE /
  SIG_CONSTRAINTS_FAILURE` ile reddederken, TUBITAK Imzager ve KamuSM tarafi
  bu imzalari kabul ediyor. Bu surumden itibaren Mersel DSS Verifier de —
  kriptografik butunluk dogruysa — bu Turkiye-ozel uretici hatasini affediyor.
  - Yeni utility: `LegacyTurkishXadesTypeUriDetector` (byte-level pattern
    matching, jenerik bir SIG_CONSTRAINTS bypass'i degil; `01903 + .xsd +
    #SignedProperties` paterni dis,inda hicbir SIG_CONSTRAINTS_FAILURE turunu
    affetmez).
  - `AdvancedSignatureVerificationService.processSignature(...)`: tolerans
    altI kosulun tumu saglandiginda devreye girer (config flag, indication,
    subIndication, `signatureIntact && signatureValid`, BBB SAV'da yalniz
    `BBB_SAV_ISQPMDOSPP` FAIL, XML'de patern eslesmesi).
  - Override edildiginde DSS'in `INDETERMINATE` indication'i `TOTAL_PASSED`'e
    yukseltilir, `validationErrors` yerine acik bir `validationWarnings` mesaji
    olusturulur, `verification.log`'a olay tek satirda kaydedilir.
  - 11 unit test (`LegacyTurkishXadesTypeUriDetectorTest`): standart URI'ler
    (xades111, xades122, xades132), case insensitive Reference/Type/prefix
    varyasyonlari, Turkce karakter encoding, false-positive trap'leri.
- Konfigurasyon flag'i: `verification.tr-legacy-xades-tolerance-enabled`
  - ENV var: `TR_LEGACY_XADES_TOLERANCE` (default `true`).
  - Default `true` olmasinin nedeni: bu API zaten Turkiye ekosistemi icin
    uretildi; TUBITAK Imzager paralelinde davranmasi onceliklidir.
  - eIDAS-QES paralelinde davranmak isteyen kurumsal operatorler `false`
    yaparak DSS'in stricte davranisina geri donebilir.

### Changed
- `AdvancedSignatureVerificationService.collectErrorsAndWarnings(...)` artik
  TR-toleransi farkindadir; toleransli imzalarda `validationErrors` listesini
  bos birakir, sebebi `validationWarnings`'e operatore yonelik dille yazar.
- `VerificationConfiguration` sinifina `trLegacyXadesToleranceEnabled` getter/
  setter ve detayli javadoc eklendi.

## [0.2.1] - 2026-05-22

### Added
- GIB / TUBITAK Mali Muhur v3 imzali XAdES dokumanlarinin DSS uzerinde
  dogrulanabilmesi icin `EcdsaXmlSignaturePreprocessor` eklendi. ASN.1
  DER-encoded ECDSA `SignatureValue`'larini W3C XMLDSig raw `r||s` formatina
  donusturur; SignedInfo digest'leri korunur.
- 11 CI-safe unit test (`EcdsaXmlSignaturePreprocessorTest`): BouncyCastle ile
  runtime synthetic fixture uretir, hicbir external dosyaya bagimli degildir.
- Emergency kill-switch: `verification.ecdsa-der-preprocessor-enabled` (default `true`).
- Release surec altyapisi:
  - `scripts/release.sh` (lokal release hazirlama)
  - `scripts/bump-version.sh` (SemVer bump)
  - `scripts/extract-release-notes.sh` (CHANGELOG bolum cikartici)
  - `scripts/build-release-notes.sh` (release notes + provenance)
  - `scripts/check-changelog-updated.sh` (PR guard)
  - `.github/workflows/release.yml` (immutable GitHub Release pipeline)
  - `.github/workflows/changelog-check.yml` (PR-time CHANGELOG kontrolu)
  - `docs/RELEASE_PROCESS.md` (release dokumantasyonu)
- `pom.xml`'e build provenance plugin'leri:
  - `maven-jar-plugin` manifestEntries (Implementation-*, Build-*, X-Mersel-*)
  - `spring-boot-maven-plugin` build-info goal (-> /actuator/info)
  - `maven-source-plugin` (sources.jar)
  - `cyclonedx-maven-plugin` 2.8.0 (CycloneDX 1.5 SBOM)
  - `project.build.outputTimestamp` (reproducible builds Maven 3.6.1+)

### Changed
- `AdvancedSignatureVerificationService` ve `SignatureVerificationService`:
  XML byte'larini DSS'e gecmeden once `EcdsaXmlSignaturePreprocessor`'dan
  gecirir; preprocessor sertifika EC degilse veya gerekli kosullar saglanmazsa
  no-op doner.

---

## [0.2.0] - 2026-05-17

### Added
- **DSS 6.3 CAdES backend**: `dss-cms-object` modülü `pom.xml`'e eklendi.
  DSS 6.3'ten itibaren `dss-cades` artık `ICMSUtils` için runtime
  implementasyonu gerektiriyor; eksikse CAdES doğrulaması 500 +
  `"No implementation found for ICMSUtils in classpath"` ile patlıyordu.
- **DSS 6.3 PAdES backend**: `dss-pades-pdfbox` modülü eklendi ve
  `pdfbox` 2.0.24 → **3.0.5** yükseltildi. Eski pdfbox'la PAdES doğrulaması
  `NoSuchFieldError: streamCache` runtime hatası veriyordu.
- **Production-grade validation policy mimarisi**: KamuSM/Mali Mühür için
  iki built-in profil + tam custom override desteği.
    - `policy/kamusm-signer-strict-constraint.xml` — **DEFAULT**:
      İmzacı sertifika için OCSP/CRL **FAIL** (iptal kontrolü zorunlu),
      ara CA için **WARN** (kısa kesintilerde valid e-Faturalar
      INDETERMINATE'e düşmesin), TS signing cert için **WARN** (TSA iptali
      nadirdir). Mali Mühür üretim default'u.
    - `policy/kamusm-strict-constraint.xml` — eIDAS-QES paraleli:
      İmzacı + ara CA + TS signer için **FAIL**. Online OCSP/CRL altyapısı
      kesintisiz çalışan ortamlar için maksimum güvenlik profili.
    - `dss.policy.profile=signer-strict|strict` ile profil seçimi
      (env: `DSS_POLICY_PROFILE`).
    - `dss.policy.path=file:|classpath:|http(s):` ile tam custom XML
      (env: `DSS_POLICY_PATH`). Set edilirse `profile` ignore edilir.
      Production'da typical: `file:/etc/mersel-dss-verify/policy.xml`
      (k8s ConfigMap/Secret ile mount).
    - Policy XML'leri DSS native `SigningCertificate` / `CACertificate` /
      `Timestamp.SigningCertificate` node'larıyla **CA, ara, imzacı**
      katmanları için ayrı davranış geçilebilir biçimde yapılandırıldı.
- **CertificateInfo.trusted alanı doldurulmaya başlandı**: önceki
  versiyonda her sertifika için `trusted=false` dönüyordu; DSS diagnostic
  data'sının `CertificateWrapper.isTrusted()` çıktısı DTO'ya yansıtıldı.

### Changed
- `AdvancedSignatureVerificationService.openValidationPolicyStream()` artık
  **fail-fast**: explicit verilen `dss.policy.path` erişilemezse
  `VerificationException` atar (sessiz DSS default'a düşmek prod riski).
  Built-in profil XML'i jar'da yoksa da fail-fast — sadece "bilinmeyen
  profil ismi" verildiğinde default profile düşülür ve **WARN** loglanır.
- `AdvancedSignatureVerificationService.validateDocument(...)` policy
  stream'i try-with-resources ile yönetiyor.
- Startup'ta `@PostConstruct` sanity check: profil + `online-validation-enabled`
  kombinasyonu çelişkiliyse (örn. signer-strict + online=false) yüksek
  sesle uyarır — operatörün dikkatini çeker, davranışı değiştirmez.
- `ValidationReportLogger.logDetailedReport` çağrısı `INFO` yerine
  `DEBUG` seviyesinde (gürültü engellendi; ihtiyaç olduğunda logback
  level=DEBUG ile açılır).

### Removed
- **`policy/kamusm-permissive-constraint.xml`** kaldırıldı. Her katmanda
  revocation kontrollerini WARN'a indirmek production senaryosu için
  güvenli bir default değildi (iptal edilmiş imzacı sertifikalar "valid"
  görünebilirdi). Test ortamları kendi `dss.policy.path`'lerini mount
  etmeli (örn. `mersel-dss-signer-api-java` test container'ı bunu yapıyor).
- **`VERIFICATION_POLICY=STRICT|RELAXED` property** kaldırıldı.
  `VerificationConfiguration.verificationPolicy` field/getter'ı vardı ama
  hiçbir karar akışında okunmuyordu — operatör `RELAXED` yapsa bile
  davranış değişmiyordu. **Sessiz no-op'lar yanıltıcı**: kaldırıldı.
  DSS validation davranışı `dss.policy.profile` (signer-strict|strict) +
  `dss.policy.path` (custom XML override) ile yönetilir; rapor seviyesi
  katılık için `verification.strict-mode` (ENV: `VERIFICATION_STRICT_MODE`)
  kullanılmaya devam edilir. application-test.properties ve README'den
  de referanslar temizlendi.

### Fixed
- **`AdvancedSignatureVerificationService.createComprehensiveValidationDetails`**:
  `details.setCertificateChainValid(!signatureWrapper.isSignatureIntact())`
  çağrısı açık bir typo'ydu (imza sağlamsa zincir invalid mantığı).
  Doğru kaynak `signatureWrapper.isTrustedChain()`.

### Known limitations
- `dss.policy.path` Spring Resource paterni kullanır
  (`classpath:`, `file:`, `http(s):`); kompleks URI rewrite/auth header
  yapıları için ek adapter yazılmalı.
- pdfbox 3.x JDK 8 ile çalışır ama JPMS modüllerine geçen projeler için
  upgrade path ayrıca planlanmalı.

---

## [0.1.0] - 2026-03-11

### Added
- Ilk release.

---

> **Versioning & Kategori rehberi:** [docs/RELEASE_PROCESS.md](docs/RELEASE_PROCESS.md).
