# Changelog

Tum onemli degisiklikler bu dosyada dokumante edilmektedir.

Format [Keep a Changelog 1.0.0](https://keepachangelog.com/en/1.0.0/) standardina dayanir,
ve bu proje [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) kullanir.

## [Unreleased]

### Added
- **`chainRevocationStatus` — SIMPLE modda da zincir geneli ozet**:
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
