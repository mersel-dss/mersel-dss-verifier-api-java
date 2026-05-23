# Changelog

Tum onemli degisiklikler bu dosyada dokumante edilmektedir.

Format [Keep a Changelog 1.0.0](https://keepachangelog.com/en/1.0.0/) standardina dayanir,
ve bu proje [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) kullanir.

## [Unreleased]

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
