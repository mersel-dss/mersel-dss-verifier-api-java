package io.mersel.dss.verify.api.config;

import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Dogrulama servisi konfigurasyonu
 */
@Configuration
public class VerificationConfiguration {

    @Value("${verification.certstore.path:}")
    private String certStorePath;

    @Value("${verification.certstore.password:}")
    private String certStorePassword;

    @Value("${verification.custom-root-cert-path:}")
    private String customRootCertPath;

    @Value("${verification.online-validation-enabled:true}")
    private boolean onlineValidationEnabled;

    @Value("${verification.trusted-tsa-certificates:}")
    private String trustedTsaCertificates;

    // NOT: Eski `VERIFICATION_POLICY=STRICT|RELAXED` property kaldırıldı.
    // Hiçbir karar akışında okunmuyor, sessiz no-op olarak operatörleri
    // yanıltıyordu. DSS validation davranışı artık `dss.policy.profile`
    // (signer-strict|strict) + `dss.policy.path` (custom XML override)
    // üzerinden yönetilir (bkz. AdvancedSignatureVerificationService).
    // Rapor seviyesi katılık için `verification.strict-mode` aşağıda kalır
    // — DSS DiagnosticData üzerinde subIndication/validationErrors gibi
    // sinyalleri "valid mi değil mi" kararına nasıl yansıttığımızı kontrol
    // eder; DSS policy XML'i ile ortogonal bir kavramdır.

    @Value("${CERT_CACHE_TTL:3600}")
    private int certCacheTtl;

    /**
     * <strong>Eski property — geriye donuk uyumluluk icin korunuyor.</strong>
     * Yeni revocation cache sistemi {@code verification.revocation.cache.ttl-seconds}
     * property'sini kullanir; {@code CRL_CACHE_TTL} oraya default deger besler.
     */
    @Value("${CRL_CACHE_TTL:3600}")
    private int crlCacheTtl;

    @Value("${verification.strict-mode:true}")
    private boolean strictMode;

    // --- Revocation (OCSP/CRL) cache + HTTP timeout konfigurasyonu ---
    // Bu property'ler RevocationServicesConfiguration tarafindan tuketilir;
    // wrapper'lar (LoggingCachingOCSPSource / LoggingCachingCRLSource) buradaki
    // degerlere gore Caffeine cache + HTTP timeout'larini kurar.

    /**
     * Cache'te tutulacak maksimum revocation token sayisi (OCSP ve CRL ayri
     * cache'ler). KamuSM ekosisteminde aktif Mali Muhur sayisi dusuk
     * oldugu icin 10K cok rahat yeter; bellek baski yapmadan haftalarca
     * calisabilir.
     */
    @Value("${verification.revocation.cache.max-size:10000}")
    private long revocationCacheMaxSize;

    /**
     * Default cache TTL (saniye). Token'in kendi {@code nextUpdate} alani
     * varsa ondan kucuk olani secilir; <strong>bu deger ust sinirdir</strong>.
     * Geriye donuk uyumluluk: belirtilmezse {@code CRL_CACHE_TTL} kullanilir.
     */
    @Value("${verification.revocation.cache.ttl-seconds:${CRL_CACHE_TTL:3600}}")
    private long revocationCacheTtlSeconds;

    /**
     * HTTP connection timeout (ms) — OCSP responder veya CRL distribution
     * point'e baglanma asamasi icin. Default 10s; KamuSM iclerinde yavas
     * cevap veren ucler oldugu icin (TS depo) cok dusuk tutmuyoruz.
     */
    @Value("${verification.revocation.http.connection-timeout-ms:10000}")
    private int revocationHttpConnectionTimeoutMs;

    /**
     * HTTP socket (read) timeout (ms) — response gelmeye basladiktan sonra
     * iki paket arasinda beklenecek azami sure. CRL'ler MB seviyesine
     * cikabildigi icin yine 10s.
     */
    @Value("${verification.revocation.http.socket-timeout-ms:10000}")
    private int revocationHttpSocketTimeoutMs;

    // --- Revocation Retry (OCSP/CRL transient hata toleransi) ---
    // Strict policy revocation verisi ZORUNLU oldugundan tek bir transient
    // hata (KamuSM 503, connection reset, TLS handshake glitch) gecerli bir
    // imzayi INDETERMINATE'a dusurur. Retry bu flake'leri gercek kesintilerden
    // ayirir: anlik hata -> imza valid, gercek kesinti -> hala FAIL.
    //
    // Algoritma: exponential backoff + jitter.
    //   delay(n) = min(initialBackoff * multiplier^(n-1), maxBackoff)
    //   sleepMs  = delay * (1 + uniform(-jitter, +jitter))

    /**
     * Retry mekanizmasinin master switch'i. <code>false</code> yapilirsa
     * {@code maxAttempts=1} olarak davranilir (sadece ilk deneme).
     * Default <strong>acik</strong> — uretimde flake toleransi standarttir.
     */
    @Value("${verification.revocation.retry.enabled:true}")
    private boolean revocationRetryEnabled;

    /**
     * Toplam deneme sayisi. <code>1</code> = retry yok; <code>3</code> = 1 ilk
     * deneme + 2 retry. KamuSM enpoint'lerine DDoS yapmamak icin sayiyi
     * dusuk tutuyoruz; 5+ retry default kabul edilmez.
     */
    @Value("${verification.revocation.retry.max-attempts:3}")
    private int revocationRetryMaxAttempts;

    /**
     * Ilk retry oncesi temel bekleme suresi (ms). KamuSM 503'leri tipik
     * 200ms-1s aralikta cozulur; 200ms hizli ama yumusak baslangic.
     */
    @Value("${verification.revocation.retry.initial-backoff-ms:200}")
    private long revocationRetryInitialBackoffMs;

    /**
     * Backoff ust siniri (ms). Exponential growth bu degere clamp'lenir;
     * 2s default — bir imza icin total worst-case ~30s civari kalir
     * (3 attempt × 10s HTTP timeout + 200ms+400ms backoff).
     */
    @Value("${verification.revocation.retry.max-backoff-ms:2000}")
    private long revocationRetryMaxBackoffMs;

    /**
     * Her retry'da onceki backoff'un &ccedil;arpani.
     * <code>1.0</code> = sabit backoff; <code>2.0</code> = ikiye katla (default).
     */
    @Value("${verification.revocation.retry.backoff-multiplier:2.0}")
    private double revocationRetryBackoffMultiplier;

    /**
     * Jitter orani — <code>±jitterRatio</code> rastgele varyasyon
     * (uniform). <code>0.2</code> = ±%20. Thundering herd onleme icin
     * standart best-practice; 0.0 yapilirsa retry'lar tam saatte tetiklenir
     * ve ayni anda dusen N istemci endpoint'i tekrar bombalayabilir.
     */
    @Value("${verification.revocation.retry.jitter-ratio:0.2}")
    private double revocationRetryJitterRatio;

    /**
     * GİB / TÜBİTAK Mali Mühür DER-encoded ECDSA SignatureValue'sini
     * W3C XMLDSig raw r||s formatına dönüştüren preprocessor'ın aktif/pasif kontrolü.
     * Emergency kill-switch: <code>false</code> yapılırsa hiç bir XML dokümanına
     * dokunulmaz (DSS sıkı W3C davranışına geri döner).
     */
    @Value("${verification.ecdsa-der-preprocessor-enabled:true}")
    private boolean ecdsaDerPreprocessorEnabled;

    /**
     * <b>Türkiye-özel XAdES SignedProperties Type URI toleransı.</b>
     *
     * <p>Pratik problem: KamuSM / GİB ekosisteminde yaygın bir grup eski
     * imzalama aracı, XAdES Reference Type URI'sini standart dışı yazıyor:</p>
     * <pre>
     *   Yanlış (üreticide görülen):  http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties
     *   Standart (ETSI 101 903):     http://uri.etsi.org/01903#SignedProperties
     * </pre>
     *
     * <p>Eclipse DSS spec'e harfiyen uyduğu için bu imzaları
     * <code>BBB_SAV_ISQPMDOSPP</code> ("ne message-digest ne SignedProperties
     * mevcut") ile reddeder ve <code>INDETERMINATE / SIG_CONSTRAINTS_FAILURE</code>
     * döndürür. Oysa TÜBİTAK İmzager ve KamuSM doğrulama servisleri bu
     * imzaları geçerli kabul ediyor — kriptografik olarak imza ZATEN sağlam,
     * yalnızca <code>Type</code> attribute'unda yazım hatası var.</p>
     *
     * <p><b>Aktifken davranış (gate v2 — universal allow-list)</b>:
     * Doğrulama sonrası inceleme sırasında şu <em>sekiz</em> koşul aranır;
     * herhangi biri eksik ise imza yine geçersiz raporlanır.</p>
     * <ol>
     *   <li>Indication = INDETERMINATE</li>
     *   <li>SubIndication explicit allow-set'te
     *       ({@code SIG_CONSTRAINTS_FAILURE} — diğerleri asla)</li>
     *   <li>DSS DiagnosticData'da
     *       <code>signatureWrapper.isSignatureIntact() == true</code>
     *       (kriptografik imza sağlam)</li>
     *   <li>DSS DiagnosticData'da
     *       <code>signatureWrapper.isSignatureValid() == true</code>
     *       (referans digest'leri eşleşiyor)</li>
     *   <li><b>Universal allow-list</b>: Tüm BBB bloklarında
     *       (FC/ISC/VCI/CV/SAV/XCV-top/SubXCV/PSV) gözlenen NOT_OK
     *       constraint key set'i {@code {BBB_SAV_ISQPMDOSPP}}'nin
     *       alt-kümesi olmalı (başka bir blokta tek bir FAIL bile
     *       gate'i kapatır; XCV/CV/FC/PSV vb. hiçbir gerçek hata
     *       affedilmez)</li>
     *   <li>Detector orijinal XML byte'larında Type URI patern eşleşmesi
     *       yakalıyor (P1 = <code>…XAdES.xsd…#SignedProperties</code>
     *       veya P2 = <code>v1.3.2/v1.4.1#SignedProperties</code>)</li>
     *   <li>Forensic audit — kararın gerekçesi
     *       {@link io.mersel.dss.verify.api.models.AppliedSuppression}
     *       altında: gate version, izinli/gözlenen FAIL key'leri,
     *       document SHA-256</li>
     * </ol>
     *
     * <p><em>Tarihsel not — re-validation katmanı:</em> v2.0/v2.1
     * sürümlerinde bu gate'in son adımı olarak bir "cryptographic
     * re-validation" katmanı vardı (Type URI normalize edilip XML DSS'e
     * yeniden veriliyordu). Tasarım hatasıydı çünkü Type URI
     * <code>&lt;ds:Reference&gt;</code> attribute olarak SignedInfo
     * bloğunda yer alır ve imza kapsamındadır; byte stream'inde
     * değiştirmek SignatureValue'yi geçersizleştirir ve re-validation
     * gerçek P1/P2 vakalarda her zaman <code>SIG_CRYPTO_FAILURE</code>
     * dönerdi. v2.2'de katman tamamen kaldırıldı; gate
     * "allow-list-only" mantığa düştü (yukarıdaki süzgeçler).</p>
     *
     * <p>Default <b>açık</b>: Mersel DSS Verifier zaten Türkiye ekosistemine
     * özgü bir doğrulayıcı. Operatör eIDAS-QES paralelinde davranmak isterse
     * <code>verification.tr-legacy-xades-tolerance-enabled=false</code> ile
     * kapatabilir.</p>
     */
    @Value("${verification.tr-legacy-xades-tolerance-enabled:true}")
    private boolean trLegacyXadesToleranceEnabled;

    /**
     * XAdES tek-referanslı imza patolojisi için rejection enrichment
     * (MISSING SignedProperties reference). DSS imzayı zaten INVALID döner;
     * bu flag yalnızca <em>tanı kanalını</em> kontrol eder: açıkken
     * detector patolojiyi tespit ederse {@link
     * io.mersel.dss.verify.api.models.AppliedRejection} objesi üretilip
     * {@link io.mersel.dss.verify.api.models.SignatureInfo#getAppliedRejections()}
     * altına yazılır; kapalıyken patoloji tespit edilse de obje üretilmez
     * ve DSS'in jenerik SIG_CONSTRAINTS_FAILURE'ı tek başına raporlanır.
     *
     * <p>Default <b>açık</b>: Mersel tanı kodlarının operatör tarafında
     * görünür olması ekosistem için fayda. Operatör bu enrichment'ı
     * istemiyorsa
     * <code>verification.tr-legacy-xades-rejection-enrichment-enabled=false</code>
     * ile kapatabilir; imzanın <code>valid=false</code> davranışı her
     * koşulda DSS akışından gelir, bu flag verdict'i değiştirmez.</p>
     */
    @Value("${verification.tr-legacy-xades-rejection-enrichment-enabled:true}")
    private boolean trLegacyXadesRejectionEnrichmentEnabled;

    /**
     * AIA (Authority Information Access) cache'i için maks giriş sayısı.
     * KamuSM ekosisteminde aktif ara CA sayısı çok düşük (≤20 endpoint);
     * 256 default haftalarca rahat yeter. Cache TTL içinde aynı CA Issuer
     * URL'ine ikinci kez gidilmesini engeller.
     */
    @Value("${verification.aia.cache.max-size:256}")
    private long aiaCacheMaxSize;

    /**
     * AIA cache TTL (saniye). Default 24 saat. Ara CA sertifikalarının
     * geçerlilik süresi yıllarca, dolayısıyla agresif cache tamamen güvenli;
     * yalnız "yeni ara CA fetched" log'unu çok sık görmemek için uzun TTL.
     */
    @Value("${verification.aia.cache.ttl-seconds:86400}")
    private long aiaCacheTtlSeconds;

    /**
     * <b>DSS i18n locale — doğrulama mesajlarının dili.</b>
     *
     * <p>DSS validation pipeline'ı tüm BBB constraint mesajlarını
     * (<code>BBB_XCV_ISCGKU</code>, <code>TRUSTED_SERVICE_STATUS</code> vb.)
     * <code>I18nProvider</code> üzerinden bu locale ile doldurur:</p>
     * <ul>
     *   <li>Bundle adı: <code>dss-messages</code> (DSS jar içinden gelir)</li>
     *   <li>Standart Java {@link java.util.ResourceBundle} fallback chain:
     *       <code>dss-messages_tr_TR.properties</code> →
     *       <code>dss-messages_tr.properties</code> →
     *       <code>dss-messages.properties</code> (DSS jar default — İngilizce)</li>
     *   <li>Türkiye bölgemizdeki üreticilerin operatörleri için default
     *       <code>tr</code>. Eksik anahtarlar otomatik olarak DSS'in
     *       İngilizce default mesajlarına fallback eder — boş çıktı oluşmaz.</li>
     *   <li>Override örnekleri: <code>en</code>, <code>en-US</code>,
     *       <code>fr</code>, <code>de</code>, ya da BCP-47 format
     *       (<code>tr-TR</code>). Tag {@link Locale#forLanguageTag} ile
     *       parse edilir; geçersiz/anlaşılmaz değer verildiğinde startup
     *       WARN log'u düşer ve <code>tr</code> default'una geri dönülür
     *       — sessiz İngilizce'ye düşmek operatörü yanıltabilir.</li>
     * </ul>
     *
     * <p>Override yöntemleri:</p>
     * <ol>
     *   <li><code>application.properties</code>:
     *       <code>verification.i18n-locale=en</code></li>
     *   <li>Environment variable: <code>VERIFICATION_I18N_LOCALE=en</code></li>
     * </ol>
     *
     * <p><b>TR çeviri ekleme</b>: <code>src/main/resources/dss-messages_tr.properties</code>
     * dosyasına Java <code>ResourceBundle</code> formatında satır ekleyin
     * (örn. <code>BBB_XCV_ISCGKU=Sertifikanın anahtar kullanım alanı (KeyUsage)
     * imza için yetkili mi?</code>). DSS jar default'undaki tüm anahtarlar
     * <code>dss-messages.properties</code> içinde listelenir; eksik
     * bıraktığınız anahtarlar otomatik İngilizce gelmeye devam eder.</p>
     */
    @Value("${verification.i18n-locale:tr}")
    private String i18nLocale;

    public String getCertStorePath() {
        return certStorePath;
    }

    public String getCertStorePassword() {
        return certStorePassword;
    }

    public String getCustomRootCertPath() {
        return customRootCertPath;
    }

    public boolean isOnlineValidationEnabled() {
        return onlineValidationEnabled;
    }

    public String getTrustedTsaCertificates() {
        return trustedTsaCertificates;
    }

    public int getCertCacheTtl() {
        return certCacheTtl;
    }

    public int getCrlCacheTtl() {
        return crlCacheTtl;
    }

    public boolean isStrictMode() {
        return strictMode;
    }

    public void setStrictMode(boolean strictMode) {
        this.strictMode = strictMode;
    }

    public long getRevocationCacheMaxSize() {
        return revocationCacheMaxSize;
    }

    public void setRevocationCacheMaxSize(long revocationCacheMaxSize) {
        this.revocationCacheMaxSize = revocationCacheMaxSize;
    }

    public long getRevocationCacheTtlSeconds() {
        return revocationCacheTtlSeconds;
    }

    public void setRevocationCacheTtlSeconds(long revocationCacheTtlSeconds) {
        this.revocationCacheTtlSeconds = revocationCacheTtlSeconds;
    }

    public int getRevocationHttpConnectionTimeoutMs() {
        return revocationHttpConnectionTimeoutMs;
    }

    public void setRevocationHttpConnectionTimeoutMs(int revocationHttpConnectionTimeoutMs) {
        this.revocationHttpConnectionTimeoutMs = revocationHttpConnectionTimeoutMs;
    }

    public int getRevocationHttpSocketTimeoutMs() {
        return revocationHttpSocketTimeoutMs;
    }

    public void setRevocationHttpSocketTimeoutMs(int revocationHttpSocketTimeoutMs) {
        this.revocationHttpSocketTimeoutMs = revocationHttpSocketTimeoutMs;
    }

    public boolean isRevocationRetryEnabled() {
        return revocationRetryEnabled;
    }

    public void setRevocationRetryEnabled(boolean revocationRetryEnabled) {
        this.revocationRetryEnabled = revocationRetryEnabled;
    }

    public int getRevocationRetryMaxAttempts() {
        return revocationRetryMaxAttempts;
    }

    public void setRevocationRetryMaxAttempts(int revocationRetryMaxAttempts) {
        this.revocationRetryMaxAttempts = revocationRetryMaxAttempts;
    }

    public long getRevocationRetryInitialBackoffMs() {
        return revocationRetryInitialBackoffMs;
    }

    public void setRevocationRetryInitialBackoffMs(long revocationRetryInitialBackoffMs) {
        this.revocationRetryInitialBackoffMs = revocationRetryInitialBackoffMs;
    }

    public long getRevocationRetryMaxBackoffMs() {
        return revocationRetryMaxBackoffMs;
    }

    public void setRevocationRetryMaxBackoffMs(long revocationRetryMaxBackoffMs) {
        this.revocationRetryMaxBackoffMs = revocationRetryMaxBackoffMs;
    }

    public double getRevocationRetryBackoffMultiplier() {
        return revocationRetryBackoffMultiplier;
    }

    public void setRevocationRetryBackoffMultiplier(double revocationRetryBackoffMultiplier) {
        this.revocationRetryBackoffMultiplier = revocationRetryBackoffMultiplier;
    }

    public double getRevocationRetryJitterRatio() {
        return revocationRetryJitterRatio;
    }

    public void setRevocationRetryJitterRatio(double revocationRetryJitterRatio) {
        this.revocationRetryJitterRatio = revocationRetryJitterRatio;
    }

    public boolean isEcdsaDerPreprocessorEnabled() {
        return ecdsaDerPreprocessorEnabled;
    }

    public void setEcdsaDerPreprocessorEnabled(boolean ecdsaDerPreprocessorEnabled) {
        this.ecdsaDerPreprocessorEnabled = ecdsaDerPreprocessorEnabled;
    }

    public boolean isTrLegacyXadesToleranceEnabled() {
        return trLegacyXadesToleranceEnabled;
    }

    public void setTrLegacyXadesToleranceEnabled(boolean trLegacyXadesToleranceEnabled) {
        this.trLegacyXadesToleranceEnabled = trLegacyXadesToleranceEnabled;
    }

    public boolean isTrLegacyXadesRejectionEnrichmentEnabled() {
        return trLegacyXadesRejectionEnrichmentEnabled;
    }

    public void setTrLegacyXadesRejectionEnrichmentEnabled(boolean trLegacyXadesRejectionEnrichmentEnabled) {
        this.trLegacyXadesRejectionEnrichmentEnabled = trLegacyXadesRejectionEnrichmentEnabled;
    }

    public long getAiaCacheMaxSize() {
        return aiaCacheMaxSize;
    }

    public void setAiaCacheMaxSize(long aiaCacheMaxSize) {
        this.aiaCacheMaxSize = aiaCacheMaxSize;
    }

    public long getAiaCacheTtlSeconds() {
        return aiaCacheTtlSeconds;
    }

    public void setAiaCacheTtlSeconds(long aiaCacheTtlSeconds) {
        this.aiaCacheTtlSeconds = aiaCacheTtlSeconds;
    }

    public String getI18nLocale() {
        return i18nLocale;
    }

    public void setI18nLocale(String i18nLocale) {
        this.i18nLocale = i18nLocale;
    }

    /**
     * Default locale tag — config tag boş veya geçersizse buna düşülür.
     * Türkçe ekosistem için <code>tr</code>; eksik mesaj olduğunda DSS
     * jar'ı zaten İngilizce default'a fallback eder, dolayısıyla bu değer
     * yalnızca primary lookup hedefini belirler.
     */
    public static final String DEFAULT_I18N_LOCALE_TAG = "tr";

    /**
     * Konfigüre edilen locale tag'ini ({@link Locale#forLanguageTag} ile)
     * parse eder; boş veya geçersiz tag durumunda {@link #DEFAULT_I18N_LOCALE_TAG}
     * Türkçe locale'ine düşer.
     *
     * <p><b>Tasarım kararı</b>: <code>Locale.ROOT</code> (i18n'i devre
     * dışı bırakır, anahtarın kendisini döner) veya silent İngilizce
     * fallback YERİNE Türkçe'ye düşülür — bu doğrulayıcı zaten Türkiye
     * ekosistemine adanmış; operatör yanlış config verdiğinde hâlâ
     * okunaklı bir output görmesi gerekir.</p>
     *
     * <p>Geçersiz tag durumu: {@link Locale#forLanguageTag} boş bir
     * Locale (language=&quot;&quot;) döndürürse — örn. operatör
     * <code>verification.i18n-locale=invalid_xx</code> verirse — bu
     * metoda yan etki olarak WARN log'u düşmez (saf parsing helper);
     * startup-time uyarı için bkz.
     * {@code I18nProviderConfiguration#warnOnInvalidLocale}.</p>
     */
    public Locale getI18nLocaleObject() {
        return parseLocaleOrDefault(i18nLocale);
    }

    /**
     * Locale tag → Locale objesi. Pakekt-private; testlerin parsing
     * davranışını doğrudan asserte edebilmesi için (`Locale#forLanguageTag`
     * sessiz fallback yapar; biz onu `language.isEmpty()` ile yakalarız).
     */
    static Locale parseLocaleOrDefault(String tag) {
        if (tag == null || tag.trim().isEmpty()) {
            return Locale.forLanguageTag(DEFAULT_I18N_LOCALE_TAG);
        }
        Locale parsed = Locale.forLanguageTag(tag.trim());
        if (parsed.getLanguage().isEmpty()) {
            // forLanguageTag IETF-uyumlu olmayan girdilerde Locale("","") döner.
            // Bu durumda default Türkçe'ye düş.
            return Locale.forLanguageTag(DEFAULT_I18N_LOCALE_TAG);
        }
        return parsed;
    }
}

