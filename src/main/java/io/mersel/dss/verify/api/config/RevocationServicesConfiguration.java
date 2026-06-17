package io.mersel.dss.verify.api.config;

import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.cache.CaffeineCacheMetrics;
import io.mersel.dss.verify.api.services.aia.NormalizingCachingAiaDataLoader;
import io.mersel.dss.verify.api.services.revocation.LoggingCachingCRLSource;
import io.mersel.dss.verify.api.services.revocation.LoggingCachingOCSPSource;
import io.mersel.dss.verify.api.services.revocation.RetryPolicy;
import io.mersel.dss.verify.api.services.revocation.RetryingCRLSource;
import io.mersel.dss.verify.api.services.revocation.RetryingOCSPSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Revocation source bean'lerinin merkezi tanimi.
 *
 * <p><strong>Politika</strong>: Tum revocation source'lari Spring singleton
 * olarak yaratiyoruz ki Caffeine cache uygulamanin tum yasam dongusunce
 * paylasilsin (yeniden yaratilan bir source cache'i sifirlardi). Bean'ler
 * sadece <code>verification.online-validation-enabled=true</code> iken
 * dirige edilir; aksi halde context'te hic olmazlar ve cagiran taraf
 * <code>ObjectProvider</code> ile "yok" durumunu net sekilde yonetebilir.</p>
 *
 * <h3>Profil-davranis matrisi</h3>
 * <table border="1">
 *   <tr><th>Profil</th><th>Revocation gereksinim</th><th>online-validation onerisi</th></tr>
 *   <tr><td>strict</td><td>Tum katmanlar FAIL</td><td>ZORUNLU true</td></tr>
 *   <tr><td>signer-strict</td><td>Imzaci FAIL, CA WARN</td><td>true (default)</td></tr>
 *   <tr><td>custom (dss.policy.path)</td><td>Operator tanimlar</td><td>operatorun sorumlulugu</td></tr>
 * </table>
 *
 * <p>"Daha hafif" bir politika (orn. revocation hic istenmiyor — laboratuvar /
 * acil offline dogrulama) icin operator <code>dss.policy.path</code> ile
 * permissive XML mount eder ve <code>verification.online-validation-enabled=false</code>
 * verir; bu durumda buradaki bean'ler hic yaratilmaz, network'e tek
 * paket gitmez.</p>
 */
@Configuration
public class RevocationServicesConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(RevocationServicesConfiguration.class);

    /**
     * Micrometer registry'sine publish edilen OCSP cache metric ailesinin prefix'i.
     * Cikti metric isimleri (Micrometer naming convention):
     * <ul>
     *   <li><code>cache.size</code> tag <code>cache=mersel.revocation.ocsp</code></li>
     *   <li><code>cache.gets</code> {result=hit|miss}</li>
     *   <li><code>cache.puts</code>, <code>cache.evictions</code></li>
     * </ul>
     * Prometheus tarafindaki final isim <code>cache_gets_total{cache="mersel.revocation.ocsp"}</code>.
     */
    static final String OCSP_CACHE_METRIC_NAME = "mersel.revocation.ocsp";

    /** CRL cache metric prefix'i — bkz. {@link #OCSP_CACHE_METRIC_NAME}. */
    static final String CRL_CACHE_METRIC_NAME = "mersel.revocation.crl";

    /**
     * AIA cache metric prefix'i — ara CA fetch cache'i. Bkz.
     * {@link #OCSP_CACHE_METRIC_NAME}; aynı naming convention.
     */
    static final String AIA_CACHE_METRIC_NAME = "mersel.aia.fetch";

    private final VerificationConfiguration config;

    /**
     * Micrometer registry — Spring Boot Actuator dependency'si bunu her zaman
     * context'e koyar; yine de {@link ObjectProvider} kullaniyoruz ki test
     * slice'larinda veya Actuator devre disi senaryolarda bean yaratimi
     * bozulmasin (graceful degradation: metric'siz ama calisan cache).
     */
    private final ObjectProvider<MeterRegistry> meterRegistryProvider;

    /**
     * Domain iş metrikleri — revocation fetch süresi/sonucu ve retry
     * olayları için. {@link ObjectProvider} ile alıyoruz ki test
     * slice'larında bean yoksa wiring bozulmasın; {@code null} ise
     * source'lara metric'siz (graceful) geçilir.
     */
    private final ObjectProvider<io.mersel.dss.verify.api.metrics.VerificationMetrics> verificationMetricsProvider;

    public RevocationServicesConfiguration(VerificationConfiguration config,
                                           ObjectProvider<MeterRegistry> meterRegistryProvider,
                                           ObjectProvider<io.mersel.dss.verify.api.metrics.VerificationMetrics> verificationMetricsProvider) {
        this.config = config;
        this.meterRegistryProvider = meterRegistryProvider;
        this.verificationMetricsProvider = verificationMetricsProvider;
    }

    /**
     * OCSP source — {@link OnlineOCSPSource} sarmali Caffeine cache + INFO logging.
     *
     * <p>{@code OCSPDataLoader} {@code CommonsDataLoader}'i extend eder ama OCSP
     * spec'ine uygun {@code Content-Type: application/ocsp-request} header'ini
     * gonderir. DSS responder bunu beklediginde basari icin sart.</p>
     */
    @Bean
    @ConditionalOnProperty(
            name = "verification.online-validation-enabled",
            havingValue = "true",
            matchIfMissing = true)
    public OCSPSource ocspSource() {
        OCSPDataLoader dataLoader = new OCSPDataLoader();
        applyTimeouts(dataLoader);

        OnlineOCSPSource online = new OnlineOCSPSource();
        online.setDataLoader(dataLoader);

        io.mersel.dss.verify.api.metrics.VerificationMetrics metrics =
                verificationMetricsProvider != null ? verificationMetricsProvider.getIfAvailable() : null;

        RetryPolicy retryPolicy = buildRetryPolicy();
        OCSPSource retryingOrPlain = retryPolicy.getMaxAttempts() > 1
                ? new RetryingOCSPSource(online, retryPolicy, metrics)
                : online;

        LoggingCachingOCSPSource source = new LoggingCachingOCSPSource(
                retryingOrPlain,
                config.getRevocationCacheMaxSize(),
                config.getRevocationCacheTtlSeconds(),
                metrics);

        bindCacheMetrics(OCSP_CACHE_METRIC_NAME, source.caffeineCache());

        logger.info("OCSP source bean ready (online + {} + cache + logging + metrics)",
                retryPolicy.getMaxAttempts() > 1 ? ("retry x" + retryPolicy.getMaxAttempts()) : "no-retry");
        return source;
    }

    /**
     * CRL source — {@link OnlineCRLSource} sarmali Caffeine cache + INFO logging.
     * CRL fetch'i icin standart {@code CommonsDataLoader} yeterli (CRL distribution
     * point HTTP GET ile cekilir, ozel content-type yok).
     */
    @Bean
    @ConditionalOnProperty(
            name = "verification.online-validation-enabled",
            havingValue = "true",
            matchIfMissing = true)
    public CRLSource crlSource() {
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        applyTimeouts(dataLoader);

        OnlineCRLSource online = new OnlineCRLSource();
        online.setDataLoader(dataLoader);

        io.mersel.dss.verify.api.metrics.VerificationMetrics metrics =
                verificationMetricsProvider != null ? verificationMetricsProvider.getIfAvailable() : null;

        RetryPolicy retryPolicy = buildRetryPolicy();
        CRLSource retryingOrPlain = retryPolicy.getMaxAttempts() > 1
                ? new RetryingCRLSource(online, retryPolicy, metrics)
                : online;

        LoggingCachingCRLSource source = new LoggingCachingCRLSource(
                retryingOrPlain,
                config.getCrlCacheMaxSize(),
                config.getRevocationCacheTtlSeconds(),
                metrics);

        bindCacheMetrics(CRL_CACHE_METRIC_NAME, source.caffeineCache());

        logger.info("CRL source bean ready (online + {} + cache + logging + metrics)",
                retryPolicy.getMaxAttempts() > 1 ? ("retry x" + retryPolicy.getMaxAttempts()) : "no-retry");
        return source;
    }

    /**
     * AIA (Authority Information Access) source — sertifika zinciri eksik
     * geldiginde ara CA sertifikasini fetch icin.
     *
     * <p>Burada {@code CommonsDataLoader}'i <strong>doğrudan</strong>
     * {@code DefaultAIASource}'a vermeyiz; arada {@link NormalizingCachingAiaDataLoader}
     * dekoratörü oturur. Bu dekoratör iki sorunu çözer:</p>
     * <ul>
     *   <li><b>Naked base64 normalize</b> — Bazı TR ESHS endpoint'leri (örnek:
     *       Eimzatr <code>depo.e-imzatriptal.com</code>) ara CA sertifikasını
     *       <code>Content-Type: application/pkix-cert</code> başlığı altında
     *       <em>raw DER yerine</em> base64-encoded text olarak servis ediyor.
     *       Java <code>CertificateFactory</code> raw DER veya PEM ister; naked
     *       base64'ü kabul etmez ve DSS <code>NO_CERTIFICATE_CHAIN_FOUND</code>
     *       döner. Decorator response'u DER'e normalize ederek bu üretici
     *       bug'ını şeffafça absorbe eder.</li>
     *   <li><b>In-memory cache</b> — KamuSM ekosisteminde ara CA sayısı düşük
     *       (<=20); aynı URL'e tekrar gitmek HTTP yükünden ibaret. 24 saat
     *       TTL ile aynı ara CA bir kez fetch edilir.</li>
     * </ul>
     */
    @Bean
    @ConditionalOnProperty(
            name = "verification.online-validation-enabled",
            havingValue = "true",
            matchIfMissing = true)
    public AIASource aiaSource() {
        CommonsDataLoader rawLoader = new CommonsDataLoader();
        applyTimeouts(rawLoader);

        io.mersel.dss.verify.api.metrics.VerificationMetrics metrics =
                verificationMetricsProvider != null ? verificationMetricsProvider.getIfAvailable() : null;

        NormalizingCachingAiaDataLoader normalizingLoader = new NormalizingCachingAiaDataLoader(
                rawLoader,
                config.getAiaCacheMaxSize(),
                config.getAiaCacheTtlSeconds(),
                metrics);

        // Caffeine cache'i Micrometer'a bağla — observability paritesi
        // OCSP/CRL ile aynı standartta. Bind başarısız olsa bile AIA
        // çalışmaya devam eder (bindCacheMetrics graceful degrade eder).
        bindCacheMetrics(AIA_CACHE_METRIC_NAME, normalizingLoader.caffeineCache());

        DefaultAIASource aia = new DefaultAIASource(normalizingLoader);
        logger.info("AIA source bean ready (normalizing + cache + metrics)");
        return aia;
    }

    /**
     * Konfigurasyondan {@link RetryPolicy} ureten factory. Retry kapali
     * ise {@link RetryPolicy#disabled()} doner (decorator wiring devre
     * disi); aksi halde 5 paramli konfigurasyon policy'sini insa eder.
     *
     * <p><strong>Sanity check</strong>: invalid bir konfig (orn. negatif
     * backoff) {@link RetryPolicy} constructor'inda IAE firlatir; Spring
     * context startup'inda fail-fast davranis — sessizce default'a dusmek
     * resmi dogrulama servisi icin riskli olur.</p>
     */
    private RetryPolicy buildRetryPolicy() {
        if (!config.isRevocationRetryEnabled()) {
            logger.info("Revocation retry: disabled (verification.revocation.retry.enabled=false)");
            return RetryPolicy.disabled();
        }
        RetryPolicy policy = new RetryPolicy(
                config.getRevocationRetryMaxAttempts(),
                config.getRevocationRetryInitialBackoffMs(),
                config.getRevocationRetryMaxBackoffMs(),
                config.getRevocationRetryBackoffMultiplier(),
                config.getRevocationRetryJitterRatio());
        logger.info("Revocation retry: enabled — {}", policy);
        return policy;
    }

    /**
     * Caffeine cache instance'ini Micrometer {@link MeterRegistry}'sine
     * baglar. Cikti metric ailesi {@code cache.size}, {@code cache.gets}
     * ({@code result=hit|miss}), {@code cache.puts}, {@code cache.evictions}
     * — Spring Boot Actuator'in <code>/actuator/prometheus</code> endpoint'i
     * uzerinden Grafana dashboard'larina dusurulebilir.
     *
     * <p><strong>Graceful degradation</strong>: {@link MeterRegistry} context'te
     * yoksa (orn. minimal test slice) metric kaydi atlanir, INFO log'u dusur
     * fakat cache calismaya devam eder. Bu, dogrulama akisinin Actuator
     * konfigurasyonuna parazit bagimliligini kirmak icin bilincli karar.</p>
     *
     * <p><strong>Idempotency</strong>: {@code CaffeineCacheMetrics.monitor()}
     * her bean refresh'inde tekrar register edilse bile aynı isim/tag tuple
     * ile mevcut gauge'lari yeniden kullanir (Micrometer registry icinde
     * deduplication yapar) — restart sonrasi metric duplicate'i olusmaz.</p>
     *
     * @param cacheName Prometheus tarafindaki {@code cache} tag degeri.
     *                  Mersel-prefix'li olarak {@link #OCSP_CACHE_METRIC_NAME}
     *                  veya {@link #CRL_CACHE_METRIC_NAME} kullanilir.
     * @param cache     Caffeine cache instance'i (wrapper'in paket-ozel getter'i)
     */
    private void bindCacheMetrics(String cacheName,
                                  com.github.benmanes.caffeine.cache.Cache<?, ?> cache) {
        MeterRegistry registry = meterRegistryProvider.getIfAvailable();
        if (registry == null) {
            logger.info("MeterRegistry bulunamadi; '{}' cache metrics atlandi (cache calismaya devam eder)",
                    cacheName);
            return;
        }
        try {
            CaffeineCacheMetrics.monitor(registry, cache, cacheName);
            logger.info("Caffeine cache metrics registered: cacheName='{}' (Prometheus: cache_*{{cache=\"{}\"}})",
                    cacheName, cacheName);
        } catch (RuntimeException e) {
            // Metric binding hatasi dogrulama akisini bloklamamali; WARN ile not.
            logger.warn("Caffeine cache metrics binding failed for '{}': {} (cache calismaya devam eder)",
                    cacheName, e.getMessage());
        }
    }

    /**
     * HTTP timeout'larini ve <strong>connection pool</strong> ayarlarini
     * uygular.
     *
     * <p><strong>Üretim olayı düzeltmesi</strong>: DSS 6.3
     * {@code CommonsDataLoader} default'lari bu servis icin tehlikeliydi —
     * {@code maxPerRoute=2}, {@code maxTotal=20}, {@code connectionRequest
     * timeout=60000ms}. Tüm OCSP istekleri tek KamuSM host'una (tek route)
     * gittiginden, pod basina yalnizca 2 eszamanli fetch yapilabiliyor;
     * havuz dolunca 3.+ Tomcat thread'i 60sn bloke kaliyor ve saatler
     * icinde tum thread havuzu kilitlenip HttpTimeout uretiyordu.</p>
     *
     * <p>Burada dort sey override edilir:</p>
     * <ul>
     *   <li><b>connection timeout</b> — TCP connect (default 10s)</li>
     *   <li><b>socket timeout</b> — read between packets (default 10s)</li>
     *   <li><b>connection-request timeout</b> — havuzdan lease (default 3s;
     *       60sn yerine HIZLI fail → thread serbest kalir)</li>
     *   <li><b>pool boyutu</b> — maxPerRoute (default 50) + maxTotal
     *       (default 200) → gercek paralellik</li>
     * </ul>
     */
    private void applyTimeouts(CommonsDataLoader dataLoader) {
        int connTimeoutMs = config.getRevocationHttpConnectionTimeoutMs();
        int socketTimeoutMs = config.getRevocationHttpSocketTimeoutMs();
        int connRequestTimeoutMs = config.getRevocationHttpConnectionRequestTimeoutMs();
        int maxPerRoute = config.getRevocationHttpMaxConnectionsPerRoute();
        int maxTotal = config.getRevocationHttpMaxConnectionsTotal();

        dataLoader.setTimeoutConnection(connTimeoutMs);
        dataLoader.setTimeoutSocket(socketTimeoutMs);
        dataLoader.setTimeoutConnectionRequest(connRequestTimeoutMs);
        dataLoader.setConnectionsMaxPerRoute(maxPerRoute);
        dataLoader.setConnectionsMaxTotal(maxTotal);

        logger.info("DataLoader HTTP tuned: connect={}ms, socket={}ms, "
                        + "connectionRequest={}ms, maxPerRoute={}, maxTotal={}",
                connTimeoutMs, socketTimeoutMs, connRequestTimeoutMs, maxPerRoute, maxTotal);
    }
}
