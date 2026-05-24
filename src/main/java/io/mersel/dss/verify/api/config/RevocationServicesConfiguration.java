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

    private final VerificationConfiguration config;

    /**
     * Micrometer registry — Spring Boot Actuator dependency'si bunu her zaman
     * context'e koyar; yine de {@link ObjectProvider} kullaniyoruz ki test
     * slice'larinda veya Actuator devre disi senaryolarda bean yaratimi
     * bozulmasin (graceful degradation: metric'siz ama calisan cache).
     */
    private final ObjectProvider<MeterRegistry> meterRegistryProvider;

    public RevocationServicesConfiguration(VerificationConfiguration config,
                                           ObjectProvider<MeterRegistry> meterRegistryProvider) {
        this.config = config;
        this.meterRegistryProvider = meterRegistryProvider;
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

        RetryPolicy retryPolicy = buildRetryPolicy();
        OCSPSource retryingOrPlain = retryPolicy.getMaxAttempts() > 1
                ? new RetryingOCSPSource(online, retryPolicy)
                : online;

        LoggingCachingOCSPSource source = new LoggingCachingOCSPSource(
                retryingOrPlain,
                config.getRevocationCacheMaxSize(),
                config.getRevocationCacheTtlSeconds());

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

        RetryPolicy retryPolicy = buildRetryPolicy();
        CRLSource retryingOrPlain = retryPolicy.getMaxAttempts() > 1
                ? new RetryingCRLSource(online, retryPolicy)
                : online;

        LoggingCachingCRLSource source = new LoggingCachingCRLSource(
                retryingOrPlain,
                config.getRevocationCacheMaxSize(),
                config.getRevocationCacheTtlSeconds());

        bindCacheMetrics(CRL_CACHE_METRIC_NAME, source.caffeineCache());

        logger.info("CRL source bean ready (online + {} + cache + logging + metrics)",
                retryPolicy.getMaxAttempts() > 1 ? ("retry x" + retryPolicy.getMaxAttempts()) : "no-retry");
        return source;
    }

    /**
     * AIA (Authority Information Access) source — sertifika zinciri eksik
     * geldiginde ara CA sertifikasini fetch icin. {@code DefaultAIASource}
     * kendi icinde HTTP fetcher kullanir; cache DSS tarafindan dahili
     * yapilir, kendi wrapper'imiza ihtiyac yok.
     */
    @Bean
    @ConditionalOnProperty(
            name = "verification.online-validation-enabled",
            havingValue = "true",
            matchIfMissing = true)
    public AIASource aiaSource() {
        CommonsDataLoader dataLoader = new CommonsDataLoader();
        applyTimeouts(dataLoader);
        DefaultAIASource aia = new DefaultAIASource(dataLoader);
        logger.info("AIA source bean ready");
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
     * HTTP timeout'larini uygular. Hardening — KamuSM uclari ara sira yavas
     * cevaplar; doğrulamanin TSA fetch / OCSP fetch yuzunden 30+ saniyeye
     * uzamasini onlemek icin agresif timeout'larla calisiyoruz.
     */
    private void applyTimeouts(CommonsDataLoader dataLoader) {
        int connTimeoutMs = config.getRevocationHttpConnectionTimeoutMs();
        int socketTimeoutMs = config.getRevocationHttpSocketTimeoutMs();
        dataLoader.setTimeoutConnection(connTimeoutMs);
        dataLoader.setTimeoutSocket(socketTimeoutMs);
        logger.debug("DataLoader timeouts applied: connection={}ms, socket={}ms",
                connTimeoutMs, socketTimeoutMs);
    }
}
