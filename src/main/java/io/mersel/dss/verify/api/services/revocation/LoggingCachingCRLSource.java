package io.mersel.dss.verify.api.services.revocation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * CRL source wrapper'i — DSS {@link CRLSource} delegate'i etrafinda
 * <b>in-memory cache</b> ve <b>INFO seviyesinde audit log</b> saglar.
 *
 * <h3>Neden ayri bir CRL cache?</h3>
 * <p>CRL'ler bir sertifika listesi indirir; tek dosya MB seviyesine ulasabilir.
 * KamuSM ara CA'larinin CRL'leri tipik olarak gunde 1-2 kez yenilenir. Her
 * imza dogrulamasinda yeniden indirmek hem ag, hem de KamuSM tarafini
 * yorar. OCSP cache'inden ayri tutuyoruz cunku:
 * <ul>
 *   <li>OCSP per-cert request; CRL per-CA list — anahtarlama mantigi farkli.</li>
 *   <li>TTL profili farkli: CRL tipik nextUpdate uzaktir (saatler / gun),
 *       OCSP saniyeler ila saatler arasi.</li>
 * </ul>
 *
 * <h3>TTL stratejisi</h3>
 * <p>{@code CRLToken.getNextUpdate()} + default TTL ust siniri.
 * {@link LoggingCachingOCSPSource} ile birebir ayni mantik.</p>
 *
 * <h3>Loglama</h3>
 * <ul>
 *   <li><b>INFO</b> — cache miss / HTTP fetch ("CRL request: ...")</li>
 *   <li><b>INFO</b> — response: thisUpdate / nextUpdate / sourceUrl</li>
 *   <li><b>DEBUG</b> — cache hit</li>
 *   <li><b>WARN</b> — delegate hata firlatti</li>
 *   <li><b>INFO</b> — hata negatif cache'e alindi ("CRL fetch failure cached for N s")</li>
 *   <li><b>DEBUG</b> — negatif cache hit (fetch yapilmadi)</li>
 * </ul>
 *
 * <h3>Negatif cache + single-flight</h3>
 * <p>{@link RevocationFailureCache} etkinse basarisiz fetch'ler (sertifika +
 * issuer kimligi + CRL URL'leri bazinda) kisa sure hatirlanir; bu surede
 * ayni sertifika icin delegate cagrilmaz ve basarisiz fetch'in bugun
 * urettigi sonucun aynisi ({@code null}) doner. Ayni anahtar icin eszamanli
 * istekler tek bir fetch'i paylasir ({@link SingleFlight}). Negatif cache
 * kapaliysa ({@code ttl=0}) akis eski davranisla birebir aynidir.</p>
 */
public class LoggingCachingCRLSource implements CRLSource {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = LoggerFactory.getLogger(LoggingCachingCRLSource.class);

    private final transient CRLSource delegate;
    private final transient Cache<String, CRLToken> cache;
    private final transient RevocationFailureCache failureCache;
    private final transient SingleFlight<CRLToken> singleFlight = new SingleFlight<>("CRL");

    /** İş metrikleri için opsiyonel hook; {@code null} olabilir. */
    private final transient io.mersel.dss.verify.api.metrics.VerificationMetrics metrics;

    public LoggingCachingCRLSource(CRLSource delegate, long maxCacheSize, long defaultTtlSeconds) {
        this(delegate, maxCacheSize, defaultTtlSeconds, null);
    }

    public LoggingCachingCRLSource(CRLSource delegate, long maxCacheSize, long defaultTtlSeconds,
                                   io.mersel.dss.verify.api.metrics.VerificationMetrics metrics) {
        this(delegate, maxCacheSize, defaultTtlSeconds, metrics, null);
    }

    /**
     * Negatif cache'li constructor.
     *
     * @param failureCache basarisiz fetch'ler icin negatif cache; {@code null}
     *                     veya kapali ise eski davranis (her istek yeniden fetch)
     */
    public LoggingCachingCRLSource(CRLSource delegate, long maxCacheSize, long defaultTtlSeconds,
                                   io.mersel.dss.verify.api.metrics.VerificationMetrics metrics,
                                   RevocationFailureCache failureCache) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.metrics = metrics;
        this.failureCache = failureCache != null ? failureCache : RevocationFailureCache.disabled("CRL");
        if (maxCacheSize <= 0) {
            throw new IllegalArgumentException("maxCacheSize must be > 0, was: " + maxCacheSize);
        }
        if (defaultTtlSeconds <= 0) {
            throw new IllegalArgumentException("defaultTtlSeconds must be > 0, was: " + defaultTtlSeconds);
        }
        this.cache = Caffeine.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfter(new TokenExpiry(defaultTtlSeconds))
                .recordStats()
                .build();
        logger.info("LoggingCachingCRLSource initialized: delegate={}, maxSize={}, defaultTtlSeconds={}, failureCache={}",
                delegate.getClass().getSimpleName(), maxCacheSize, defaultTtlSeconds, this.failureCache);
    }

    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        if (certificateToken == null || issuerCertificateToken == null) {
            logger.debug("CRL skipped: null cert ({}) or issuer ({})", certificateToken, issuerCertificateToken);
            return null;
        }

        String key = buildKey(certificateToken, issuerCertificateToken);
        CRLToken cached = cache.getIfPresent(key);
        if (cached != null) {
            logCacheHit(certificateToken, cached);
            return cached;
        }

        if (!failureCache.isEnabled()) {
            return fetch(key, null, null, certificateToken, issuerCertificateToken);
        }

        List<String> urls = crlUrls(certificateToken);
        String failureKey = key + "|" + String.join(",", urls);
        if (isCachedFailure(failureKey, certificateToken)) {
            return null;
        }
        return singleFlight.execute(key, () -> {
            // Lider olmadan hemen once biten bir fetch cache'leri doldurmus olabilir.
            CRLToken raced = cache.getIfPresent(key);
            if (raced != null) {
                logCacheHit(certificateToken, raced);
                return raced;
            }
            if (isCachedFailure(failureKey, certificateToken)) {
                return null;
            }
            return fetch(key, failureKey, urls, certificateToken, issuerCertificateToken);
        });
    }

    /**
     * Gercek fetch + cache. {@code failureKey == null} ise negatif cache kapali
     * (eski davranis birebir).
     */
    private CRLToken fetch(String key, String failureKey, List<String> urls,
                           CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        logger.info("CRL request: subject='{}', issuer='{}' — cache miss, fetching CRL",
                safeSubject(certificateToken),
                safeSubject(issuerCertificateToken));

        long fetchStartNanos = System.nanoTime();
        CRLToken token;
        try {
            token = delegate.getRevocationToken(certificateToken, issuerCertificateToken);
        } catch (RuntimeException e) {
            recordFetch("error", fetchStartNanos);
            RevocationFailureCache.CachedFailure remembered =
                    failureKey == null ? null : failureCache.remember(failureKey, e);
            if (remembered == null) {
                logger.warn("CRL fetch failed for subject='{}': {} (not cached, returning null)",
                        safeSubject(certificateToken), e.getMessage());
            } else {
                logger.warn("CRL fetch failed for subject='{}': {} (returning null)",
                        safeSubject(certificateToken), e.getMessage());
                logger.info("CRL fetch failure cached for {} s: subject='{}', urls={}, failure={}",
                        remembered.getTtlSeconds(), safeSubject(certificateToken),
                        RevocationUrls.forLog(urls), remembered.getClassification());
            }
            return null;
        }

        if (token == null) {
            recordFetch("empty", fetchStartNanos);
            logger.info("CRL response: subject='{}' — distribution point returned no token (not cached)",
                    safeSubject(certificateToken));
            return null;
        }

        recordFetch("success", fetchStartNanos);
        cache.put(key, token);
        logger.info("CRL response: subject='{}', status={}, thisUpdate={}, nextUpdate={}, sourceUrl={} (cached)",
                safeSubject(certificateToken),
                token.getStatus(),
                token.getThisUpdate(),
                token.getNextUpdate(),
                token.getSourceURL());
        return token;
    }

    private boolean isCachedFailure(String failureKey, CertificateToken certificateToken) {
        RevocationFailureCache.CachedFailure failure = failureCache.getIfPresent(failureKey);
        if (failure == null) {
            return false;
        }
        logger.debug("CRL failure cache hit: subject='{}', failure={} — skipping fetch, returning null",
                safeSubject(certificateToken), failure);
        return true;
    }

    private void logCacheHit(CertificateToken certificateToken, CRLToken cached) {
        logger.debug("CRL cache hit: subject='{}', status={}, sourceUrl={}",
                safeSubject(certificateToken),
                cached.getStatus(),
                cached.getSourceURL());
    }

    private static List<String> crlUrls(CertificateToken certificateToken) {
        try {
            List<String> urls = CertificateExtensionsUtils.getCRLAccessUrls(certificateToken);
            return urls != null ? urls : Collections.<String>emptyList();
        } catch (RuntimeException e) {
            return Collections.emptyList();
        }
    }

    private void recordFetch(String outcome, long startNanos) {
        if (metrics == null) {
            return;
        }
        try {
            metrics.recordRevocationFetch("crl", outcome, System.nanoTime() - startNanos);
        } catch (RuntimeException ignore) {
            // metric akışı bozamaz
        }
    }

    public com.github.benmanes.caffeine.cache.stats.CacheStats stats() {
        return cache.stats();
    }

    public void invalidateAll() {
        cache.invalidateAll();
        failureCache.invalidateAll();
        logger.info("CRL cache invalidated");
    }

    /** Negatif cache (metrics binding / test icin). */
    public RevocationFailureCache failureCache() {
        return failureCache;
    }

    /**
     * Cache instance'ina erisim — Micrometer {@code CaffeineCacheMetrics}
     * binding'i icin. Bkz. {@link LoggingCachingOCSPSource#caffeineCache()}
     * — ayni sorumluluk dağilimi, ayni uyarilar.
     */
    public Cache<String, CRLToken> caffeineCache() {
        return cache;
    }

    private static String buildKey(CertificateToken cert, CertificateToken issuer) {
        return cert.getDSSIdAsString() + "::" + issuer.getDSSIdAsString();
    }

    private static String safeSubject(CertificateToken token) {
        try {
            return token.getSubject().getPrettyPrintRFC2253();
        } catch (Exception e) {
            return token.getDSSIdAsString();
        }
    }

    private static final class TokenExpiry implements Expiry<String, CRLToken> {
        private final long defaultTtlNanos;

        TokenExpiry(long defaultTtlSeconds) {
            this.defaultTtlNanos = TimeUnit.SECONDS.toNanos(defaultTtlSeconds);
        }

        @Override
        public long expireAfterCreate(String key, CRLToken token, long currentTime) {
            return computeTtl(token);
        }

        @Override
        public long expireAfterUpdate(String key, CRLToken token, long currentTime, long currentDuration) {
            return computeTtl(token);
        }

        @Override
        public long expireAfterRead(String key, CRLToken token, long currentTime, long currentDuration) {
            return currentDuration;
        }

        private long computeTtl(CRLToken token) {
            Date nextUpdate = token.getNextUpdate();
            if (nextUpdate == null) {
                return defaultTtlNanos;
            }
            long remainingMs = nextUpdate.getTime() - System.currentTimeMillis();
            if (remainingMs <= 0) {
                return 1L;
            }
            long remainingNanos = TimeUnit.MILLISECONDS.toNanos(remainingMs);
            return Math.min(remainingNanos, defaultTtlNanos);
        }
    }
}
