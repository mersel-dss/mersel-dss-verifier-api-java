package io.mersel.dss.verify.api.services.revocation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
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
 * </ul>
 */
public class LoggingCachingCRLSource implements CRLSource {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = LoggerFactory.getLogger(LoggingCachingCRLSource.class);

    private final transient CRLSource delegate;
    private final transient Cache<String, CRLToken> cache;

    /** İş metrikleri için opsiyonel hook; {@code null} olabilir. */
    private final transient io.mersel.dss.verify.api.metrics.VerificationMetrics metrics;

    public LoggingCachingCRLSource(CRLSource delegate, long maxCacheSize, long defaultTtlSeconds) {
        this(delegate, maxCacheSize, defaultTtlSeconds, null);
    }

    public LoggingCachingCRLSource(CRLSource delegate, long maxCacheSize, long defaultTtlSeconds,
                                   io.mersel.dss.verify.api.metrics.VerificationMetrics metrics) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.metrics = metrics;
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
        logger.info("LoggingCachingCRLSource initialized: delegate={}, maxSize={}, defaultTtlSeconds={}",
                delegate.getClass().getSimpleName(), maxCacheSize, defaultTtlSeconds);
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
            logger.debug("CRL cache hit: subject='{}', status={}, sourceUrl={}",
                    safeSubject(certificateToken),
                    cached.getStatus(),
                    cached.getSourceURL());
            return cached;
        }

        logger.info("CRL request: subject='{}', issuer='{}' — cache miss, fetching CRL",
                safeSubject(certificateToken),
                safeSubject(issuerCertificateToken));

        long fetchStartNanos = System.nanoTime();
        CRLToken token;
        try {
            token = delegate.getRevocationToken(certificateToken, issuerCertificateToken);
        } catch (RuntimeException e) {
            recordFetch("error", fetchStartNanos);
            logger.warn("CRL fetch failed for subject='{}': {} (not cached, returning null)",
                    safeSubject(certificateToken), e.getMessage());
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
        logger.info("CRL cache invalidated");
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
