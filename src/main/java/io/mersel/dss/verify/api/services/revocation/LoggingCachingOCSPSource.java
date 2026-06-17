package io.mersel.dss.verify.api.services.revocation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * OCSP source wrapper'i — DSS {@link OCSPSource} delegate'i etrafinda
 * <b>in-memory cache</b> ve <b>INFO seviyesinde audit log</b> saglar.
 *
 * <h3>Neden?</h3>
 * <p>Resmi imza dogrulama akisinda her sertifika icin OCSP responder'a HTTP
 * istegi atilir. Bir e-Fatura paketinde 10 imza varsa ve hepsi ayni imzaci
 * sertifikasi kullaniyorsa 10 ayri request gider — KamuSM tarafini bos yere
 * yorar, response time'imizi 2-3 saniyeden 200ms'e cekemiyoruz. Caffeine
 * cache ile <em>ayni token icin tekrar fetch'i ortadan kaldiriyoruz</em>.</p>
 *
 * <h3>TTL stratejisi (best practice)</h3>
 * <p>Cache, OCSP response'unun kendi {@code nextUpdate} alanini taban alir:
 * <ul>
 *   <li>Token'in {@code nextUpdate} degeri varsa ve <em>su an + default TTL</em>'den
 *       daha yakin bir tarihse → o tarihe kadar tut.</li>
 *   <li>{@code nextUpdate} yoksa ya da default TTL'den uzaksa → default TTL'e bagla.
 *       Bu, "uzun olan nextUpdate sertifika iptalini gec gormemize" yol acmasin diye
 *       <strong>guvenlik ust siniri</strong>.</li>
 *   <li>{@link CertificateStatus#UNKNOWN} statusu cache'lenmez (responder gec cevap
 *       vermisse bir sonraki istekte yine deneriz).</li>
 *   <li>Delegate {@code null} donerse cache'lenmez.</li>
 * </ul>
 *
 * <h3>Loglama</h3>
 * <ul>
 *   <li><b>INFO</b> — cache miss: aktif HTTP istegi atilirken ("OCSP request: ...")</li>
 *   <li><b>INFO</b> — response: status / thisUpdate / nextUpdate / sourceUrl</li>
 *   <li><b>DEBUG</b> — cache hit: HTTP atilmadi (operasyonel guruluk azaltma)</li>
 *   <li><b>WARN</b> — delegate hata firlatti: cache'lenmez, null donulur</li>
 * </ul>
 *
 * <p><strong>Thread-safety</strong>: Caffeine cache thread-safe; bu wrapper
 * stateless (cache disinda) oldugu icin Spring singleton bean olarak guvenle
 * paylasilabilir.</p>
 */
public class LoggingCachingOCSPSource implements OCSPSource {

    private static final long serialVersionUID = 1L;

    private static final Logger logger = LoggerFactory.getLogger(LoggingCachingOCSPSource.class);

    private final transient OCSPSource delegate;
    private final transient Cache<String, OCSPToken> cache;
    private final long defaultTtlSeconds;

    /**
     * İş metrikleri için opsiyonel hook — gerçek fetch (cache-miss)
     * süresi + sonucu ({@code mdss_revocation_fetch_duration_seconds})
     * buraya yazılır. {@code null} olabilir (metric'siz çalışır).
     */
    private final transient io.mersel.dss.verify.api.metrics.VerificationMetrics metrics;

    /**
     * @param delegate          gercek OCSP source (tipik: {@code OnlineOCSPSource})
     * @param maxCacheSize      cache'te tutulacak maksimum entry sayisi
     * @param defaultTtlSeconds varsayilan TTL (nextUpdate yoksa veya cok uzaksa)
     */
    public LoggingCachingOCSPSource(OCSPSource delegate, long maxCacheSize, long defaultTtlSeconds) {
        this(delegate, maxCacheSize, defaultTtlSeconds, null);
    }

    /**
     * Metrics-aware constructor — bkz. {@link #LoggingCachingOCSPSource(OCSPSource, long, long)}.
     *
     * @param metrics fetch süresi/sonucu için hook; {@code null} olabilir.
     */
    public LoggingCachingOCSPSource(OCSPSource delegate, long maxCacheSize, long defaultTtlSeconds,
                                    io.mersel.dss.verify.api.metrics.VerificationMetrics metrics) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.metrics = metrics;
        if (maxCacheSize <= 0) {
            throw new IllegalArgumentException("maxCacheSize must be > 0, was: " + maxCacheSize);
        }
        if (defaultTtlSeconds <= 0) {
            throw new IllegalArgumentException("defaultTtlSeconds must be > 0, was: " + defaultTtlSeconds);
        }
        this.defaultTtlSeconds = defaultTtlSeconds;
        this.cache = Caffeine.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfter(new TokenExpiry(defaultTtlSeconds))
                .recordStats()
                .build();
        logger.info("LoggingCachingOCSPSource initialized: delegate={}, maxSize={}, defaultTtlSeconds={}",
                delegate.getClass().getSimpleName(), maxCacheSize, defaultTtlSeconds);
    }

    @Override
    public OCSPToken getRevocationToken(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        if (certificateToken == null || issuerCertificateToken == null) {
            // OCSP icin ikisi de zorunlu; null gelirse delegate hatasini onleyip dogrudan dusulur.
            logger.debug("OCSP skipped: null cert ({}) or issuer ({})", certificateToken, issuerCertificateToken);
            return null;
        }

        String key = buildKey(certificateToken, issuerCertificateToken);
        OCSPToken cached = cache.getIfPresent(key);
        if (cached != null) {
            logger.debug("OCSP cache hit: subject='{}', status={}, sourceUrl={}",
                    safeSubject(certificateToken),
                    cached.getStatus(),
                    cached.getSourceURL());
            return cached;
        }

        logger.info("OCSP request: subject='{}', issuer='{}' — cache miss, fetching from responder",
                safeSubject(certificateToken),
                safeSubject(issuerCertificateToken));

        long fetchStartNanos = System.nanoTime();
        OCSPToken token;
        try {
            token = delegate.getRevocationToken(certificateToken, issuerCertificateToken);
        } catch (RuntimeException e) {
            recordFetch("error", fetchStartNanos);
            logger.warn("OCSP fetch failed for subject='{}': {} (not cached, returning null)",
                    safeSubject(certificateToken), e.getMessage());
            return null;
        }

        if (token == null) {
            recordFetch("empty", fetchStartNanos);
            logger.info("OCSP response: subject='{}' — responder returned no token (not cached)",
                    safeSubject(certificateToken));
            return null;
        }

        recordFetch("success", fetchStartNanos);

        if (token.getStatus() == CertificateStatus.UNKNOWN) {
            // Responder "bilmiyorum" diyorsa cache'lersek diger isteklerde de bilmedigini varsayariz —
            // halbuki belki responder kisa sureli down idi. Bu yuzden UNKNOWN cache'lenmez.
            logger.info("OCSP response: subject='{}', status=UNKNOWN, thisUpdate={}, sourceUrl={} (not cached)",
                    safeSubject(certificateToken),
                    token.getThisUpdate(),
                    token.getSourceURL());
            return token;
        }

        cache.put(key, token);
        logger.info("OCSP response: subject='{}', status={}, thisUpdate={}, nextUpdate={}, sourceUrl={} (cached)",
                safeSubject(certificateToken),
                token.getStatus(),
                token.getThisUpdate(),
                token.getNextUpdate(),
                token.getSourceURL());
        return token;
    }

    /**
     * Gerçek fetch (cache-miss) süresi + sonucunu metrics hook'una yazar.
     * Hook null ise no-op; hata asla revocation akışını bozmaz.
     */
    private void recordFetch(String outcome, long startNanos) {
        if (metrics == null) {
            return;
        }
        try {
            metrics.recordRevocationFetch("ocsp", outcome, System.nanoTime() - startNanos);
        } catch (RuntimeException ignore) {
            // metric akışı bozamaz
        }
    }

    /**
     * Test/diagnostic icin cache istatistikleri. {@code recordStats()} aktif oldugu icin
     * hit-rate / eviction sayilari raporlanabilir.
     */
    public com.github.benmanes.caffeine.cache.stats.CacheStats stats() {
        return cache.stats();
    }

    /**
     * Test/operasyonel icin cache temizleme (orn. KamuSM gerceginde sertifika iptal
     * edildiginde manuel flush istenebilir).
     */
    public void invalidateAll() {
        cache.invalidateAll();
        logger.info("OCSP cache invalidated");
    }

    /**
     * Cache instance'ina erisim — <strong>yalnizca Micrometer
     * {@code CaffeineCacheMetrics} binding'i veya operasyonel inspection icin
     * tasarlandi</strong>.
     *
     * <p>Wrapper'in normal akiminda dis dunya cache'le dogrudan oynamasin;
     * bu metodu cagiran kod entry'leri manuel olarak put/invalidate
     * etmemelidir — TTL ve UNKNOWN cache'leme stratejisini bozar.</p>
     *
     * <p>Bilincli olarak Micrometer bagimliligini wrapper'a TASIMIYORUZ
     * (wrapper saf bir DSS {@code OCSPSource} adaptori kalsin);
     * {@link io.mersel.dss.verify.api.config.RevocationServicesConfiguration}
     * Caffeine cache'ini bu getter ile alip Spring tarafinda
     * {@code CaffeineCacheMetrics.monitor()} cagirir. Bu sayede bean
     * dependency yonu tek istikamette akar (wrapper -> Micrometer DEGIL).</p>
     */
    public Cache<String, OCSPToken> caffeineCache() {
        return cache;
    }

    /**
     * Cache anahtari: {@code certificateId + "::" + issuerId}. DSS'in
     * {@code getDSSIdAsString()} metodu sertifika icin sabit, deterministik
     * bir identifier doner (entity key + serial number bazli) — ayni sertifika
     * + ayni issuer kombosu icin garanti edilmis bir anahtar.
     */
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

    /**
     * Caffeine {@link Expiry} stratejisi: token nextUpdate'i temel alir,
     * default TTL'i ust sinir olarak uygular.
     *
     * <p>Caffeine API'si nanoseconds bekler — saatleri unite donusumlerinde
     * dikkat ediyoruz.</p>
     */
    private static final class TokenExpiry implements Expiry<String, OCSPToken> {
        private final long defaultTtlNanos;

        TokenExpiry(long defaultTtlSeconds) {
            this.defaultTtlNanos = TimeUnit.SECONDS.toNanos(defaultTtlSeconds);
        }

        @Override
        public long expireAfterCreate(String key, OCSPToken token, long currentTime) {
            return computeTtl(token);
        }

        @Override
        public long expireAfterUpdate(String key, OCSPToken token, long currentTime, long currentDuration) {
            return computeTtl(token);
        }

        @Override
        public long expireAfterRead(String key, OCSPToken token, long currentTime, long currentDuration) {
            // Read'ler TTL'i sifirlamasin — token'in kendi takvimine uy.
            return currentDuration;
        }

        private long computeTtl(OCSPToken token) {
            Date nextUpdate = token.getNextUpdate();
            if (nextUpdate == null) {
                return defaultTtlNanos;
            }
            long remainingMs = nextUpdate.getTime() - System.currentTimeMillis();
            if (remainingMs <= 0) {
                // Zaten geride kalmis bir token — minimum 1 ns ile expire et.
                return 1L;
            }
            long remainingNanos = TimeUnit.MILLISECONDS.toNanos(remainingMs);
            // Default TTL ust sinir: nextUpdate cok ileride olsa bile gercek dunyada
            // sertifika iptal edilebilir; cache'i taze tutmak icin sinirliyoruz.
            return Math.min(remainingNanos, defaultTtlNanos);
        }
    }
}
