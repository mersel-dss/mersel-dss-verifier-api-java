package io.mersel.dss.verify.api.services.revocation;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.Ticker;
import com.github.benmanes.caffeine.cache.stats.CacheStats;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Basarisiz OCSP/CRL fetch'leri icin kisa omurlu <b>negatif cache</b>.
 *
 * <h3>Neden?</h3>
 * <p>Ayni sertifika icin dagitim noktasi/responder hata veriyorsa (orn. KamuSM
 * test CRL'leri kalici HTTP 400), her dogrulama ayni HTTP istegini atip ayni
 * hatayi aliyordu. Negatif cache bu hatayi kisa bir sure hatirlar; o sure
 * boyunca {@code LoggingCaching*Source} ag cagrisi yapmadan, basarisiz bir
 * fetch'in bugun urettigi sonucun <em>aynisini</em> ({@code null} token)
 * dondurur. DSS ayni girdiyi gordugu icin dogrulama karari degismez.</p>
 *
 * <h3>TTL</h3>
 * <ul>
 *   <li><b>Kalici hatalar</b> ({@link RevocationFailureClassifier}: HTTP 4xx,
 *       bozuk cevap, protokol) — {@code ttlSeconds}.</li>
 *   <li><b>Gecici hatalar</b> (timeout / 5xx sonrasi retry'lar tukenmis;
 *       retry edilmeyen DNS cozumleme hatasi) —
 *       {@code transientTtlSeconds} (daha kisa; toparlanan responder hizla
 *       yeniden kullanilsin). {@code ttlSeconds}'i asamaz; {@code 0} =
 *       gecici hatalar cache'lenmez.</li>
 *   <li>{@code ttlSeconds == 0} — ozellik tamamen kapali
 *       ({@link #isEnabled()} {@code false}); kaynaklar eski davranisa doner.</li>
 * </ul>
 *
 * <p>Boyut {@code maxSize} ile sinirli (Caffeine W-TinyLFU eviction).
 * Thread-safe. Anahtarlama cagiranin sorumlulugundadir (sertifika + issuer
 * kimligi + kaynak URL'ler).</p>
 */
public final class RevocationFailureCache {

    private final String kind;
    private final long ttlSeconds;
    private final long transientTtlSeconds;
    private final long maxSize;
    private final FailureClassifier classifier;
    private final Cache<String, CachedFailure> cache;

    /**
     * @param kind                log etiketi ({@code "CRL"} / {@code "OCSP"})
     * @param ttlSeconds          kalici hatalarin cache suresi; {@code 0} = kapali
     * @param transientTtlSeconds gecici hatalarin cache suresi; {@code ttlSeconds}'e clamp'lenir
     * @param maxSize             maksimum kayit sayisi (etkinken {@code > 0})
     */
    public RevocationFailureCache(String kind, long ttlSeconds, long transientTtlSeconds, long maxSize) {
        this(kind, ttlSeconds, transientTtlSeconds, maxSize, Ticker.systemTicker(),
                RevocationFailureClassifier.INSTANCE);
    }

    /** Test constructor — sahte {@link Ticker} ile TTL'i deterministik ilerletmek icin. */
    RevocationFailureCache(String kind, long ttlSeconds, long transientTtlSeconds, long maxSize,
                           Ticker ticker, FailureClassifier classifier) {
        this.kind = Objects.requireNonNull(kind, "kind must not be null");
        this.classifier = Objects.requireNonNull(classifier, "classifier must not be null");
        if (ttlSeconds < 0) {
            throw new IllegalArgumentException("failure cache ttlSeconds must be >= 0 (0 = disabled), was: " + ttlSeconds);
        }
        if (transientTtlSeconds < 0) {
            throw new IllegalArgumentException("failure cache transientTtlSeconds must be >= 0, was: " + transientTtlSeconds);
        }
        if (ttlSeconds > 0 && maxSize <= 0) {
            throw new IllegalArgumentException("failure cache maxSize must be > 0, was: " + maxSize);
        }
        this.ttlSeconds = ttlSeconds;
        this.transientTtlSeconds = Math.min(transientTtlSeconds, ttlSeconds);
        this.maxSize = maxSize;
        this.cache = ttlSeconds == 0
                ? null
                : Caffeine.newBuilder()
                        .maximumSize(maxSize)
                        .expireAfter(new FailureExpiry())
                        .ticker(Objects.requireNonNull(ticker, "ticker must not be null"))
                        .recordStats()
                        .build();
    }

    /** Kapali bir negatif cache — eski davranis (her istek yeniden fetch eder). */
    public static RevocationFailureCache disabled(String kind) {
        return new RevocationFailureCache(kind, 0L, 0L, 0L);
    }

    public boolean isEnabled() {
        return cache != null;
    }

    public String getKind() {
        return kind;
    }

    public long getTtlSeconds() {
        return ttlSeconds;
    }

    public long getTransientTtlSeconds() {
        return transientTtlSeconds;
    }

    public long getMaxSize() {
        return maxSize;
    }

    /**
     * @return anahtar icin hala gecerli cache'li hata, yoksa {@code null}
     */
    public CachedFailure getIfPresent(String key) {
        return cache == null ? null : cache.getIfPresent(key);
    }

    /**
     * Basarisiz bir fetch'i siniflandirip uygun TTL ile kaydeder.
     *
     * @return kaydedilen giris; ozellik kapaliysa veya bu hata sinifinin
     *         TTL'i {@code 0} ise {@code null} (cache'lenmedi)
     */
    public CachedFailure remember(String key, Throwable failure) {
        if (cache == null) {
            return null;
        }
        FailureClassification classification;
        try {
            classification = classifier.classify(failure);
        } catch (RuntimeException e) {
            classification = FailureClassification.transientFailure("unclassified");
        }
        // Gecici hatalar (retry'li veya DNS gibi retry'siz) kisa TTL; yalniz kalicilar uzun.
        long ttl = classification.isTransient() ? transientTtlSeconds : ttlSeconds;
        if (ttl <= 0) {
            return null;
        }
        CachedFailure entry = new CachedFailure(classification, ttl);
        cache.put(key, entry);
        return entry;
    }

    public void invalidateAll() {
        if (cache != null) {
            cache.invalidateAll();
        }
    }

    public CacheStats stats() {
        return cache == null ? CacheStats.empty() : cache.stats();
    }

    /**
     * Micrometer {@code CaffeineCacheMetrics} binding'i icin; ozellik
     * kapaliysa {@code null}. Disaridan put/invalidate yapilmamali.
     */
    public Cache<String, CachedFailure> caffeineCache() {
        return cache;
    }

    @Override
    public String toString() {
        return "RevocationFailureCache{" + kind
                + (isEnabled()
                    ? ", ttlSeconds=" + ttlSeconds + ", transientTtlSeconds=" + transientTtlSeconds + ", maxSize=" + maxSize
                    : ", disabled")
                + '}';
    }

    /** Cache'lenmis bir fetch hatasi; token yerine gecmez, yalniz "fetch etme, null don" isaretidir. */
    public static final class CachedFailure {
        private final FailureClassification classification;
        private final long ttlSeconds;

        CachedFailure(FailureClassification classification, long ttlSeconds) {
            this.classification = classification;
            this.ttlSeconds = ttlSeconds;
        }

        public FailureClassification getClassification() {
            return classification;
        }

        public long getTtlSeconds() {
            return ttlSeconds;
        }

        @Override
        public String toString() {
            return classification + ", ttl=" + ttlSeconds + "s";
        }
    }

    private static final class FailureExpiry implements Expiry<String, CachedFailure> {
        @Override
        public long expireAfterCreate(String key, CachedFailure value, long currentTime) {
            return TimeUnit.SECONDS.toNanos(value.ttlSeconds);
        }

        @Override
        public long expireAfterUpdate(String key, CachedFailure value, long currentTime, long currentDuration) {
            return TimeUnit.SECONDS.toNanos(value.ttlSeconds);
        }

        @Override
        public long expireAfterRead(String key, CachedFailure value, long currentTime, long currentDuration) {
            // Okuma TTL'i uzatmaz: hata en gec ttl sonra yeniden denenir.
            return currentDuration;
        }
    }
}
