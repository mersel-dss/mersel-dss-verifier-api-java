package io.mersel.dss.verify.api.services.revocation;

import com.github.benmanes.caffeine.cache.Ticker;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RevocationFailureCache} — TTL (kalici / gecici), kapali mod, boyut
 * siniri ve konfig dogrulamasi.
 */
class RevocationFailureCacheTest {

    static final class FakeTicker implements Ticker {
        private final AtomicLong nanos = new AtomicLong();

        @Override
        public long read() {
            return nanos.get();
        }

        void advanceSeconds(long seconds) {
            nanos.addAndGet(TimeUnit.SECONDS.toNanos(seconds));
        }
    }

    static RuntimeException permanentFailure() {
        return RevocationFailureClassifierTest.dssCrlFailure(new UnacceptableHttpStatusException(400,
                RevocationFailureClassifierTest.dssStatusMessage(400)));
    }

    static RuntimeException transientFailure() {
        return RevocationFailureClassifierTest.dssCrlFailure(new SocketTimeoutException("Read timed out"));
    }

    @Test
    @DisplayName("ttl=0: kapali — hicbir sey cache'lenmez")
    void disabledWhenTtlZero() {
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 0L, 30L, 100L);
        assertFalse(cache.isEnabled());
        assertNull(cache.remember("k", permanentFailure()));
        assertNull(cache.getIfPresent("k"));
        assertNull(cache.caffeineCache());
        assertFalse(RevocationFailureCache.disabled("OCSP").isEnabled());
    }

    @Test
    @DisplayName("Kalici hata ttl-seconds boyunca hit, sonra expire")
    void permanentFailureExpiresAfterTtl() {
        FakeTicker ticker = new FakeTicker();
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 300L, 30L, 100L, ticker,
                RevocationFailureClassifier.INSTANCE);

        assertNull(cache.getIfPresent("k"), "miss before any failure");
        RevocationFailureCache.CachedFailure entry = cache.remember("k", permanentFailure());
        assertNotNull(entry);
        assertEquals(300L, entry.getTtlSeconds());
        assertFalse(entry.getClassification().isRetryable());
        assertEquals("HTTP 400", entry.getClassification().getReason());

        ticker.advanceSeconds(299);
        assertNotNull(cache.getIfPresent("k"), "still cached at 299 s");
        ticker.advanceSeconds(2);
        assertNull(cache.getIfPresent("k"), "expired after 300 s");
    }

    @Test
    @DisplayName("Gecici hata transient-ttl-seconds kadar tutulur")
    void transientFailureUsesShorterTtl() {
        FakeTicker ticker = new FakeTicker();
        RevocationFailureCache cache = new RevocationFailureCache("OCSP", 300L, 30L, 100L, ticker,
                RevocationFailureClassifier.INSTANCE);

        RevocationFailureCache.CachedFailure entry = cache.remember("k", transientFailure());
        assertNotNull(entry);
        assertEquals(30L, entry.getTtlSeconds());
        assertTrue(entry.getClassification().isRetryable());

        ticker.advanceSeconds(29);
        assertNotNull(cache.getIfPresent("k"));
        ticker.advanceSeconds(2);
        assertNull(cache.getIfPresent("k"));
    }

    @Test
    @DisplayName("DNS hatasi (retry'siz gecici) kalici TTL ile degil transient-ttl-seconds ile tutulur")
    void dnsFailureUsesTransientTtl() {
        FakeTicker ticker = new FakeTicker();
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 300L, 30L, 100L, ticker,
                RevocationFailureClassifier.INSTANCE);

        RevocationFailureCache.CachedFailure entry = cache.remember("k",
                RevocationFailureClassifierTest.dssCrlFailure(new UnknownHostException("DNS error")));
        assertNotNull(entry);
        assertEquals(30L, entry.getTtlSeconds());
        assertFalse(entry.getClassification().isRetryable());
        assertTrue(entry.getClassification().isTransient());

        ticker.advanceSeconds(31);
        assertNull(cache.getIfPresent("k"), "DNS failure must not be remembered for the permanent TTL");
    }

    @Test
    @DisplayName("Okuma TTL'i uzatmaz")
    void readsDoNotExtendTtl() {
        FakeTicker ticker = new FakeTicker();
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 10L, 10L, 100L, ticker,
                RevocationFailureClassifier.INSTANCE);
        cache.remember("k", permanentFailure());
        for (int i = 0; i < 9; i++) {
            ticker.advanceSeconds(1);
            assertNotNull(cache.getIfPresent("k"));
        }
        ticker.advanceSeconds(2);
        assertNull(cache.getIfPresent("k"));
    }

    @Test
    @DisplayName("transient-ttl-seconds=0: gecici hatalar cache'lenmez, kalicilar cache'lenir")
    void transientTtlZeroSkipsTransientFailures() {
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 300L, 0L, 100L);
        assertNull(cache.remember("t", transientFailure()));
        assertNull(cache.getIfPresent("t"));
        assertNotNull(cache.remember("p", permanentFailure()));
        assertNotNull(cache.getIfPresent("p"));
    }

    @Test
    @DisplayName("transient-ttl-seconds, ttl-seconds'a clamp'lenir")
    void transientTtlIsClampedToTtl() {
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 20L, 60L, 100L);
        assertEquals(20L, cache.getTransientTtlSeconds());
        assertEquals(20L, cache.remember("k", transientFailure()).getTtlSeconds());
    }

    @Test
    @DisplayName("Boyut siniri: max-size asilmaz")
    void boundedSize() {
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 300L, 30L, 10L);
        for (int i = 0; i < 500; i++) {
            cache.remember("k" + i, permanentFailure());
        }
        // Caffeine eviction'i amortize eder (common pool'da async bakim); tek bir
        // cleanUp() devam eden bir bakim turuyla yarisip siniri bir tur gec
        // uygulayabilir (~%5 flaky). Birkac tur cleanUp ile oturmasini bekle.
        for (int i = 0; i < 10 && cache.caffeineCache().estimatedSize() > 10L; i++) {
            cache.caffeineCache().cleanUp();
        }
        assertTrue(cache.caffeineCache().estimatedSize() <= 10L,
                "size " + cache.caffeineCache().estimatedSize() + " must be <= 10");
    }

    @Test
    @DisplayName("invalidateAll() negatif cache'i temizler")
    void invalidateAll() {
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 300L, 30L, 10L);
        cache.remember("k", permanentFailure());
        cache.invalidateAll();
        assertNull(cache.getIfPresent("k"));
    }

    @Test
    @DisplayName("Siniflandirici patlarsa gecici sayilir (kisa TTL)")
    void classifierErrorFallsBackToTransient() {
        RevocationFailureCache cache = new RevocationFailureCache("CRL", 300L, 30L, 10L, Ticker.systemTicker(),
                failure -> {
                    throw new IllegalStateException("boom");
                });
        assertEquals(30L, cache.remember("k", permanentFailure()).getTtlSeconds());
    }

    @Test
    @DisplayName("Gecersiz konfig fail-fast")
    void rejectsInvalidConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new RevocationFailureCache("CRL", -1L, 30L, 10L));
        assertThrows(IllegalArgumentException.class, () -> new RevocationFailureCache("CRL", 300L, -1L, 10L));
        assertThrows(IllegalArgumentException.class, () -> new RevocationFailureCache("CRL", 300L, 30L, 0L));
        // Kapaliyken max-size onemsiz
        assertFalse(new RevocationFailureCache("CRL", 0L, 0L, 0L).isEnabled());
    }
}
