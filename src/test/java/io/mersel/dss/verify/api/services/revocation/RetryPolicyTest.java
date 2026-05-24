package io.mersel.dss.verify.api.services.revocation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RetryPolicy} invariant testleri — degirsel obje;
 * dogrulanan tum kurallar JavaDoc'taki sozlesmeye karsilik gelir.
 */
class RetryPolicyTest {

    @Test
    @DisplayName("Constructor: maxAttempts < 1 IAE firlatir")
    void rejectsBadMaxAttempts() {
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(0, 100L, 1000L, 2.0d, 0.2d));
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(-1, 100L, 1000L, 2.0d, 0.2d));
    }

    @Test
    @DisplayName("Constructor: negatif initialBackoff IAE firlatir")
    void rejectsNegativeInitialBackoff() {
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, -1L, 1000L, 2.0d, 0.2d));
    }

    @Test
    @DisplayName("Constructor: maxBackoff < initialBackoff IAE firlatir")
    void rejectsMaxLessThanInitial() {
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, 1000L, 500L, 2.0d, 0.2d));
    }

    @Test
    @DisplayName("Constructor: backoffMultiplier < 1.0 IAE firlatir (algoritma diverge eder)")
    void rejectsSubUnitMultiplier() {
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, 100L, 1000L, 0.5d, 0.2d));
    }

    @Test
    @DisplayName("Constructor: jitterRatio < 0 veya > 1 IAE firlatir")
    void rejectsOutOfRangeJitter() {
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, 100L, 1000L, 2.0d, -0.1d));
        assertThrows(IllegalArgumentException.class,
                () -> new RetryPolicy(3, 100L, 1000L, 2.0d, 1.5d));
    }

    @Test
    @DisplayName("disabled(): maxAttempts=1, backoff/jitter etkisiz")
    void disabledFactory() {
        RetryPolicy disabled = RetryPolicy.disabled();
        assertEquals(1, disabled.getMaxAttempts());
        assertEquals(0L, disabled.getInitialBackoffMs());
        assertEquals(0L, disabled.getMaxBackoffMs());
        assertEquals(1.0d, disabled.getBackoffMultiplier(), 0.0d);
        assertEquals(0.0d, disabled.getJitterRatio(), 0.0d);
    }

    @Test
    @DisplayName("computeRawBackoffMs: exponential growth + maxBackoff clamp")
    void backoffGrowsExponentiallyAndClamps() {
        RetryPolicy policy = new RetryPolicy(5, 200L, 2000L, 2.0d, 0.0d);
        assertEquals(200L, policy.computeRawBackoffMs(0));
        assertEquals(400L, policy.computeRawBackoffMs(1));
        assertEquals(800L, policy.computeRawBackoffMs(2));
        assertEquals(1600L, policy.computeRawBackoffMs(3));
        assertEquals(2000L, policy.computeRawBackoffMs(4)); // clamped at maxBackoff
        assertEquals(2000L, policy.computeRawBackoffMs(10));
    }

    @Test
    @DisplayName("computeRawBackoffMs: multiplier=1.0 sabit backoff")
    void constantBackoffWithUnitMultiplier() {
        RetryPolicy policy = new RetryPolicy(5, 500L, 5000L, 1.0d, 0.0d);
        for (int i = 0; i < 5; i++) {
            assertEquals(500L, policy.computeRawBackoffMs(i));
        }
    }

    @Test
    @DisplayName("computeRawBackoffMs: negatif retryIndex IAE firlatir")
    void rejectsNegativeRetryIndex() {
        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.2d);
        assertThrows(IllegalArgumentException.class,
                () -> policy.computeRawBackoffMs(-1));
    }

    @Test
    @DisplayName("toString: debug-friendly tum field'lari icerir")
    void toStringContainsAllFields() {
        String s = new RetryPolicy(3, 200L, 2000L, 2.0d, 0.2d).toString();
        assertTrue(s.contains("maxAttempts=3"));
        assertTrue(s.contains("initialBackoffMs=200"));
        assertTrue(s.contains("maxBackoffMs=2000"));
        assertTrue(s.contains("backoffMultiplier=2.0"));
        assertTrue(s.contains("jitterRatio=0.2"));
    }
}
