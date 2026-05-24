package io.mersel.dss.verify.api.services.revocation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RetryExecutor} davranissal testleri.
 *
 * <p>Bir <em>recording Sleeper</em> kullanarak (gercek Thread.sleep yerine)
 * deterministik testler yaziyoruz; jitterRatio=0.0 ile jitter etkisi
 * test edilebilirligi bozmuyor.</p>
 */
class RetryExecutorTest {

    /**
     * Test yardimcisi: sleep'leri kayit altina alir, gercek sleep yapmaz.
     * RetryExecutor'in beklenen sleep'leri tetikleyip tetiklemedigini dogrularken
     * test sayisini saniyelerce yavaslatmamiz gerekmez.
     */
    private static class RecordingSleeper implements Sleeper {
        final List<Long> sleeps = new ArrayList<>();

        @Override
        public void sleep(long millis) {
            sleeps.add(millis);
        }
    }

    @Test
    @DisplayName("Ilk attempt basariliysa retry yok, sleeper hi&ccedil; cagrilmaz")
    void firstSuccessNoRetry() {
        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RecordingSleeper sleeper = new RecordingSleeper();
        RetryExecutor exec = new RetryExecutor(policy, sleeper);

        AtomicInteger calls = new AtomicInteger(0);
        String result = exec.execute("op", () -> {
            calls.incrementAndGet();
            return "ok";
        });

        assertEquals("ok", result);
        assertEquals(1, calls.get());
        assertTrue(sleeper.sleeps.isEmpty(), "Sleep yapilmamali");
    }

    @Test
    @DisplayName("Transient hata sonrasi 2. attempt basariliysa token doner, 1 kez sleep yapilir")
    void retrySucceedsOnSecondAttempt() {
        RetryPolicy policy = new RetryPolicy(3, 200L, 2000L, 2.0d, 0.0d);
        RecordingSleeper sleeper = new RecordingSleeper();
        RetryExecutor exec = new RetryExecutor(policy, sleeper);

        AtomicInteger calls = new AtomicInteger(0);
        String result = exec.execute("op", () -> {
            int n = calls.incrementAndGet();
            if (n == 1) {
                throw new RuntimeException("transient 503");
            }
            return "ok";
        });

        assertEquals("ok", result);
        assertEquals(2, calls.get());
        assertEquals(1, sleeper.sleeps.size());
        assertEquals(200L, sleeper.sleeps.get(0).longValue()); // initialBackoff (jitter=0)
    }

    @Test
    @DisplayName("Tum attempt'lar basarisizsa son exception caller'a firlatilir")
    void retryExhaustedRethrowsLastException() {
        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RecordingSleeper sleeper = new RecordingSleeper();
        RetryExecutor exec = new RetryExecutor(policy, sleeper);

        RuntimeException lastError = new RuntimeException("third failure");
        AtomicInteger calls = new AtomicInteger(0);
        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                exec.execute("op", () -> {
                    int n = calls.incrementAndGet();
                    if (n < 3) {
                        throw new RuntimeException("attempt " + n);
                    }
                    throw lastError;
                }));

        assertSame(lastError, thrown, "Son exception (3. attempt) firlatilmali");
        assertEquals(3, calls.get());
        assertEquals(2, sleeper.sleeps.size());
        assertEquals(100L, sleeper.sleeps.get(0).longValue());
        assertEquals(200L, sleeper.sleeps.get(1).longValue());
    }

    @Test
    @DisplayName("maxAttempts=1 (retry kapali): delegate bir kez cagrilir, sleep yok")
    void disabledPolicySkipsRetry() {
        RetryPolicy policy = RetryPolicy.disabled();
        RecordingSleeper sleeper = new RecordingSleeper();
        RetryExecutor exec = new RetryExecutor(policy, sleeper);

        AtomicInteger calls = new AtomicInteger(0);
        RuntimeException error = new RuntimeException("boom");
        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                exec.execute("op", () -> {
                    calls.incrementAndGet();
                    throw error;
                }));

        assertSame(error, thrown);
        assertEquals(1, calls.get());
        assertTrue(sleeper.sleeps.isEmpty());
    }

    @Test
    @DisplayName("Supplier null donerse retry YAPILMAZ, null caller'a uzatilir")
    void nullResultNotRetried() {
        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RecordingSleeper sleeper = new RecordingSleeper();
        RetryExecutor exec = new RetryExecutor(policy, sleeper);

        AtomicInteger calls = new AtomicInteger(0);
        Object result = exec.execute("op", () -> {
            calls.incrementAndGet();
            return null;
        });

        assertEquals(null, result);
        assertEquals(1, calls.get());
        assertTrue(sleeper.sleeps.isEmpty());
    }

    @Test
    @DisplayName("Sleep sirasinda interrupt: interrupt flag set + son exception firlatilir")
    void interruptedDuringBackoffAbandons() {
        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        Sleeper interruptingSleeper = millis -> {
            throw new InterruptedException("test interrupt");
        };
        RetryExecutor exec = new RetryExecutor(policy, interruptingSleeper);

        AtomicInteger calls = new AtomicInteger(0);
        RuntimeException error = new RuntimeException("flake");
        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                exec.execute("op", () -> {
                    calls.incrementAndGet();
                    throw error;
                }));

        assertSame(error, thrown);
        assertEquals(1, calls.get(), "Ilk hata sonrasi sleep'te interrupt -> retry yapilmaz");
        assertTrue(Thread.interrupted(), "Thread interrupt flag restore edilmis olmali");
    }

    @Test
    @DisplayName("Exponential backoff: 3 retry boyunca 100, 200, 400 ms sleep eder")
    void exponentialBackoffSleepProgression() {
        RetryPolicy policy = new RetryPolicy(4, 100L, 10_000L, 2.0d, 0.0d);
        RecordingSleeper sleeper = new RecordingSleeper();
        RetryExecutor exec = new RetryExecutor(policy, sleeper);

        AtomicInteger calls = new AtomicInteger(0);
        assertThrows(RuntimeException.class, () ->
                exec.execute("op", () -> {
                    calls.incrementAndGet();
                    throw new RuntimeException("always fail");
                }));

        assertEquals(4, calls.get());
        assertEquals(3, sleeper.sleeps.size());
        assertEquals(100L, sleeper.sleeps.get(0).longValue());
        assertEquals(200L, sleeper.sleeps.get(1).longValue());
        assertEquals(400L, sleeper.sleeps.get(2).longValue());
    }

    @Test
    @DisplayName("applyJitter: jitterRatio=0.0 raw degerini doner")
    void noJitterReturnsRaw() {
        assertEquals(500L, RetryExecutor.applyJitter(500L, 0.0d));
        assertEquals(0L, RetryExecutor.applyJitter(0L, 0.5d));
    }

    @Test
    @DisplayName("applyJitter: jitterRatio uygulandiginda sonuc [raw*(1-r), raw*(1+r)] araligin&dot;a duser")
    void jitterStaysWithinBounds() {
        long raw = 1000L;
        double ratio = 0.2d;
        long min = (long) (raw * (1.0d - ratio));
        long max = (long) (raw * (1.0d + ratio));
        for (int i = 0; i < 500; i++) {
            long jittered = RetryExecutor.applyJitter(raw, ratio);
            assertTrue(jittered >= min - 1L && jittered <= max + 1L,
                    "Jittered value out of bounds: " + jittered + " (expected " + min + "..." + max + ")");
        }
    }
}
