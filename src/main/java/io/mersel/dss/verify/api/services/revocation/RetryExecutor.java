package io.mersel.dss.verify.api.services.revocation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Supplier;

/**
 * Generic retry runner — {@link RetryPolicy} kurallarini OCSP ve CRL
 * decorator'lari arasinda paylasilabilir tek bir yere koyar.
 *
 * <h3>Davranis sozlesmesi</h3>
 * <ul>
 *   <li>Supplier {@code RuntimeException} firlatirsa: policy'nin
 *       <code>maxAttempts</code>'i tukenene kadar yeniden dener. Tukendiginde
 *       <strong>son exception olduğu gibi tekrar firlatilir</strong> (cunku
 *       caller — decorator wrapper — bu hatayi mevcut log + cache mantigi
 *       icinde dogru sekilde yakalayip null'a cevirebilsin).</li>
 *   <li>Supplier <code>null</code> donerse: bu transient bir hata DEGIL
 *       (delegate "responder bilmiyorum" demis); retry YAPILMAZ, null
 *       caller'a dondurulur.</li>
 *   <li>Thread interrupt: backoff sleep'i sirasinda
 *       {@link InterruptedException} alirsa interrupt flag restore edilir
 *       ve son hata firlatilir — retry kuyrugu agresif sekilde sonlandirilir
 *       (servis shutdown'i strict kabul edilir).</li>
 * </ul>
 *
 * <h3>Backoff hesabi</h3>
 * <p>{@link RetryPolicy#computeRawBackoffMs(int)} raw backoff'u verir;
 * {@link #applyJitter(long, double)} +/- jitterRatio aralikla rastgele
 * varyasyon ekler. Jitter best-practice: {@code thundering herd}'i
 * (ayni anda dusen N istemci ayni saniyede retry yapip endpoint'i
 * tekrar bombalamak) onlemek icin.</p>
 *
 * <p>Thread-safe (state yok; her cagri kendi loop state'i ile).</p>
 */
public final class RetryExecutor {

    private static final Logger logger = LoggerFactory.getLogger(RetryExecutor.class);

    private final RetryPolicy policy;
    private final Sleeper sleeper;

    public RetryExecutor(RetryPolicy policy, Sleeper sleeper) {
        this.policy = Objects.requireNonNull(policy, "policy must not be null");
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper must not be null");
    }

    public RetryPolicy getPolicy() {
        return policy;
    }

    /**
     * {@code action}'i policy'ye gore retry'la cagirir.
     *
     * @param operation insan-okur etiket (log icin: orn. "OCSP fetch for CN=...")
     * @param action    supplier; {@code null} donerse retry YAPILMAZ
     * @param <T>       donus tipi
     * @return son basarili attempt'in donusu veya tum attempt'lar exception
     *         firlattiysa son exception yeniden firlatilir (tail-call)
     */
    public <T> T execute(String operation, Supplier<T> action) {
        Objects.requireNonNull(operation, "operation label must not be null");
        Objects.requireNonNull(action, "action must not be null");

        int maxAttempts = policy.getMaxAttempts();
        RuntimeException lastException = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                T result = action.get();
                if (attempt > 1) {
                    logger.info("Retry succeeded for '{}' on attempt {}/{}",
                            operation, attempt, maxAttempts);
                }
                return result;
            } catch (RuntimeException e) {
                lastException = e;
                if (attempt >= maxAttempts) {
                    logger.warn("Retry exhausted for '{}' after {} attempt(s); last error: {}",
                            operation, maxAttempts, e.getMessage());
                    break;
                }
                long rawBackoff = policy.computeRawBackoffMs(attempt - 1);
                long sleepMs = applyJitter(rawBackoff, policy.getJitterRatio());
                logger.info("Retrying '{}' after {}ms (next attempt {}/{}); transient error: {}",
                        operation, sleepMs, attempt + 1, maxAttempts, e.getMessage());
                try {
                    if (sleepMs > 0L) {
                        sleeper.sleep(sleepMs);
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    logger.warn("Retry sleep interrupted for '{}'; abandoning retries", operation);
                    throw e;
                }
            }
        }
        // Tum attempt'lar bitti; son exception'i caller'a uzat.
        // lastException null olamaz (loop body'sinde her zaman atanir).
        throw lastException;
    }

    /**
     * {@code raw}'a [-jitterRatio, +jitterRatio] araliginda uniform random
     * varyasyon uygular. {@code jitterRatio == 0.0} ise raw'in kendisini doner
     * (deterministik test).
     *
     * <p>Negatif sonuc olusabilirse 0'a clamp eder — backoff hicbir zaman
     * negatif olmamali.</p>
     */
    static long applyJitter(long rawMs, double jitterRatio) {
        if (rawMs <= 0L || jitterRatio <= 0.0d) {
            return Math.max(0L, rawMs);
        }
        double delta = (ThreadLocalRandom.current().nextDouble() * 2.0d - 1.0d) * jitterRatio;
        long jittered = (long) (rawMs * (1.0d + delta));
        return Math.max(0L, jittered);
    }
}
