package io.mersel.dss.verify.api.services.revocation;

/**
 * Revocation source (OCSP / CRL) cagrilari icin retry politikasi.
 *
 * <h3>Neden retry?</h3>
 * <p>KamuSM / GIB OCSP responder'lari ve CRL distribution point'leri zaman zaman
 * gecici 5xx, connection reset veya TLS handshake hatalari uretir; 200-2000ms
 * icinde normale doner. <strong>Strict politika</strong> (signer-strict /
 * strict) revocation verisi ZORUNLU oldugundan tek bir transient hata
 * geceri bir e-Faturayi <code>INDETERMINATE/NO_REVOCATION_DATA</code>'ya
 * dusurur. Retry, gercek bir endpoint kesintisi ile saniyelik flake'i
 * birbirinden ayirir: anlik flake'te imza valid kalir, ger&ccedil;ek
 * kesinti'de hala FAIL doner (cunku tum attempt'lar bitti).</p>
 *
 * <h3>Algoritma — exponential backoff + jitter</h3>
 * <pre>
 *   delay(n)  = min(initialBackoffMs * multiplier^(n-1), maxBackoffMs)
 *   sleepMs   = delay * (1 + uniform(-jitterRatio, +jitterRatio))
 * </pre>
 * <p>Jitter bilincli: ayni anda dusen N istemci ayni retry penceresine
 * carpip "thundering herd" yapmasin diye standart bir best-practice.</p>
 *
 * <h3>Sinif invariantlari</h3>
 * <ul>
 *   <li><code>maxAttempts &ge; 1</code> — 1 = retry yok (sadece ilk deneme).</li>
 *   <li><code>initialBackoffMs &ge; 0</code></li>
 *   <li><code>maxBackoffMs &ge; initialBackoffMs</code></li>
 *   <li><code>backoffMultiplier &ge; 1.0</code> — ge&ccedil;mi&scedil;e
 *       gore kucuk backoff kabul edilmez (algoritma diverge eder).</li>
 *   <li><code>0 &le; jitterRatio &le; 1.0</code></li>
 * </ul>
 *
 * <p>Immutable + final field'lar — thread-safe paylasilabilir.</p>
 */
public final class RetryPolicy {

    private final int maxAttempts;
    private final long initialBackoffMs;
    private final long maxBackoffMs;
    private final double backoffMultiplier;
    private final double jitterRatio;

    public RetryPolicy(int maxAttempts,
                       long initialBackoffMs,
                       long maxBackoffMs,
                       double backoffMultiplier,
                       double jitterRatio) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException(
                    "maxAttempts must be >= 1 (1 = no retry), was: " + maxAttempts);
        }
        if (initialBackoffMs < 0) {
            throw new IllegalArgumentException(
                    "initialBackoffMs must be >= 0, was: " + initialBackoffMs);
        }
        if (maxBackoffMs < initialBackoffMs) {
            throw new IllegalArgumentException(
                    "maxBackoffMs (" + maxBackoffMs + ") must be >= initialBackoffMs (" + initialBackoffMs + ")");
        }
        if (backoffMultiplier < 1.0d) {
            throw new IllegalArgumentException(
                    "backoffMultiplier must be >= 1.0, was: " + backoffMultiplier);
        }
        if (jitterRatio < 0.0d || jitterRatio > 1.0d) {
            throw new IllegalArgumentException(
                    "jitterRatio must be in [0.0, 1.0], was: " + jitterRatio);
        }
        this.maxAttempts = maxAttempts;
        this.initialBackoffMs = initialBackoffMs;
        this.maxBackoffMs = maxBackoffMs;
        this.backoffMultiplier = backoffMultiplier;
        this.jitterRatio = jitterRatio;
    }

    /**
     * Retry'i tamamen devre disi birakan policy — yalniz ilk deneme yapilir.
     * Operatör <code>verification.revocation.retry.enabled=false</code> dedikten
     * sonra <code>RevocationServicesConfiguration</code> bu instance'i kullanir.
     */
    public static RetryPolicy disabled() {
        return new RetryPolicy(1, 0L, 0L, 1.0d, 0.0d);
    }

    public int getMaxAttempts() {
        return maxAttempts;
    }

    public long getInitialBackoffMs() {
        return initialBackoffMs;
    }

    public long getMaxBackoffMs() {
        return maxBackoffMs;
    }

    public double getBackoffMultiplier() {
        return backoffMultiplier;
    }

    public double getJitterRatio() {
        return jitterRatio;
    }

    /**
     * {@code attempt} 0-tabanli — 0. retry icin initialBackoff, 1. icin
     * initialBackoff * multiplier, vb. {@link #maxBackoffMs} ust sinir.
     * Jitter UYGULANMAZ — caller jitter'i sleep oncesi ayri uygular ki
     * test edilebilirlik korunsun.
     *
     * @param retryIndex 0-tabanli retry sirasi (1. retry = 0)
     * @return jitter'siz raw backoff suresi (ms)
     */
    long computeRawBackoffMs(int retryIndex) {
        if (retryIndex < 0) {
            throw new IllegalArgumentException("retryIndex must be >= 0, was: " + retryIndex);
        }
        double raw = initialBackoffMs * Math.pow(backoffMultiplier, retryIndex);
        if (raw >= (double) maxBackoffMs) {
            return maxBackoffMs;
        }
        return Math.max(0L, (long) raw);
    }

    @Override
    public String toString() {
        return "RetryPolicy{" +
                "maxAttempts=" + maxAttempts +
                ", initialBackoffMs=" + initialBackoffMs +
                ", maxBackoffMs=" + maxBackoffMs +
                ", backoffMultiplier=" + backoffMultiplier +
                ", jitterRatio=" + jitterRatio +
                '}';
    }
}
