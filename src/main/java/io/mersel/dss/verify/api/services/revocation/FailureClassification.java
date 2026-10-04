package io.mersel.dss.verify.api.services.revocation;

import java.util.Objects;

/**
 * Bir revocation (OCSP/CRL) fetch hatasinin siniflandirmasi.
 *
 * <ul>
 *   <li><b>Gecici (transient)</b> — kisa sure sonra ayni istek basarili
 *       olabilir (timeout, baglanti reset/reddi, HTTP 408/425/429/5xx,
 *       OCSP {@code TRY_LATER}). {@link RetryExecutor} bu hatalarda yeniden
 *       dener.</li>
 *   <li><b>Gecici, retry'siz</b> — ortamdan kaynaklanir ve kisa surede
 *       duzelebilir, ama saniye-alti retry ayni sonucu alir (DNS cozumleme
 *       hatasi: JVM negatif DNS cache'i ~10 s). Yeniden denenmez; negatif
 *       cache'te gecici hata TTL'i ile tutulur.</li>
 *   <li><b>Kalici (permanent)</b> — ayni istek ayni cevabi uretir (HTTP 4xx,
 *       bozuk/okunamayan CRL/OCSP cevabi, desteklenmeyen protokol). Retry
 *       yalniz gecikme ekler; yapilmaz.</li>
 * </ul>
 *
 * <p>{@link #getReason()} log/metrik icin kisa, gizli bilgi icermeyen bir
 * etikettir (orn. {@code "HTTP 400"}, {@code "read/connect timeout"}).</p>
 *
 * <p>Immutable; thread-safe paylasilabilir.</p>
 */
public final class FailureClassification {

    private final boolean retryable;
    private final boolean transientFailure;
    private final String reason;

    private FailureClassification(boolean retryable, boolean transientFailure, String reason) {
        this.retryable = retryable;
        this.transientFailure = transientFailure;
        this.reason = Objects.requireNonNull(reason, "reason must not be null");
    }

    public static FailureClassification transientFailure(String reason) {
        return new FailureClassification(true, true, reason);
    }

    /**
     * Gecici ama yeniden denemeye degmeyen hata (orn. DNS): retry yapilmaz,
     * negatif cache'te gecici hata TTL'i kullanilir.
     */
    public static FailureClassification transientNoRetry(String reason) {
        return new FailureClassification(false, true, reason);
    }

    public static FailureClassification permanentFailure(String reason) {
        return new FailureClassification(false, false, reason);
    }

    /** {@code true} ise hemen yeniden denemek anlamlidir. */
    public boolean isRetryable() {
        return retryable;
    }

    /**
     * {@code true} ise hata gecicidir (retry'li ya da retry'siz); negatif
     * cache kisa (gecici hata) TTL'ini kullanir.
     */
    public boolean isTransient() {
        return transientFailure;
    }

    public String getReason() {
        return reason;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FailureClassification)) {
            return false;
        }
        FailureClassification that = (FailureClassification) o;
        return retryable == that.retryable
                && transientFailure == that.transientFailure
                && reason.equals(that.reason);
    }

    @Override
    public int hashCode() {
        return Objects.hash(retryable, transientFailure, reason);
    }

    @Override
    public String toString() {
        String kind = retryable ? "transient" : (transientFailure ? "transient, not retried" : "permanent");
        return kind + " (" + reason + ")";
    }
}
