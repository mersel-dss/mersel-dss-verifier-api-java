package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;

import java.util.Objects;

/**
 * CRL source decorator'i — delegate'i {@link RetryExecutor} ile sarar.
 *
 * <p>Tasarim notlari ve davranis sozlesmesi icin
 * {@link RetryingOCSPSource} JavaDoc'una bakin; OCSP ve CRL kosesinde
 * ayni invariant'lar gecerli, sadece dondurulen token tipi farkli.</p>
 *
 * <p>Yalniz <b>gecici</b> hatalar yeniden denenir (timeout, baglanti
 * reset/reddi, HTTP 408/425/429/5xx); kalici hatalar (HTTP 4xx, bozuk CRL,
 * desteklenmeyen protokol) ve DNS hatasi ilk denemede caller'a firlatilir — bkz.
 * {@link RevocationFailureClassifier}.</p>
 *
 * <p>CRL'lerin tipik dosya boyutu (MB seviyesi) ve KamuSM CRL DP'lerin
 * zaman zaman yavas cevap vermesi dusunulurse retry mekanizmasi CRL
 * tarafinda OCSP'den daha sik tetiklenecektir; jitter ozellikle bu
 * akista degerli.</p>
 */
public class RetryingCRLSource implements CRLSource {

    private static final long serialVersionUID = 1L;

    private final transient CRLSource delegate;
    private final transient RetryExecutor retryExecutor;

    public RetryingCRLSource(CRLSource delegate, RetryPolicy policy) {
        this(delegate, policy, Sleeper.threadSleep());
    }

    /**
     * Test constructor — {@link Sleeper} mocklanabilir; hatalar
     * {@link RevocationFailureClassifier} ile siniflandirilir.
     */
    public RetryingCRLSource(CRLSource delegate, RetryPolicy policy, Sleeper sleeper) {
        this(delegate, policy, sleeper, RevocationFailureClassifier.INSTANCE);
    }

    /**
     * Siniflandiriciyi da disaridan alan constructor (test / ozel wiring).
     */
    public RetryingCRLSource(CRLSource delegate, RetryPolicy policy, Sleeper sleeper,
                             FailureClassifier classifier) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.retryExecutor = new RetryExecutor(policy, sleeper, null, null, classifier);
    }

    /**
     * Metrics-aware production constructor — retry olaylarini
     * {@code mdss_revocation_retry_total{type="crl"}} sayacina yazar.
     *
     * @param classifier fast-fail kapaliyken {@link FailureClassifier#retryAll()}
     *                   (her hata yeniden denenir), acikken
     *                   {@link RevocationFailureClassifier#INSTANCE}
     */
    public RetryingCRLSource(CRLSource delegate, RetryPolicy policy,
                             io.mersel.dss.verify.api.metrics.VerificationMetrics metrics,
                             FailureClassifier classifier) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.retryExecutor = new RetryExecutor(policy, Sleeper.threadSleep(), metrics, "crl", classifier);
    }

    @Override
    public CRLToken getRevocationToken(CertificateToken certificateToken,
                                       CertificateToken issuerCertificateToken) {
        String op = buildOperationLabel(certificateToken);
        return retryExecutor.execute(op,
                () -> delegate.getRevocationToken(certificateToken, issuerCertificateToken));
    }

    public RetryPolicy getRetryPolicy() {
        return retryExecutor.getPolicy();
    }

    private static String buildOperationLabel(CertificateToken token) {
        if (token == null) {
            return "CRL fetch (null cert)";
        }
        try {
            return "CRL fetch for " + token.getSubject().getPrettyPrintRFC2253();
        } catch (Exception e) {
            return "CRL fetch for " + token.getDSSIdAsString();
        }
    }
}
