package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;

import java.util.Objects;

/**
 * OCSP source decorator'i — delegate'i {@link RetryExecutor} ile sarar.
 *
 * <h3>Nerede konumlanir?</h3>
 * <p>{@code RevocationServicesConfiguration} icindeki onerilen sira:</p>
 * <pre>
 *   OnlineOCSPSource (DSS)
 *     -> RetryingOCSPSource     [bu sinif]
 *       -> LoggingCachingOCSPSource
 *         -> CertificateVerifier
 * </pre>
 * <p>Yani cache <em>dis</em> katmanda — cache hit retry'a girmez, sadece
 * gercek HTTP fetch hatalarinda retry akisi tetiklenir.</p>
 *
 * <h3>Davranis</h3>
 * <ul>
 *   <li>Delegate {@code null} donerse retry YAPILMAZ — bu "responder
 *       cevap verdi ama token uretemedi" anlami tasir (transient degil).</li>
 *   <li>Delegate {@code RuntimeException} firlatirsa policy'ye gore retry'a
 *       girilir. Tum attempt'lar tukendiginde son exception caller'a
 *       firlatilir; caller (genellikle {@code LoggingCachingOCSPSource})
 *       WARN'lar ve null doner -> DSS strict policy'sinde imzayi
 *       INDETERMINATE / NO_REVOCATION_DATA olarak isaretler.</li>
 *   <li>{@code null} cert veya issuer girisi: delegate hi&ccedil; cagrilmaz.
 *       Bu sinif sadece delegate'in retry decoration'unu yapar; argument
 *       validation delegate'in sorumlulugu (ust katmanlar bu null check'i
 *       zaten yapiyor).</li>
 * </ul>
 *
 * <p>Thread-safe — durumsuz, tum state {@code RetryExecutor} icinde.</p>
 */
public class RetryingOCSPSource implements OCSPSource {

    private static final long serialVersionUID = 1L;

    private final transient OCSPSource delegate;
    private final transient RetryExecutor retryExecutor;

    /**
     * Production constructor — gercek {@link Thread#sleep(long)} kullanir.
     */
    public RetryingOCSPSource(OCSPSource delegate, RetryPolicy policy) {
        this(delegate, policy, Sleeper.threadSleep());
    }

    /**
     * Test constructor — caller'in {@link Sleeper}'i mocklamasina izin verir.
     */
    public RetryingOCSPSource(OCSPSource delegate, RetryPolicy policy, Sleeper sleeper) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.retryExecutor = new RetryExecutor(policy, sleeper);
    }

    /**
     * Metrics-aware production constructor — retry olaylarini
     * {@code mdss_revocation_retry_total{type="ocsp"}} sayacina yazar.
     */
    public RetryingOCSPSource(OCSPSource delegate, RetryPolicy policy,
                              io.mersel.dss.verify.api.metrics.VerificationMetrics metrics) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.retryExecutor = new RetryExecutor(policy, Sleeper.threadSleep(), metrics, "ocsp");
    }

    @Override
    public OCSPToken getRevocationToken(CertificateToken certificateToken,
                                        CertificateToken issuerCertificateToken) {
        String op = buildOperationLabel(certificateToken);
        return retryExecutor.execute(op,
                () -> delegate.getRevocationToken(certificateToken, issuerCertificateToken));
    }

    /**
     * Diagnostic — bu source'un kullandigi politika referansi.
     * Yalniz operasyonel inspection icin expose ediliyor.
     */
    public RetryPolicy getRetryPolicy() {
        return retryExecutor.getPolicy();
    }

    private static String buildOperationLabel(CertificateToken token) {
        if (token == null) {
            return "OCSP fetch (null cert)";
        }
        try {
            return "OCSP fetch for " + token.getSubject().getPrettyPrintRFC2253();
        } catch (Exception e) {
            return "OCSP fetch for " + token.getDSSIdAsString();
        }
    }
}
