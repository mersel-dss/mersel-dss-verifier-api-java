package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link RetryingOCSPSource} davranissal testleri.
 *
 * <p>Wrapper'in sozlesmesi: delegate'i {@link RetryExecutor} ile sarar.
 * Burada test edilen invariantlar:</p>
 * <ul>
 *   <li>Delegate basariliysa retry yapilmaz</li>
 *   <li>Transient hata sonrasi retry basariliysa token doner</li>
 *   <li>Tum attempt'lar tukenirse son exception caller'a uzatilir
 *       (LoggingCachingOCSPSource bunu null'a cevirir)</li>
 *   <li>Delegate {@code null} donerse retry yapilmaz</li>
 * </ul>
 */
class RetryingOCSPSourceTest {

    private OCSPSource delegate;
    private CertificateToken cert;
    private CertificateToken issuer;
    private NoOpSleeper sleeper;

    @BeforeEach
    void setUp() {
        delegate = mock(OCSPSource.class);
        cert = mockCertificate("CERT-1", "CN=Imzaci");
        issuer = mockCertificate("ISSUER-1", "CN=Issuer CA");
        sleeper = new NoOpSleeper();
    }

    @Test
    @DisplayName("Ilk attempt basariliysa delegate 1 kez cagrilir, sleep yok")
    void firstSuccessNoRetry() {
        OCSPToken token = mockToken(CertificateStatus.GOOD);
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingOCSPSource source = new RetryingOCSPSource(delegate, policy, sleeper);

        OCSPToken result = source.getRevocationToken(cert, issuer);

        assertSame(token, result);
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Transient hata + ardindan basari: delegate 2 kez cagrilir, token doner")
    void retrySucceedsAfterTransientError() {
        OCSPToken token = mockToken(CertificateStatus.GOOD);
        when(delegate.getRevocationToken(cert, issuer))
                .thenThrow(new RuntimeException("transient 503"))
                .thenReturn(token);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingOCSPSource source = new RetryingOCSPSource(delegate, policy, sleeper);

        OCSPToken result = source.getRevocationToken(cert, issuer);

        assertSame(token, result);
        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Tum attempt'lar basarisizsa son exception caller'a firlatilir")
    void retryExhaustedRethrows() {
        RuntimeException finalError = new RuntimeException("attempt 3 failed");
        when(delegate.getRevocationToken(cert, issuer))
                .thenThrow(new RuntimeException("attempt 1"))
                .thenThrow(new RuntimeException("attempt 2"))
                .thenThrow(finalError);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingOCSPSource source = new RetryingOCSPSource(delegate, policy, sleeper);

        RuntimeException thrown = assertThrows(RuntimeException.class,
                () -> source.getRevocationToken(cert, issuer));

        assertSame(finalError, thrown);
        verify(delegate, times(3)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Delegate null donerse retry yapilmaz, null caller'a uzatilir")
    void nullTokenNotRetried() {
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(null);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingOCSPSource source = new RetryingOCSPSource(delegate, policy, sleeper);

        assertNull(source.getRevocationToken(cert, issuer));
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Retry disabled: tek attempt, ilk hata immediate firlatilir")
    void retryDisabledOneAttempt() {
        RuntimeException error = new RuntimeException("network down");
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(error);

        RetryingOCSPSource source = new RetryingOCSPSource(delegate, RetryPolicy.disabled(), sleeper);

        assertThrows(RuntimeException.class, () -> source.getRevocationToken(cert, issuer));
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("getRetryPolicy(): expose edilen policy constructor'a verilenle ayni")
    void exposesPolicy() {
        RetryPolicy policy = new RetryPolicy(5, 250L, 5000L, 3.0d, 0.1d);
        RetryingOCSPSource source = new RetryingOCSPSource(delegate, policy, sleeper);

        assertSame(policy, source.getRetryPolicy());
    }

    // ---- helpers -----------------------------------------------------------

    private static class NoOpSleeper implements Sleeper {
        @Override
        public void sleep(long millis) {
            // no-op: testleri saniyelerce yavaslatmamak icin
        }
    }

    private CertificateToken mockCertificate(String dssId, String subjectDn) {
        CertificateToken token = mock(CertificateToken.class);
        when(token.getDSSIdAsString()).thenReturn(dssId);
        X500PrincipalHelper subject = mock(X500PrincipalHelper.class);
        when(subject.getPrettyPrintRFC2253()).thenReturn(subjectDn);
        when(token.getSubject()).thenReturn(subject);
        return token;
    }

    private OCSPToken mockToken(CertificateStatus status) {
        OCSPToken token = mock(OCSPToken.class);
        when(token.getStatus()).thenReturn(status);
        return token;
    }
}
