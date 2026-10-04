package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
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
 * {@link RetryingCRLSource} davranissal testleri — {@link RetryingOCSPSourceTest}
 * ile ayni invariantlar, sadece tip CRLSource/CRLToken.
 */
class RetryingCRLSourceTest {

    private CRLSource delegate;
    private CertificateToken cert;
    private CertificateToken issuer;
    private NoOpSleeper sleeper;

    @BeforeEach
    void setUp() {
        delegate = mock(CRLSource.class);
        cert = mockCertificate("CERT-1", "CN=Imzaci");
        issuer = mockCertificate("ISSUER-1", "CN=Issuer CA");
        sleeper = new NoOpSleeper();
    }

    @Test
    @DisplayName("Ilk attempt basariliysa delegate 1 kez cagrilir")
    void firstSuccessNoRetry() {
        CRLToken token = mock(CRLToken.class);
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingCRLSource source = new RetryingCRLSource(delegate, policy, sleeper);

        assertSame(token, source.getRevocationToken(cert, issuer));
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Transient hata + ardindan basari: 2 cagri, token doner")
    void retrySucceedsAfterTransientError() {
        CRLToken token = mock(CRLToken.class);
        when(delegate.getRevocationToken(cert, issuer))
                .thenThrow(transientFailure("CRL DP 503"))
                .thenReturn(token);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingCRLSource source = new RetryingCRLSource(delegate, policy, sleeper);

        assertSame(token, source.getRevocationToken(cert, issuer));
        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Tum attempt'lar basarisizsa son exception caller'a firlatilir")
    void retryExhaustedRethrows() {
        RuntimeException finalError = transientFailure("CRL fetch attempt 3 failed");
        when(delegate.getRevocationToken(cert, issuer))
                .thenThrow(transientFailure("attempt 1"))
                .thenThrow(transientFailure("attempt 2"))
                .thenThrow(finalError);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingCRLSource source = new RetryingCRLSource(delegate, policy, sleeper);

        RuntimeException thrown = assertThrows(RuntimeException.class,
                () -> source.getRevocationToken(cert, issuer));

        assertSame(finalError, thrown);
        verify(delegate, times(3)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Delegate null donerse retry yapilmaz")
    void nullTokenNotRetried() {
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(null);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingCRLSource source = new RetryingCRLSource(delegate, policy, sleeper);

        assertNull(source.getRevocationToken(cert, issuer));
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Retry disabled: tek attempt, ilk hata immediate firlatilir")
    void retryDisabledOneAttempt() {
        RuntimeException error = new RuntimeException("network down");
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(error);

        RetryingCRLSource source = new RetryingCRLSource(delegate, RetryPolicy.disabled(), sleeper);

        assertThrows(RuntimeException.class, () -> source.getRevocationToken(cert, issuer));
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Kalici hata (HTTP 400): retry yapilmaz, ilk hata hemen firlatilir")
    void permanentFailureNotRetried() {
        RuntimeException http400 = RevocationFailureCacheTest.permanentFailure();
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(http400);

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingCRLSource source = new RetryingCRLSource(delegate, policy, sleeper);

        RuntimeException thrown = assertThrows(RuntimeException.class,
                () -> source.getRevocationToken(cert, issuer));
        assertSame(http400, thrown);
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Gecici hata (HTTP 503) hala 3 kez denenir")
    void transientHttpStatusStillRetried() {
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(
                RevocationFailureClassifierTest.dssCrlFailure(new UnacceptableHttpStatusException(503,
                        RevocationFailureClassifierTest.dssStatusMessage(503))));

        RetryPolicy policy = new RetryPolicy(3, 100L, 1000L, 2.0d, 0.0d);
        RetryingCRLSource source = new RetryingCRLSource(delegate, policy, sleeper);

        assertThrows(RuntimeException.class, () -> source.getRevocationToken(cert, issuer));
        verify(delegate, times(3)).getRevocationToken(cert, issuer);
    }

    /** Siniflandiricinin gecici sayacagi bir hata (read timeout). */
    static RuntimeException transientFailure(String message) {
        return new RuntimeException(message, new java.net.SocketTimeoutException("Read timed out"));
    }

    private static class NoOpSleeper implements Sleeper {
        @Override
        public void sleep(long millis) {
            // no-op
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
}
