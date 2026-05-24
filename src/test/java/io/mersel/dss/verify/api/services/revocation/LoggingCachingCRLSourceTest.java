package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * {@link LoggingCachingCRLSource} davranissal testleri.
 *
 * <p>OCSP wrapper'i ile birebir simetrik bekleyislerle calisir, tek fark:
 * CRL'de "UNKNOWN" statusu ozel olarak handle edilmez (CRL'lerde "bilmiyorum"
 * yok; ya listede iptal var ya yok). Bu yuzden butun statuslar cache'lenir.</p>
 */
class LoggingCachingCRLSourceTest {

    private CRLSource delegate;
    private CertificateToken cert;
    private CertificateToken issuer;
    private LoggingCachingCRLSource source;

    @BeforeEach
    void setUp() {
        delegate = mock(CRLSource.class);
        cert = mockCertificate("CERT-1", "CN=Imzaci");
        issuer = mockCertificate("ISSUER-1", "CN=Issuer CA");
        source = new LoggingCachingCRLSource(delegate, 100L, 60L);
    }

    @Test
    @DisplayName("Constructor: null delegate NullPointerException firlatir")
    void constructorRejectsNullDelegate() {
        assertThrows(NullPointerException.class,
                () -> new LoggingCachingCRLSource(null, 100L, 60L));
    }

    @Test
    @DisplayName("Constructor invariant'lari (maxSize > 0, ttl > 0)")
    void constructorRejectsBadInputs() {
        assertThrows(IllegalArgumentException.class,
                () -> new LoggingCachingCRLSource(delegate, 0L, 60L));
        assertThrows(IllegalArgumentException.class,
                () -> new LoggingCachingCRLSource(delegate, 100L, 0L));
    }

    @Test
    @DisplayName("null cert veya issuer durumunda delegate cagrilmaz")
    void shortCircuitOnNullInputs() {
        assertNull(source.getRevocationToken(null, issuer));
        assertNull(source.getRevocationToken(cert, null));
        verifyNoInteractions(delegate);
    }

    @Test
    @DisplayName("Cache hit: ikinci cagri delegate'e gitmemeli")
    void cacheHitAvoidsDelegate() {
        CRLToken token = mockToken(CertificateStatus.GOOD, new Date(System.currentTimeMillis() + 600_000L));
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        CRLToken first = source.getRevocationToken(cert, issuer);
        CRLToken second = source.getRevocationToken(cert, issuer);

        assertSame(token, first);
        assertSame(token, second);
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("null token cache'lenmez")
    void nullTokenNotCached() {
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(null);

        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(cert, issuer);

        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Delegate exception → null doner, cache'lemez")
    void delegateExceptionReturnsNullAndDoesNotCache() {
        when(delegate.getRevocationToken(cert, issuer))
                .thenThrow(new RuntimeException("CRL DP unreachable"));

        assertNull(source.getRevocationToken(cert, issuer));
        assertNull(source.getRevocationToken(cert, issuer));

        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("REVOKED status cache'lenir")
    void revokedStatusIsCached() {
        CRLToken token = mockToken(CertificateStatus.REVOKED, new Date(System.currentTimeMillis() + 600_000L));
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(cert, issuer);

        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("invalidateAll(): cache temizlenir")
    void invalidateAllClearsCache() {
        CRLToken token = mockToken(CertificateStatus.GOOD, new Date(System.currentTimeMillis() + 600_000L));
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        source.getRevocationToken(cert, issuer);
        source.invalidateAll();
        source.getRevocationToken(cert, issuer);

        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    // ---- helpers -----------------------------------------------------------

    private CertificateToken mockCertificate(String dssId, String subjectDn) {
        CertificateToken token = mock(CertificateToken.class);
        when(token.getDSSIdAsString()).thenReturn(dssId);
        X500PrincipalHelper subject = mock(X500PrincipalHelper.class);
        when(subject.getPrettyPrintRFC2253()).thenReturn(subjectDn);
        when(subject.getCanonical()).thenReturn(subjectDn.toLowerCase());
        when(token.getSubject()).thenReturn(subject);
        return token;
    }

    private CRLToken mockToken(CertificateStatus status, Date nextUpdate) {
        CRLToken token = mock(CRLToken.class);
        when(token.getStatus()).thenReturn(status);
        when(token.getNextUpdate()).thenReturn(nextUpdate);
        when(token.getThisUpdate()).thenReturn(new Date());
        when(token.getSourceURL()).thenReturn("http://crl.kamusm.gov.tr/RootCA.crl");
        return token;
    }
}
