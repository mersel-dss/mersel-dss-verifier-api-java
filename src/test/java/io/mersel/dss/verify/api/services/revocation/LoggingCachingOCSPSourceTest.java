package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * {@link LoggingCachingOCSPSource} davranissal testleri.
 *
 * <p>Test edilen invariantlar:</p>
 * <ul>
 *   <li>Delegate her zaman cache miss durumunda cagrilir, cache hit'te HIC cagrilmaz.</li>
 *   <li>{@code null} ve {@link CertificateStatus#UNKNOWN} cache'lenmez (her seferinde
 *       delegate'e gider).</li>
 *   <li>Delegate {@code RuntimeException} firlatirsa wrapper null doner, sessizce sutum
 *       atmaz; sonraki cagrida tekrar dener (cache'lemez).</li>
 *   <li>{@code null} cert veya issuer durumunda delegate hic cagrilmaz.</li>
 *   <li>Constructor invariant'lari (maxSize > 0, ttl > 0).</li>
 * </ul>
 */
class LoggingCachingOCSPSourceTest {

    private OCSPSource delegate;
    private CertificateToken cert;
    private CertificateToken issuer;
    private LoggingCachingOCSPSource source;

    @BeforeEach
    void setUp() {
        delegate = mock(OCSPSource.class);
        cert = mockCertificate("CERT-1", "CN=Imzaci");
        issuer = mockCertificate("ISSUER-1", "CN=Issuer CA");
        source = new LoggingCachingOCSPSource(delegate, 100L, 60L);
    }

    @Test
    @DisplayName("Constructor: null delegate NullPointerException firlatir")
    void constructorRejectsNullDelegate() {
        assertThrows(NullPointerException.class,
                () -> new LoggingCachingOCSPSource(null, 100L, 60L));
    }

    @Test
    @DisplayName("Constructor: maxSize <= 0 IllegalArgumentException firlatir")
    void constructorRejectsNonPositiveMaxSize() {
        assertThrows(IllegalArgumentException.class,
                () -> new LoggingCachingOCSPSource(delegate, 0L, 60L));
        assertThrows(IllegalArgumentException.class,
                () -> new LoggingCachingOCSPSource(delegate, -1L, 60L));
    }

    @Test
    @DisplayName("Constructor: defaultTtlSeconds <= 0 IllegalArgumentException firlatir")
    void constructorRejectsNonPositiveTtl() {
        assertThrows(IllegalArgumentException.class,
                () -> new LoggingCachingOCSPSource(delegate, 100L, 0L));
        assertThrows(IllegalArgumentException.class,
                () -> new LoggingCachingOCSPSource(delegate, 100L, -1L));
    }

    @Test
    @DisplayName("null cert veya issuer durumunda delegate hic cagrilmaz, null doner")
    void shortCircuitOnNullInputs() {
        OCSPToken r1 = source.getRevocationToken(null, issuer);
        OCSPToken r2 = source.getRevocationToken(cert, null);
        assertNull(r1);
        assertNull(r2);
        verifyNoInteractions(delegate);
    }

    @Test
    @DisplayName("Cache hit: ikinci cagri delegate'e gitmemeli")
    void cacheHitAvoidsDelegate() {
        OCSPToken token = mockToken(CertificateStatus.GOOD, new Date(System.currentTimeMillis() + 600_000L));
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        OCSPToken first = source.getRevocationToken(cert, issuer);
        OCSPToken second = source.getRevocationToken(cert, issuer);

        assertSame(token, first);
        assertSame(token, second);
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("UNKNOWN status cache'lenmez: ikinci cagri yine delegate'e gider")
    void unknownStatusNotCached() {
        OCSPToken token = mockToken(CertificateStatus.UNKNOWN, null);
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(cert, issuer);

        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("null token cache'lenmez: ikinci cagri yine delegate'e gider")
    void nullTokenNotCached() {
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(null);

        assertNull(source.getRevocationToken(cert, issuer));
        assertNull(source.getRevocationToken(cert, issuer));

        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Delegate exception fırlatırsa wrapper null doner, swallow eder, cache'lemez")
    void delegateExceptionReturnsNullAndDoesNotCache() {
        when(delegate.getRevocationToken(cert, issuer))
                .thenThrow(new RuntimeException("network timeout"));

        assertNull(source.getRevocationToken(cert, issuer));
        assertNull(source.getRevocationToken(cert, issuer));

        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("REVOKED status cache'lenir (status sabittir, tekrar fetch gereksiz)")
    void revokedStatusIsCached() {
        OCSPToken token = mockToken(CertificateStatus.REVOKED, new Date(System.currentTimeMillis() + 600_000L));
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token);

        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(cert, issuer);

        verify(delegate, times(1)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("Farkli (cert, issuer) cifti farkli cache key uretir")
    void differentCertsProduceDifferentKeys() {
        CertificateToken cert2 = mockCertificate("CERT-2", "CN=Diger Imzaci");
        OCSPToken token1 = mockToken(CertificateStatus.GOOD, new Date(System.currentTimeMillis() + 600_000L));
        OCSPToken token2 = mockToken(CertificateStatus.GOOD, new Date(System.currentTimeMillis() + 600_000L));
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(token1);
        when(delegate.getRevocationToken(cert2, issuer)).thenReturn(token2);

        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(cert2, issuer);
        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(cert2, issuer);

        verify(delegate, times(1)).getRevocationToken(cert, issuer);
        verify(delegate, times(1)).getRevocationToken(cert2, issuer);
    }

    @Test
    @DisplayName("invalidateAll(): cache temizlenir, sonraki cagri delegate'e gider")
    void invalidateAllClearsCache() {
        OCSPToken token = mockToken(CertificateStatus.GOOD, new Date(System.currentTimeMillis() + 600_000L));
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

    private OCSPToken mockToken(CertificateStatus status, Date nextUpdate) {
        OCSPToken token = mock(OCSPToken.class);
        when(token.getStatus()).thenReturn(status);
        when(token.getNextUpdate()).thenReturn(nextUpdate);
        when(token.getThisUpdate()).thenReturn(new Date());
        when(token.getSourceURL()).thenReturn("http://ocsp.kamusm.gov.tr");
        return token;
    }
}
