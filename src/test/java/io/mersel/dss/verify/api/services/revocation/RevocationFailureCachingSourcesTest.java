package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.X500PrincipalHelper;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import io.mersel.dss.verify.api.services.revocation.RevocationFailureCacheTest.FakeTicker;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.LocalHttpServer;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.TestPki;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.util.TimeValue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * {@link LoggingCachingCRLSource} / {@link LoggingCachingOCSPSource} negatif
 * cache + single-flight davranisi.
 *
 * <p>Ana invariant: cache'li bir hata, basarisiz bir fetch'in bugun urettigi
 * sonucun aynisini ({@code null}) dondurur; yalniz ag cagrisi yapilmaz.</p>
 */
class RevocationFailureCachingSourcesTest {

    private CertificateToken cert;
    private CertificateToken issuer;
    private FakeTicker ticker;

    @BeforeEach
    void setUp() {
        cert = mockCertificate("CERT-1", "CN=Imzaci");
        issuer = mockCertificate("ISSUER-1", "CN=Issuer CA");
        ticker = new FakeTicker();
    }

    private RevocationFailureCache failureCache(String kind) {
        return new RevocationFailureCache(kind, 300L, 30L, 100L, ticker, RevocationFailureClassifier.INSTANCE);
    }

    // ------------------------------------------------------------------ CRL

    @Test
    @DisplayName("CRL: kalici hata cache'lenir — ikinci istek delegate'e gitmez, ayni null doner")
    void crlFailureIsCachedAndReturnsSameNull() {
        CRLSource delegate = mock(CRLSource.class);
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(RevocationFailureCacheTest.permanentFailure());
        LoggingCachingCRLSource source = new LoggingCachingCRLSource(delegate, 100L, 60L, null, failureCache("CRL"));

        assertNull(source.getRevocationToken(cert, issuer));
        assertNull(source.getRevocationToken(cert, issuer));
        assertNull(source.getRevocationToken(cert, issuer));

        verify(delegate, times(1)).getRevocationToken(cert, issuer);
        assertEquals(2L, source.failureCache().stats().hitCount());
    }

    @Test
    @DisplayName("CRL: TTL dolunca yeniden fetch edilir; gecici hata kisa TTL ile")
    void crlFailureExpires() {
        CRLSource delegate = mock(CRLSource.class);
        when(delegate.getRevocationToken(cert, issuer))
                .thenThrow(RevocationFailureCacheTest.transientFailure());
        LoggingCachingCRLSource source = new LoggingCachingCRLSource(delegate, 100L, 60L, null, failureCache("CRL"));

        assertNull(source.getRevocationToken(cert, issuer));
        ticker.advanceSeconds(29);
        assertNull(source.getRevocationToken(cert, issuer));
        verify(delegate, times(1)).getRevocationToken(cert, issuer);

        ticker.advanceSeconds(2);
        assertNull(source.getRevocationToken(cert, issuer));
        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("CRL: negatif cache kapaliyken (ttl=0) her istek yeniden fetch eder (eski davranis)")
    void crlDisabledFailureCacheIsLegacy() {
        CRLSource delegate = mock(CRLSource.class);
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(RevocationFailureCacheTest.permanentFailure());
        LoggingCachingCRLSource source = new LoggingCachingCRLSource(delegate, 100L, 60L, null,
                new RevocationFailureCache("CRL", 0L, 0L, 0L));

        assertNull(source.getRevocationToken(cert, issuer));
        assertNull(source.getRevocationToken(cert, issuer));
        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("CRL: hatadan sonra gelen basari normal cache'lenir; null token negatif cache'e girmez")
    void crlSuccessAndEmptyUnaffected() {
        CRLSource delegate = mock(CRLSource.class);
        CRLToken token = mock(CRLToken.class);
        when(token.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(token.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() + 600_000L));
        when(delegate.getRevocationToken(cert, issuer)).thenReturn(null).thenReturn(token);
        LoggingCachingCRLSource source = new LoggingCachingCRLSource(delegate, 100L, 60L, null, failureCache("CRL"));

        assertNull(source.getRevocationToken(cert, issuer));       // empty: not negatively cached
        assertSame(token, source.getRevocationToken(cert, issuer)); // fetched again -> success
        assertSame(token, source.getRevocationToken(cert, issuer)); // positive cache hit
        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("CRL: farkli sertifikalarin hatalari birbirini etkilemez; invalidateAll negatif cache'i de temizler")
    void crlKeysAreIndependent() {
        CertificateToken other = mockCertificate("CERT-2", "CN=Diger");
        CRLSource delegate = mock(CRLSource.class);
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(RevocationFailureCacheTest.permanentFailure());
        when(delegate.getRevocationToken(other, issuer)).thenThrow(RevocationFailureCacheTest.permanentFailure());
        LoggingCachingCRLSource source = new LoggingCachingCRLSource(delegate, 100L, 60L, null, failureCache("CRL"));

        source.getRevocationToken(cert, issuer);
        source.getRevocationToken(other, issuer);
        source.getRevocationToken(cert, issuer);
        verify(delegate, times(1)).getRevocationToken(cert, issuer);
        verify(delegate, times(1)).getRevocationToken(other, issuer);

        source.invalidateAll();
        source.getRevocationToken(cert, issuer);
        verify(delegate, times(2)).getRevocationToken(cert, issuer);
    }

    @Test
    @DisplayName("CRL eszamanlilik: 16 thread ayni hatali sertifika -> tek fetch, hepsi null")
    void crlConcurrentFailuresSingleFlight() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        CRLSource delegate = (c, i) -> {
            calls.incrementAndGet();
            await(release);
            throw RevocationFailureCacheTest.permanentFailure();
        };
        LoggingCachingCRLSource source = new LoggingCachingCRLSource(delegate, 100L, 60L, null, failureCache("CRL"));

        List<CRLToken> results = runConcurrently(16, () -> source.getRevocationToken(cert, issuer), release);

        assertEquals(1, calls.get(), "single fetch for 16 concurrent callers");
        assertEquals(16, results.size());
        for (CRLToken r : results) {
            assertNull(r);
        }
        assertNull(source.getRevocationToken(cert, issuer));
        assertEquals(1, calls.get(), "subsequent call served from failure cache");
    }

    @Test
    @DisplayName("CRL eszamanlilik: basarili fetch de paylasilir (tek fetch, ayni token)")
    void crlConcurrentSuccessSingleFlight() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        CRLToken token = mock(CRLToken.class);
        when(token.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(token.getNextUpdate()).thenReturn(new Date(System.currentTimeMillis() + 600_000L));
        CRLSource delegate = (c, i) -> {
            calls.incrementAndGet();
            await(release);
            return token;
        };
        LoggingCachingCRLSource source = new LoggingCachingCRLSource(delegate, 100L, 60L, null, failureCache("CRL"));

        List<CRLToken> results = runConcurrently(16, () -> source.getRevocationToken(cert, issuer), release);

        assertEquals(1, calls.get());
        for (CRLToken r : results) {
            assertSame(token, r);
        }
    }

    // ----------------------------------------------------------------- OCSP

    @Test
    @DisplayName("OCSP: hata cache'lenir, UNKNOWN ve null eskisi gibi cache'lenmez")
    void ocspFailureCachedUnknownNot() {
        OCSPSource delegate = mock(OCSPSource.class);
        when(delegate.getRevocationToken(cert, issuer)).thenThrow(RevocationFailureCacheTest.permanentFailure());
        LoggingCachingOCSPSource source = new LoggingCachingOCSPSource(delegate, 100L, 60L, null, failureCache("OCSP"));
        assertNull(source.getRevocationToken(cert, issuer));
        assertNull(source.getRevocationToken(cert, issuer));
        verify(delegate, times(1)).getRevocationToken(cert, issuer);

        CertificateToken unknownCert = mockCertificate("CERT-U", "CN=Unknown");
        OCSPToken unknown = mock(OCSPToken.class);
        when(unknown.getStatus()).thenReturn(CertificateStatus.UNKNOWN);
        when(delegate.getRevocationToken(unknownCert, issuer)).thenReturn(unknown);
        assertSame(unknown, source.getRevocationToken(unknownCert, issuer));
        assertSame(unknown, source.getRevocationToken(unknownCert, issuer));
        verify(delegate, times(2)).getRevocationToken(unknownCert, issuer);
    }

    @Test
    @DisplayName("OCSP eszamanlilik: 16 thread -> tek fetch")
    void ocspConcurrentFailuresSingleFlight() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        OCSPSource delegate = (c, i) -> {
            calls.incrementAndGet();
            await(release);
            throw RevocationFailureCacheTest.transientFailure();
        };
        LoggingCachingOCSPSource source = new LoggingCachingOCSPSource(delegate, 100L, 60L, null, failureCache("OCSP"));

        List<OCSPToken> results = runConcurrently(16, () -> source.getRevocationToken(cert, issuer), release);

        assertEquals(1, calls.get());
        for (OCSPToken r : results) {
            assertNull(r);
        }
    }

    // ---------------------------------------------- gercek zincir (yerel HTTP)

    @Test
    @DisplayName("Uretim zinciri (Online + Retrying + LoggingCaching): HTTP 400 -> 1 HTTP istegi, sonra cache")
    void productionChainPermanentFailure() throws Exception {
        try (LocalHttpServer server = LocalHttpServer.start()) {
            server.respond("/root.crl", 400, "bad".getBytes(StandardCharsets.UTF_8));
            TestPki pki = TestPki.create("Chain Signer 400", server.url("/root.crl"), null);
            LoggingCachingCRLSource source = productionCrlChain(failureCache("CRL"));

            assertNull(source.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(1, server.hits("/root.crl"), "permanent failure: no retries");
            assertNull(source.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertNull(source.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(1, server.hits("/root.crl"), "served from failure cache");
        }
    }

    @Test
    @DisplayName("Uretim zinciri: HTTP 500 -> 3 deneme (retry korunur), sonra kisa sureli cache")
    void productionChainTransientFailure() throws Exception {
        try (LocalHttpServer server = LocalHttpServer.start()) {
            server.respond("/root.crl", 500, "oops".getBytes(StandardCharsets.UTF_8));
            TestPki pki = TestPki.create("Chain Signer 500", server.url("/root.crl"), null);
            LoggingCachingCRLSource source = productionCrlChain(failureCache("CRL"));

            assertNull(source.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(3, server.hits("/root.crl"), "transient failure: 1 + 2 retries");
            assertNull(source.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(3, server.hits("/root.crl"));
            ticker.advanceSeconds(31);
            assertNull(source.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(6, server.hits("/root.crl"), "re-fetched after transient TTL");
        }
    }

    private static LoggingCachingCRLSource productionCrlChain(RevocationFailureCache failureCache) {
        CommonsDataLoader loader = new CommonsDataLoader();
        loader.setTimeoutConnection(2_000);
        loader.setTimeoutSocket(2_000);
        loader.setRetryStrategy(new DefaultHttpRequestRetryStrategy(0, TimeValue.ZERO_MILLISECONDS));
        loader.setHttpClientResponseHandler(new StatusAwareHttpClientResponseHandler());
        OnlineCRLSource online = new OnlineCRLSource();
        online.setDataLoader(loader);
        RetryingCRLSource retrying = new RetryingCRLSource(online, new RetryPolicy(3, 200L, 2000L, 2.0d, 0.0d),
                millis -> { /* no sleep in tests */ });
        return new LoggingCachingCRLSource(retrying, 100L, 60L, null, failureCache);
    }

    // ---------------------------------------------------------------- helpers

    private static <T> List<T> runConcurrently(int threads, Callable<T> task, CountDownLatch release)
            throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch ready = new CountDownLatch(threads);
            List<Future<T>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    ready.countDown();
                    return task.call();
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            // Tum thread'lerin lideri bekledigi ana kadar kisa bir pay; lider latch'te bekliyor.
            Thread.sleep(200L);
            release.countDown();
            List<T> results = new ArrayList<>();
            for (Future<T> f : futures) {
                results.add(f.get(10, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static CertificateToken mockCertificate(String dssId, String subjectDn) {
        CertificateToken token = mock(CertificateToken.class);
        when(token.getDSSIdAsString()).thenReturn(dssId);
        X500PrincipalHelper subject = mock(X500PrincipalHelper.class);
        when(subject.getPrettyPrintRFC2253()).thenReturn(subjectDn);
        when(token.getSubject()).thenReturn(subject);
        return token;
    }
}
