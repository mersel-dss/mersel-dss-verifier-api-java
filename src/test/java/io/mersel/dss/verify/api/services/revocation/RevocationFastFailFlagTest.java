package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import io.mersel.dss.verify.api.config.RevocationServicesConfiguration;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.LocalHttpServer;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.TestPki;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Gercek {@link RevocationServicesConfiguration} zinciri uzerinden fast-fail feature flag'i:
 * kapaliyken (varsayilan, canli) her hata v1.0.4'teki gibi yeniden denenir ve hicbir hata
 * hatirlanmaz; aciksa kalici hata (HTTP 400) tek denemede biter ve negatif cache'ten doner.
 */
class RevocationFastFailFlagTest {

    @Test
    @DisplayName("Kapali (varsayilan): CRL 400 her istekte 3 kez denenir, cache yok — v1.0.4 ile ayni")
    void crlDisabledBehavesLikeV104() throws Exception {
        try (LocalHttpServer server = LocalHttpServer.start().respond("/root.crl", 400, null)) {
            TestPki pki = TestPki.create("Flag Off CRL", server.url("/root.crl"), null);
            CRLSource crl = configuration(false).crlSource();

            assertNull(crl.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(3, server.hits("/root.crl"), "1 deneme + 2 retry");
            assertNull(crl.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(6, server.hits("/root.crl"), "hata hatirlanmaz, yeniden fetch edilir");
        }
    }

    @Test
    @DisplayName("Kapali (varsayilan): OCSP 400 her istekte 3 kez denenir, cache yok — v1.0.4 ile ayni")
    void ocspDisabledBehavesLikeV104() throws Exception {
        try (LocalHttpServer server = LocalHttpServer.start().respond("/ocsp", 400, null)) {
            TestPki pki = TestPki.create("Flag Off OCSP", null, server.url("/ocsp"));
            OCSPSource ocsp = configuration(false).ocspSource();

            assertNull(ocsp.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(3, server.hits("/ocsp"), "1 deneme + 2 retry");
            assertNull(ocsp.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(6, server.hits("/ocsp"), "hata hatirlanmaz, yeniden fetch edilir");
        }
    }

    @Test
    @DisplayName("Acik: CRL 400 tek denemede biter, ikinci istek negatif cache'ten doner")
    void crlEnabledFailsFastAndRemembers() throws Exception {
        try (LocalHttpServer server = LocalHttpServer.start().respond("/root.crl", 400, null)) {
            TestPki pki = TestPki.create("Flag On CRL", server.url("/root.crl"), null);
            CRLSource crl = configuration(true).crlSource();

            assertNull(crl.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(1, server.hits("/root.crl"), "kalici hata yeniden denenmez");
            assertNull(crl.getRevocationToken(pki.leafToken(), pki.caToken()));
            assertEquals(1, server.hits("/root.crl"), "negatif cache'ten doner");
        }
    }

    private static RevocationServicesConfiguration configuration(boolean fastFail) {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setRevocationCacheMaxSize(100L);
        config.setRevocationCacheTtlSeconds(60L);
        config.setCrlCacheMaxSize(10L);
        config.setRevocationHttpConnectionTimeoutMs(2_000);
        config.setRevocationHttpSocketTimeoutMs(2_000);
        config.setRevocationHttpConnectionRequestTimeoutMs(2_000);
        config.setRevocationHttpMaxConnectionsPerRoute(5);
        config.setRevocationHttpMaxConnectionsTotal(10);
        config.setRevocationRetryEnabled(true);
        config.setRevocationRetryMaxAttempts(3);
        config.setRevocationRetryInitialBackoffMs(1L);
        config.setRevocationRetryMaxBackoffMs(2L);
        config.setRevocationRetryBackoffMultiplier(1.0d);
        config.setRevocationRetryJitterRatio(0.0d);
        config.setRevocationFastFailEnabled(fastFail);
        config.setRevocationFailureCacheTtlSeconds(300L);
        config.setRevocationFailureCacheTransientTtlSeconds(30L);
        config.setRevocationFailureCacheMaxSize(1000L);
        return new RevocationServicesConfiguration(config, provider(null), provider(null));
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }
}
