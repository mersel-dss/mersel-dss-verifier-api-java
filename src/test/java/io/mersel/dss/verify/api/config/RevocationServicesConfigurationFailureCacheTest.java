package io.mersel.dss.verify.api.config;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.mersel.dss.verify.api.services.revocation.LoggingCachingCRLSource;
import io.mersel.dss.verify.api.services.revocation.LoggingCachingOCSPSource;
import io.mersel.dss.verify.api.services.revocation.RevocationFailureCache;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link RevocationServicesConfiguration} negatif cache wiring'i:
 * fast-fail feature flag'i kapaliyken (varsayilan) negatif cache yoktur;
 * aciksa {@code verification.revocation.failure-cache.*} degerleri OCSP/CRL
 * kaynaklarina gecer, metric'ler baglanir, {@code ttl-seconds=0} ozelligi
 * kapatir.
 */
class RevocationServicesConfigurationFailureCacheTest {

    @Test
    @DisplayName("Fast-fail kapali (varsayilan): TTL ayarli olsa da negatif cache yok, metric baglanmaz")
    void fastFailDisabledByDefaultMeansNoFailureCache() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        VerificationConfiguration config = config(300L, 30L, 1000L);
        config.setRevocationFastFailEnabled(false);
        RevocationServicesConfiguration rsc = new RevocationServicesConfiguration(
                config, provider(registry), provider(null));

        assertFalse(new VerificationConfiguration().isRevocationFastFailEnabled(), "flag varsayilan kapali");
        assertFalse(((LoggingCachingCRLSource) rsc.crlSource()).failureCache().isEnabled());
        assertFalse(((LoggingCachingOCSPSource) rsc.ocspSource()).failureCache().isEnabled());
        assertNull(registry.find("cache.gets").tag("cache", RevocationServicesConfiguration.CRL_FAILURE_CACHE_METRIC_NAME).meter());
        assertNull(registry.find("cache.gets").tag("cache", RevocationServicesConfiguration.OCSP_FAILURE_CACHE_METRIC_NAME).meter());
    }

    @Test
    @DisplayName("Fast-fail acik, varsayilan degerler: kalici 300 s, gecici 30 s, max 1000; metric'ler bagli")
    void failureCacheWiredFromConfiguration() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        RevocationServicesConfiguration rsc = new RevocationServicesConfiguration(
                config(300L, 30L, 1000L), provider(registry), provider(null));

        LoggingCachingCRLSource crl = (LoggingCachingCRLSource) rsc.crlSource();
        LoggingCachingOCSPSource ocsp = (LoggingCachingOCSPSource) rsc.ocspSource();

        for (RevocationFailureCache cache : new RevocationFailureCache[]{crl.failureCache(), ocsp.failureCache()}) {
            assertTrue(cache.isEnabled());
            assertEquals(300L, cache.getTtlSeconds());
            assertEquals(30L, cache.getTransientTtlSeconds());
            assertEquals(1000L, cache.getMaxSize());
        }
        assertNotNull(registry.find("cache.gets").tag("cache", RevocationServicesConfiguration.CRL_FAILURE_CACHE_METRIC_NAME).meter());
        assertNotNull(registry.find("cache.gets").tag("cache", RevocationServicesConfiguration.OCSP_FAILURE_CACHE_METRIC_NAME).meter());
    }

    @Test
    @DisplayName("Fast-fail acik + ttl-seconds=0: negatif cache kapali, metric baglanmaz")
    void zeroTtlDisables() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        RevocationServicesConfiguration rsc = new RevocationServicesConfiguration(
                config(0L, 30L, 1000L), provider(registry), provider(null));

        assertFalse(((LoggingCachingCRLSource) rsc.crlSource()).failureCache().isEnabled());
        assertFalse(((LoggingCachingOCSPSource) rsc.ocspSource()).failureCache().isEnabled());
        assertNull(registry.find("cache.gets").tag("cache", RevocationServicesConfiguration.CRL_FAILURE_CACHE_METRIC_NAME).meter());
    }

    private static VerificationConfiguration config(long ttl, long transientTtl, long maxSize) {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setRevocationCacheMaxSize(100L);
        config.setRevocationCacheTtlSeconds(60L);
        config.setCrlCacheMaxSize(10L);
        config.setRevocationHttpConnectionTimeoutMs(1_000);
        config.setRevocationHttpSocketTimeoutMs(1_000);
        config.setRevocationHttpConnectionRequestTimeoutMs(1_000);
        config.setRevocationHttpMaxConnectionsPerRoute(5);
        config.setRevocationHttpMaxConnectionsTotal(10);
        config.setRevocationRetryEnabled(true);
        config.setRevocationRetryMaxAttempts(3);
        config.setRevocationRetryInitialBackoffMs(200L);
        config.setRevocationRetryMaxBackoffMs(2_000L);
        config.setRevocationRetryBackoffMultiplier(2.0d);
        config.setRevocationRetryJitterRatio(0.2d);
        config.setRevocationFastFailEnabled(true);
        config.setRevocationFailureCacheTtlSeconds(ttl);
        config.setRevocationFailureCacheTransientTtlSeconds(transientTtl);
        config.setRevocationFailureCacheMaxSize(maxSize);
        return config;
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> provider(T value) {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(value);
        return provider;
    }

}
