package io.mersel.dss.verify.api.services.certificate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.MockMultipartFile;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

class RequestTrustFactoryTest {
    static CertificateToken a, b;
    RequestTrustFactory factory = new RequestTrustFactory(true);
    @BeforeAll static void certificates() throws Exception {
        a = certificate("A"); b = certificate("B -----BEGIN");
    }
    static CertificateToken certificate(String name) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair(); X500Name dn = new X500Name("CN=Test Root " + name);
        // Expired roots are intentional negative-test inputs, not rejected at upload.
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(dn, BigInteger.ONE,
            new Date(0), new Date(1000), dn, keys.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
        return new CertificateToken(cert);
    }
    static MockMultipartFile der(CertificateToken token) { return new MockMultipartFile("trustedCertificates", "root.cer", "application/pkix-cert", token.getEncoded()); }
    static String pem(CertificateToken token) { return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder().encodeToString(token.getEncoded()) + "\n-----END CERTIFICATE-----\n"; }
    @Test void requiresExplicitOptInAndNeverFallsBack() {
        assertNull(new RequestTrustFactory(false).resolve("SERVER", null));
        assertThrows(IllegalArgumentException.class, () -> new RequestTrustFactory(false).resolve("CUSTOM", null));
        assertThrows(IllegalArgumentException.class, () -> factory.resolve("server", null));
        assertThrows(IllegalArgumentException.class, () -> factory.resolve("SERVER", Collections.singletonList(der(a))));
        RequestTrustContext empty = factory.resolve("CUSTOM", null);
        assertTrue(empty.newSource().getCertificates().isEmpty());
        assertEquals("CUSTOM", empty.evidence(false).getMode());
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", empty.evidence(false).getSnapshotSha256());
    }
    @Test void pemDerOrderAndDuplicatesProduceTheSameSnapshot() {
        RequestTrustContext der = factory.resolve("CUSTOM", Arrays.asList(der(a), der(b), der(a)));
        RequestTrustContext pem = factory.resolve("CUSTOM", Collections.singletonList(new MockMultipartFile("trustedCertificates", (pem(b) + pem(a)).getBytes(java.nio.charset.StandardCharsets.US_ASCII))));
        assertEquals(2, pem.evidence(true).getCertificateCount());
        assertTrue(pem.evidence(true).isOnlineValidationEnabled());
        assertEquals(der.evidence(false).getSnapshotSha256(), pem.evidence(false).getSnapshotSha256());
    }
    @Test void invalidInputAndSizeLimitsRejectTheWholeRequest() {
        for (byte[] bad : Arrays.asList(new byte[0], "not a certificate".getBytes(), (pem(a) + "garbage").getBytes(), Arrays.copyOf(a.getEncoded(), a.getEncoded().length + 1), new byte[RequestTrustFactory.MAX_BYTES + 1])) {
            assertThrows(IllegalArgumentException.class, () -> factory.resolve("CUSTOM", Arrays.asList(der(b), new MockMultipartFile("trustedCertificates", bad))));
        }
        assertThrows(IllegalArgumentException.class, () -> factory.resolve("CUSTOM", Collections.nCopies(101, der(a))));
        assertThrows(IllegalArgumentException.class, () -> factory.resolve("CUSTOM", Collections.singletonList(new MockMultipartFile("trustedCertificates", String.join("", Collections.nCopies(101, pem(a))).getBytes()))));
    }
    @Test void concurrentRequestSourcesAndServerSnapshotAreIsolated() throws Exception {
        CommonTrustedCertificateSource shared = new CommonTrustedCertificateSource(); shared.addCertificate(a);
        RequestTrustContext server = RequestTrustContext.server(shared);
        shared.addCertificate(b);
        assertEquals(1, server.evidence(false).getCertificateCount());
        RequestTrustContext custom = factory.resolve("CUSTOM", Collections.singletonList(der(b)));
        ExecutorService executor = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            for (int i = 0; i < 16; i++) { final boolean present = i % 2 == 0; tasks.add(() -> {
                RequestTrustContext context = present ? custom : factory.resolve("CUSTOM", null);
                CommonTrustedCertificateSource source = context.newSource();
                boolean trusted = KamusmRootCertificateService.isChainTrusted(b, Collections.singletonList(b), source);
                source.addCertificate(a);
                assertEquals(present ? 1 : 0, context.newSource().getCertificates().size());
                return trusted == present;
            }); }
            for (Future<Boolean> result : executor.invokeAll(tasks)) assertTrue(result.get());
        } finally { executor.shutdownNow(); }
        assertEquals(2, shared.getCertificates().size());
        assertEquals(1, server.newSource().getCertificates().size());
    }
}
