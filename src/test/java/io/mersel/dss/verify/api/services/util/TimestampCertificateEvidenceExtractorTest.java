package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.dtos.TimestampVerificationResponseDto;
import io.mersel.dss.verify.api.models.CertificateInfo;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import io.mersel.dss.verify.api.services.timestamp.AdvancedTimestampVerificationService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TimestampCertificateEvidenceExtractorTest {
    @Test
    void signerIsSelectedByCmsSidWhenCaAppearsFirstAndChainUsesVerifiedIssuers() throws Exception {
        Fixture fixture = fixture();
        TimestampToken token = spy(new TimestampToken(fixture.token.getEncoded(), null));
        doReturn(Arrays.asList(fixture.root, fixture.leaf)).when(token).getCertificates();
        CertificateToken selected = TimestampCertificateEvidenceExtractor.selectSigner(token);
        assertEquals(fixture.leaf.getDSSIdAsString(), selected.getDSSIdAsString());
        List<CertificateInfo> chain = TimestampCertificateEvidenceExtractor.exportChain(selected,
                Collections.singletonList(fixture.leaf), fixture.trust, null, new CertificateInfoExtractor());
        assertEquals(2, chain.size(), "Issuer must be resolved from the configured trust store");
        assertEquals(fixture.leaf.getDSSIdAsString(), chain.get(0).getCertificateId());
        assertEquals(fixture.root.getDSSIdAsString(), chain.get(0).getIssuerCertificateId());
        assertTrue(chain.get(1).isTrusted());
        assertArrayEquals(fixture.root.getEncoded(), Base64.getDecoder().decode(chain.get(1).getCertificateBase64()));
        doReturn(Collections.singletonList(fixture.root)).when(token).getCertificates();
        assertNull(TimestampCertificateEvidenceExtractor.selectSigner(token), "Do not select a CA when the SID signer is absent");
    }

    @Test
    void advancedTimestampEndpointExportsActualSignerAndChain() throws Exception {
        Fixture fixture = fixture();
        Security.addProvider(new BouncyCastleProvider());
        AdvancedTimestampVerificationService service = new AdvancedTimestampVerificationService();
        KamusmRootCertificateService roots = mock(KamusmRootCertificateService.class);
        when(roots.getTrustedCertificateSource()).thenReturn(fixture.trust);
        when(roots.getVerificationTrustContext()).thenAnswer(call -> io.mersel.dss.verify.api.services.certificate.RequestTrustContext.server(fixture.trust));
        when(roots.isChainTrusted(any(CertificateToken.class), anyList())).thenReturn(true);
        VerificationConfiguration config = new VerificationConfiguration();
        ReflectionTestUtils.setField(config, "onlineValidationEnabled", false);
        ReflectionTestUtils.setField(service, "rootCertificateService", roots);
        ReflectionTestUtils.setField(service, "config", config);
        ReflectionTestUtils.setField(service, "certificateInfoExtractor", new CertificateInfoExtractor());
        byte[] bytes = fixture.token.getEncoded();
        TimestampVerificationResponseDto response = service.verifyTimestamp(
                new MockMultipartFile("timestampFile", "generated.tst", "application/timestamp-reply", bytes),
                new MockMultipartFile("originalDataFile", "message.bin", "application/octet-stream", fixture.data), true);
        assertTrue(response.isValid(), String.valueOf(response.getErrors()));
        assertEquals(fixture.leaf.getDSSIdAsString(), response.getTsaCertificate().getCertificateId());
        assertEquals(2, response.getCertificateChain().size());
        assertSame(response.getTsaCertificate(), response.getCertificateChain().get(0));
        Path folder = Paths.get("target", "generated-test-fixtures");
        Files.createDirectories(folder);
        Files.write(folder.resolve("generated.tst"), bytes);
        Files.write(folder.resolve("timestamp-original.bin"), fixture.data);
    }

    @Test
    void requestTrustChangesTsaDecisionWithoutMutatingServerRoots() throws Exception {
        Fixture fixture = fixture();
        Security.addProvider(new BouncyCastleProvider());
        AdvancedTimestampVerificationService service = new AdvancedTimestampVerificationService();
        KamusmRootCertificateService roots = mock(KamusmRootCertificateService.class);
        when(roots.getTrustedCertificateSource()).thenReturn(fixture.trust);
        when(roots.getVerificationTrustContext()).thenAnswer(call -> io.mersel.dss.verify.api.services.certificate.RequestTrustContext.server(fixture.trust));
        ReflectionTestUtils.setField(service, "rootCertificateService", roots);
        ReflectionTestUtils.setField(service, "config", new VerificationConfiguration());
        ReflectionTestUtils.setField(service, "certificateInfoExtractor", new CertificateInfoExtractor());
        MockMultipartFile token = new MockMultipartFile("timestampFile", "generated.tst", "application/timestamp-reply", fixture.token.getEncoded());
        io.mersel.dss.verify.api.services.certificate.RequestTrustContext selected =
            new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", Collections.singletonList(fixture.root));
        io.mersel.dss.verify.api.services.certificate.RequestTrustContext empty =
            new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", Collections.emptyList());
        TimestampVerificationResponseDto trusted = service.verifyTimestamp(token, null, true, selected);
        assertTrue(trusted.isValid()); assertTrue(trusted.getTsaCertificate().isTrusted());
        TimestampVerificationResponseDto removed = service.verifyTimestamp(token, null, true, empty);
        assertFalse(removed.isValid()); assertFalse(removed.getTsaCertificate().isTrusted());
        assertEquals(0, removed.getTrustContext().getCertificateCount());
        assertEquals("CUSTOM", removed.getTrustContext().getMode());
        assertEquals(1, fixture.trust.getCertificates().size());
        TimestampVerificationResponseDto standard = service.verifyTimestamp(token, null, true);
        assertTrue(standard.isValid()); assertEquals("SERVER", standard.getTrustContext().getMode());
        io.mersel.dss.verify.api.services.certificate.ActiveTrustStore activeStore = new io.mersel.dss.verify.api.services.certificate.ActiveTrustStore();
        org.mockito.Mockito.when(roots.getVerificationTrustContext()).thenAnswer(call -> activeStore.snapshot(() -> fixture.trust));
        String initialId = activeStore.snapshot(() -> fixture.trust).getActiveTrustId();
        activeStore.replace(initialId, new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", Collections.emptyList()), Collections.emptyList(), () -> fixture.trust);
        assertFalse(service.verifyTimestamp(token, null, true).getTsaCertificate().isTrusted());
        String activeId = activeStore.snapshot(() -> fixture.trust).getActiveTrustId();
        activeStore.replace(activeId, new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", fixture.trust.getCertificates()), Collections.emptyList(), () -> fixture.trust);
        for (int repeat=0; repeat<2; repeat++) assertTrue(service.verifyTimestamp(token, null, true).getTsaCertificate().isTrusted());

    }

    @Test
    void sameIssuerNameWithoutMatchingSignatureCannotBecomeAChainLink() throws Exception {
        Fixture fixture = fixture();
        KeyPair wrongKeys = keys();
        CertificateToken wrongRoot = new CertificateToken(certificate("CN=Test Root", "CN=Test Root", wrongKeys, wrongKeys, true));
        assertNull(TimestampCertificateEvidenceExtractor.findIssuer(fixture.leaf, Collections.singletonList(wrongRoot), null));
    }

    @Test
    void duplicateSidDecoyCannotMaskTheGenuineTimestampSigner() throws Exception {
        Fixture fixture = fixture(true);
        Security.addProvider(new BouncyCastleProvider());
        TimestampToken token = new TimestampToken(fixture.token.getEncoded(), null);
        assertEquals(fixture.leaf.getDSSIdAsString(), TimestampCertificateEvidenceExtractor.selectSigner(token).getDSSIdAsString());
        AdvancedTimestampVerificationService service = new AdvancedTimestampVerificationService();
        Boolean intact = ReflectionTestUtils.invokeMethod(service, "verifyTimestampIntegrity", token, fixture.token.getEncoded());
        assertEquals(Boolean.TRUE, intact, "Integrity verification must use the cryptographically matching SID candidate");
    }

    private static Fixture fixture() throws Exception { return fixture(false); }

    private static Fixture fixture(boolean addDecoy) throws Exception {
        KeyPair rootKeys = keys();
        KeyPair tsaKeys = keys();
        X509Certificate rootCert = certificate("CN=Test Root", "CN=Test Root", rootKeys, rootKeys, true);
        X509Certificate leafCert = certificate("CN=Actual Timestamp Signer", "CN=Test Root", tsaKeys, rootKeys, false);
        DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder().build();
        TimeStampTokenGenerator generator = new TimeStampTokenGenerator(
                new JcaSignerInfoGeneratorBuilder(digests).build(new JcaContentSignerBuilder("SHA256withRSA").build(tsaKeys.getPrivate()), leafCert),
                digests.get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)), new ASN1ObjectIdentifier("1.2.3.4.1"));
        X509Certificate decoy = certificate("CN=D", "CN=Test Root", keys(), rootKeys, false);
        generator.addCertificates(new JcaCertStore(addDecoy ? Arrays.asList(rootCert, decoy, leafCert) : Arrays.asList(rootCert, leafCert)));
        byte[] data = "Mersel offline timestamp fixture".getBytes("UTF-8");
        TimeStampRequestGenerator requests = new TimeStampRequestGenerator();
        requests.setCertReq(true);
        TimeStampRequest request = requests.generate(TSPAlgorithms.SHA256, MessageDigest.getInstance("SHA-256").digest(data));
        Fixture fixture = new Fixture();
        fixture.token = generator.generate(request, BigInteger.valueOf(100), new Date());
        fixture.root = new CertificateToken(rootCert);
        fixture.leaf = new CertificateToken(leafCert);
        fixture.data = data;
        fixture.trust = new CommonTrustedCertificateSource();
        fixture.trust.addCertificate(fixture.root);
        return fixture;
    }

    private static KeyPair keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate certificate(String subject, String issuer, KeyPair key, KeyPair issuerKey, boolean ca) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(new X500Name(issuer), ca ? BigInteger.ONE : BigInteger.TEN,
                new Date(System.currentTimeMillis() - 3600000), new Date(System.currentTimeMillis() + 86400000), new X500Name(subject), key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
        if (!ca) builder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey.getPrivate())));
    }

    private static class Fixture {
        private CertificateToken root;
        private CertificateToken leaf;
        private TimeStampToken token;
        private CommonTrustedCertificateSource trust;
        private byte[] data;
    }
}
