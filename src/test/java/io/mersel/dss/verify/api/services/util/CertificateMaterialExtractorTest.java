package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.model.x509.CertificateToken;
import io.mersel.dss.verify.api.models.CertificateInfo;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class CertificateMaterialExtractorTest {
    public static X509Certificate certificate(String algorithm) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if ("EC".equals(algorithm)) generator.initialize(new ECGenParameterSpec("secp256r1"));
        else generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        X500Name name = new X500Name("CN=Backend Certificate Test,O=Mersel");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(42),
                new Date(System.currentTimeMillis() - 3600000), new Date(System.currentTimeMillis() + 86400000), name, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(2));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation
                | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement
                | KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.encipherOnly | KeyUsage.decipherOnly));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(
                new PolicyInformation(new ASN1ObjectIdentifier("2.16.792.1.2.1.1.5.7.1.3.1"))));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(
                new GeneralName(GeneralName.dNSName, "verifier.test")));
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder(
                "EC".equals(algorithm) ? "SHA256withECDSA" : "SHA256withRSA").build(pair.getPrivate())));
    }

    @Test
    void exportsExactDerAndFingerprintsWithoutChangingDssVerdict() throws Exception {
        X509Certificate certificate = certificate("RSA");
        CertificateInfo info = new CertificateInfo();
        info.setTrusted(true);
        info.setRevoked(true);
        info.setValid(false);
        CertificateMaterialExtractor.enrich(info, certificate.getEncoded());
        assertArrayEquals(certificate.getEncoded(), Base64.getDecoder().decode(info.getCertificateBase64()));
        assertEquals(CertificateMaterialExtractor.hex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())), info.getSha256Fingerprint());
        assertEquals(40, info.getSha1Fingerprint().length());
        assertEquals(2048, info.getPublicKeySize());
        assertEquals(9, info.getKeyUsages().size());
        assertEquals("2.16.792.1.2.1.1.5.7.1.3.1", info.getCertificatePolicyOids().get(0));
        assertTrue(info.getExtendedKeyUsages().contains("1.3.6.1.5.5.7.3.8"));
        assertTrue(info.getCriticalExtensionOids().contains("2.5.29.15"));
        assertTrue(info.getNonCriticalExtensionOids().contains("2.5.29.32"));
        assertTrue(info.getSubjectAlternativeNames().contains("2: verifier.test"));
        assertEquals(Boolean.TRUE, info.getCertificateAuthority());
        assertEquals(2, info.getBasicConstraints());
        assertTrue(info.isTrusted());
        assertTrue(info.isRevoked());
        assertFalse(info.isValid());
    }

    @Test
    void tokenExtractorAlsoExportsEcCertificateForStandaloneTimestampPath() throws Exception {
        X509Certificate certificate = certificate("EC");
        CertificateInfo info = new CertificateInfoExtractor().extractCertificateInfo(new CertificateToken(certificate));
        assertArrayEquals(certificate.getEncoded(), Base64.getDecoder().decode(info.getCertificateBase64()));
        assertEquals("EC", info.getPublicKeyAlgorithm());
        assertEquals(256, info.getPublicKeySize());
        assertNotNull(info.getCertificateId());
    }

    @Test
    void missingOrMalformedBytesDoNotHideDiagnosticCertificate() {
        CertificateInfo info = new CertificateInfo();
        info.setSubject("CN=Diagnostic only");
        CertificateMaterialExtractor.enrich(info, (byte[]) null);
        CertificateMaterialExtractor.enrich(info, new byte[] {1, 2, 3});
        assertEquals("CN=Diagnostic only", info.getSubject());
        assertNull(info.getCertificateBase64());
        assertNull(info.getSha256Fingerprint());
    }
}
