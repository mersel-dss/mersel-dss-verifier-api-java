package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class PdfCertificateEvidenceIntegrationTest {
    private static String previousHeadless;

    @BeforeAll
    static void useHeadlessPdfProcessing() {
        previousHeadless = System.getProperty("java.awt.headless");
        System.setProperty("java.awt.headless", "true");
    }

    @AfterAll
    static void restoreHeadlessProperty() {
        if (previousHeadless == null) System.clearProperty("java.awt.headless");
        else System.setProperty("java.awt.headless", previousHeadless);
    }

    @Test
    void actualSignedPdfExportsTheSignerCertificateDer() throws Exception {
        KeyPairGenerator keys = KeyPairGenerator.getInstance("RSA");
        keys.initialize(2048);
        KeyPair pair = keys.generateKeyPair();
        X500Name name = new X500Name("CN=Generated PDF Signer,O=Mersel Local Test");
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(52), new Date(System.currentTimeMillis() - 60000),
                new Date(System.currentTimeMillis() + 86400000), name, pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate())));
        ByteArrayOutputStream blank = new ByteArrayOutputStream();
        try (PDDocument document = new PDDocument()) {
            document.addPage(new PDPage());
            document.save(blank);
        }
        ByteArrayOutputStream signed = new ByteArrayOutputStream();
        try (PDDocument document = Loader.loadPDF(blank.toByteArray())) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            signature.setName("Generated PDF Signer");
            signature.setSignDate(Calendar.getInstance());
            document.addSignature(signature, input -> {
                try {
                    ByteArrayOutputStream content = new ByteArrayOutputStream();
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = input.read(buffer)) != -1) content.write(buffer, 0, read);
                    ASN1EncodableVector attributes = new ASN1EncodableVector();
                    attributes.add(new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2,
                            new DERSet(new SigningCertificateV2(new ESSCertIDv2(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))))));
                    JcaSignerInfoGeneratorBuilder signer = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build());
                    signer.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
                    CMSSignedDataGenerator cms = new CMSSignedDataGenerator();
                    cms.addSignerInfoGenerator(signer.build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate()), certificate));
                    cms.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));
                    return cms.generate(new CMSProcessableByteArray(content.toByteArray()), false).getEncoded();
                } catch (Exception e) {
                    throw new IOException("Cannot generate the local signed PDF fixture", e);
                }
            });
            document.saveIncremental(signed);
        }
        CommonTrustedCertificateSource trust = new CommonTrustedCertificateSource();
        trust.addCertificate(new CertificateToken(certificate));
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trust);
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signed.toByteArray(), "generated-pades.pdf"));
        validator.setCertificateVerifier(verifier);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_TIMESTAMPS);
        Reports reports = validator.validateDocument();
        assertEquals(1, reports.getDiagnosticData().getSignatureIdList().size());
        SignatureWrapper signature = reports.getDiagnosticData().getSignatureById(reports.getDiagnosticData().getSignatureIdList().get(0));
        assertTrue(signature.isSignatureIntact());
        assertArrayEquals(certificate.getEncoded(), signature.getSigningCertificate().getBinaries());
        assertTrue(signature.getSignatureFormat().name().contains("PAdES") || signature.getSignatureFormat().name().contains("PADES"));
        Path folder = Paths.get("target", "generated-test-fixtures");
        Files.createDirectories(folder);
        Files.write(folder.resolve("generated-pades.pdf"), signed.toByteArray());
    }
}
