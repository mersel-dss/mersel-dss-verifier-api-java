package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.TokenExtractionStrategy;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.verify.api.models.SignatureInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Local generated signatures exercise the actual DSS diagnostic pipeline without remote services. */
class DssEvidenceIntegrationTest {
    @Test
    void realDssExportsCertificateBytesAndCryptographicCounterSignatureRelationship() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=Local Counter Signature Test");
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.ONE, new Date(System.currentTimeMillis() - 60000),
                        new Date(System.currentTimeMillis() + 86400000), name, keys.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
        DocumentBuilderFactory documents = DocumentBuilderFactory.newInstance();
        documents.setNamespaceAware(true);
        Document document = documents.newDocumentBuilder().newDocument();
        Element root = document.createElement("Invoice");
        root.setTextContent("Generated offline test invoice");
        document.appendChild(root);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        KeyInfo keyInfo = factory.getKeyInfoFactory().newKeyInfo(Collections.singletonList(
                factory.getKeyInfoFactory().newX509Data(Collections.singletonList(certificate))));
        Reference content = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)), null, "document-ref");
        sign(factory, root, keys, keyInfo, content, "parent-signature", "parent-value");
        Element parent = (Element) document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature").item(0);
        Element signatureValue = (Element) parent.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureValue").item(0);
        signatureValue.setIdAttribute("Id", true);
        Element object = document.createElementNS(XMLSignature.XMLNS, "ds:Object");
        parent.appendChild(object);
        String xades = "http://uri.etsi.org/01903/v1.3.2#";
        Element properties = document.createElementNS(xades, "xades:QualifyingProperties");
        properties.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:xades", xades);
        properties.setAttribute("Target", "#parent-signature");
        object.appendChild(properties);
        Element unsigned = document.createElementNS(xades, "xades:UnsignedProperties");
        properties.appendChild(unsigned);
        Element unsignedSignature = document.createElementNS(xades, "xades:UnsignedSignatureProperties");
        unsigned.appendChild(unsignedSignature);
        Element counter = document.createElementNS(xades, "xades:CounterSignature");
        unsignedSignature.appendChild(counter);
        Reference parentValue = factory.newReference("#parent-value", factory.newDigestMethod(DigestMethod.SHA256, null),
                null, "http://uri.etsi.org/01903#CountersignedSignature", "counter-ref");
        sign(factory, counter, keys, keyInfo, parentValue, "counter-signature", "counter-value");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(output));
        CommonTrustedCertificateSource trust = new CommonTrustedCertificateSource();
        trust.addCertificate(new CertificateToken(certificate));
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trust);
        // No AIA, OCSP, CRL or network data loaders are configured.
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(output.toByteArray(), "counter.xml"));
        validator.setCertificateVerifier(verifier);
        validator.setTokenExtractionStrategy(TokenExtractionStrategy.EXTRACT_CERTIFICATES_AND_TIMESTAMPS);
        Reports reports = validator.validateDocument();
        List<String> ids = reports.getDiagnosticData().getSignatureIdList();
        assertEquals(2, ids.size());
        List<SignatureInfo> evidence = new ArrayList<>();
        SignatureWrapper counterWrapper = null;
        for (String id : ids) {
            SignatureWrapper signature = reports.getDiagnosticData().getSignatureById(id);
            assertTrue(signature.isSignatureIntact(), "Generated signatures must remain cryptographically intact");
            assertArrayEquals(certificate.getEncoded(), signature.getSigningCertificate().getBinaries());
            SignatureInfo info = new SignatureInfo();
            info.setSignatureId(id);
            SignatureEvidenceExtractor.enrich(info, signature);
            evidence.add(info);
            if (signature.isCounterSignature()) counterWrapper = signature;
        }
        io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService service = new io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService();
        io.mersel.dss.verify.api.config.VerificationConfiguration config = new io.mersel.dss.verify.api.config.VerificationConfiguration();
        org.springframework.test.util.ReflectionTestUtils.setField(config, "strictMode", true);
        org.springframework.test.util.ReflectionTestUtils.setField(service, "config", config);
        org.springframework.test.util.ReflectionTestUtils.setField(service, "resourceLoader", new org.springframework.core.io.DefaultResourceLoader());
        org.springframework.test.util.ReflectionTestUtils.setField(service, "dssValidationLocale", java.util.Locale.ENGLISH);
        org.springframework.test.util.ReflectionTestUtils.setField(service, "xadesPackagingDetector", new XadesSignaturePackagingDetector());
        org.springframework.test.util.ReflectionTestUtils.setField(service, "legacyTrXadesDetector", new LegacyTurkishXadesTypeUriDetector());
        org.springframework.test.util.ReflectionTestUtils.setField(service, "revocationInfoExtractor", new RevocationInfoExtractor());
        io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService roots = org.mockito.Mockito.mock(io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService.class);
        org.mockito.Mockito.when(roots.getTrustedCertificateSource()).thenReturn(trust);
        org.mockito.Mockito.when(roots.getVerificationTrustContext()).thenAnswer(call -> io.mersel.dss.verify.api.services.certificate.RequestTrustContext.server(trust));
        org.springframework.test.util.ReflectionTestUtils.setField(service, "rootCertificateService", roots);
        org.springframework.mock.web.MockMultipartFile file = new org.springframework.mock.web.MockMultipartFile("signedDocument", "generated.xml", "text/xml", output.toByteArray());
        io.mersel.dss.verify.api.services.certificate.RequestTrustContext selected = new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", trust.getCertificates());
        io.mersel.dss.verify.api.services.certificate.RequestTrustContext empty = new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", Collections.emptyList());
        io.mersel.dss.verify.api.models.VerificationResult withRoot = service.verifySignature(file, null, io.mersel.dss.verify.api.models.enums.VerificationLevel.COMPREHENSIVE, true, selected);
        assertEquals(1, withRoot.getTrustContext().getCertificateCount());
        assertTrue(withRoot.getSignatures().get(0).getSignerCertificate().isTrusted());
        io.mersel.dss.verify.api.models.VerificationResult withoutRoot = service.verifySignature(file, null, io.mersel.dss.verify.api.models.enums.VerificationLevel.COMPREHENSIVE, true, empty);
        assertEquals(0, withoutRoot.getTrustContext().getCertificateCount());
        assertFalse(withoutRoot.getSignatures().get(0).getSignerCertificate().isTrusted());
        assertFalse(withoutRoot.isValid());
        org.mockito.Mockito.verifyNoInteractions(roots);
        io.mersel.dss.verify.api.models.VerificationResult standard = service.verifySignature(file, null, io.mersel.dss.verify.api.models.enums.VerificationLevel.COMPREHENSIVE, true);
        assertEquals("SERVER", standard.getTrustContext().getMode());
        assertTrue(standard.getSignatures().get(0).getSignerCertificate().isTrusted());
        assertEquals(1, trust.getCertificates().size());
        io.mersel.dss.verify.api.services.certificate.ActiveTrustStore activeStore = new io.mersel.dss.verify.api.services.certificate.ActiveTrustStore();
        org.mockito.Mockito.when(roots.getVerificationTrustContext()).thenAnswer(call -> activeStore.snapshot(() -> trust));
        String initialId = activeStore.snapshot(() -> trust).getActiveTrustId();
        activeStore.replace(initialId, new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", Collections.emptyList()), Collections.emptyList(), () -> trust);
        assertFalse(service.verifySignature(file, null, io.mersel.dss.verify.api.models.enums.VerificationLevel.COMPREHENSIVE, true).getSignatures().get(0).getSignerCertificate().isTrusted());
        String activeId = activeStore.snapshot(() -> trust).getActiveTrustId();
        activeStore.replace(activeId, new io.mersel.dss.verify.api.services.certificate.RequestTrustContext("CUSTOM", trust.getCertificates()), Collections.emptyList(), () -> trust);
        for (int repeat=0; repeat<2; repeat++) assertTrue(service.verifySignature(file, null, io.mersel.dss.verify.api.models.enums.VerificationLevel.COMPREHENSIVE, true).getSignatures().get(0).getSignerCertificate().isTrusted());

        assertNotNull(counterWrapper, "DSS must identify the countersignature from signed reference evidence");
        assertNotNull(counterWrapper.getParent());
        SignatureEvidenceExtractor.connectCounterSignatures(evidence);
        assertTrue(evidence.stream().anyMatch(info -> info.getCounterSignatureIds().size() == 1));
        assertTrue(evidence.stream().flatMap(info -> info.getSignedReferences().stream())
                .anyMatch(ref -> "#parent-value".equals(ref.getUri()) && ref.isDataFound() && ref.isDataIntact()));
    }

    private static void sign(XMLSignatureFactory factory, Element target, KeyPair keys, KeyInfo keyInfo,
                             Reference reference, String signatureId, String valueId) throws Exception {
        SignedInfo signedInfo = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                        (C14NMethodParameterSpec) null), factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null), Collections.singletonList(reference));
        XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo, null, signatureId, valueId);
        DOMSignContext context = new DOMSignContext(keys.getPrivate(), target);
        context.setDefaultNamespacePrefix("ds");
        signature.sign(context);
    }
}
