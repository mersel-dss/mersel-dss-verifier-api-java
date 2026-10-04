package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.LocalHttpServer;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.TestPki;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.util.TimeValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Karar esdegerligi: ayni imzali belge, ayni politika
 * ({@code kamusm-signer-strict-constraint.xml}) ve kalici HTTP 400 donen bir
 * CRL dagitim noktasi ile DSS dogrulamasi
 * <ol>
 *   <li>eski boru hatti (her hata 3 kez denenir, negatif cache yok),</li>
 *   <li>yeni boru hatti negatif cache kapali,</li>
 *   <li>yeni boru hatti negatif cache acik (ikinci dogrulama cache'ten)</li>
 * </ol>
 * icin <b>birebir ayni</b> sonucu uretir (indication, subIndication,
 * hata/uyari/bilgi mesajlari, revocation sayisi, tarihleri ayiklanmis
 * detailed report XML'i). Yalniz HTTP istegi sayisi degisir.
 *
 * <p>Tamamen offline: PKI BouncyCastle ile uretilir, CRL DP 127.0.0.1'deki
 * yerel sunucuyu gosterir.</p>
 */
class RevocationVerdictEquivalenceTest {

    private static final String POLICY = "/policy/kamusm-signer-strict-constraint.xml";

    @Test
    @DisplayName("Negatif cache ve retry siniflandirmasi dogrulama kararini degistirmez")
    void sameVerdictWithAndWithoutFailureCache() throws Exception {
        try (LocalHttpServer server = LocalHttpServer.start()) {
            server.respond("/RootA1.crl", 400, "Bad Request".getBytes(StandardCharsets.UTF_8));
            TestPki pki = TestPki.create("Verdict Equivalence Signer", server.url("/RootA1.crl"), null);
            byte[] signed = signEnveloped(pki);

            // 1) Eski davranis: her RuntimeException yeniden denenir, hata cache'lenmez.
            CRLSource legacy = new LoggingCachingCRLSource(
                    retrying(onlineCrl(), FailureClassifier.retryAll()), 100L, 60L);
            Verdict legacy1 = validate(signed, pki, legacy);
            int legacyHits = server.hits("/RootA1.crl");
            Verdict legacy2 = validate(signed, pki, legacy);
            assertEquals(3, legacyHits, "old pipeline retries the permanent 400 twice per fetch");
            assertEquals(6, server.hits("/RootA1.crl"));

            // 2) Yeni siniflandirma, negatif cache kapali: 400 bir kez denenir.
            CRLSource noCache = new LoggingCachingCRLSource(
                    retrying(onlineCrl(), RevocationFailureClassifier.INSTANCE), 100L, 60L, null,
                    RevocationFailureCache.disabled("CRL"));
            Verdict noCache1 = validate(signed, pki, noCache);
            Verdict noCache2 = validate(signed, pki, noCache);
            assertEquals(8, server.hits("/RootA1.crl"), "one request per validation, no retries");

            // 3) Yeni siniflandirma + negatif cache: ikinci dogrulama ag cagrisi yapmaz.
            CRLSource cached = new LoggingCachingCRLSource(
                    retrying(onlineCrl(), RevocationFailureClassifier.INSTANCE), 100L, 60L, null,
                    new RevocationFailureCache("CRL", 300L, 30L, 100L));
            Verdict cached1 = validate(signed, pki, cached);
            assertEquals(9, server.hits("/RootA1.crl"));
            Verdict cached2 = validate(signed, pki, cached);
            assertEquals(9, server.hits("/RootA1.crl"), "second validation served from failure cache");

            for (Verdict v : Arrays.asList(legacy2, noCache1, noCache2, cached1, cached2)) {
                assertEquals(legacy1, v);
            }
            // Senaryo anlamli olsun: revocation verisi yok ve imza TOTAL_PASSED degil.
            assertEquals(0, legacy1.revocationCount);
            assertFalse(legacy1.signatures.isEmpty());
            assertFalse(legacy1.signatures.get(0).contains("TOTAL_PASSED"), legacy1.signatures.toString());
        }
    }

    // ---------------------------------------------------------------- helpers

    private static OnlineCRLSource onlineCrl() {
        CommonsDataLoader loader = new CommonsDataLoader();
        loader.setTimeoutConnection(2_000);
        loader.setTimeoutSocket(2_000);
        loader.setRetryStrategy(new DefaultHttpRequestRetryStrategy(0, TimeValue.ZERO_MILLISECONDS));
        loader.setHttpClientResponseHandler(new StatusAwareHttpClientResponseHandler());
        OnlineCRLSource online = new OnlineCRLSource();
        online.setDataLoader(loader);
        return online;
    }

    private static RetryingCRLSource retrying(CRLSource online, FailureClassifier classifier) {
        return new RetryingCRLSource(online, new RetryPolicy(3, 200L, 2000L, 2.0d, 0.0d),
                millis -> { /* backoff yok — testi hizli tut */ }, classifier);
    }

    private static Verdict validate(byte[] signed, TestPki pki, CRLSource crlSource) throws Exception {
        CommonTrustedCertificateSource trust = new CommonTrustedCertificateSource();
        trust.addCertificate(pki.caToken());
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trust);
        verifier.setCrlSource(crlSource);
        verifier.setOcspSource(null);
        verifier.setAIASource(null);
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signed, "signed.xml"));
        validator.setCertificateVerifier(verifier);
        try (InputStream policy = RevocationVerdictEquivalenceTest.class.getResourceAsStream(POLICY)) {
            assertNotNull(policy, "bundled policy " + POLICY);
            return Verdict.of(validator.validateDocument(policy));
        }
    }

    private static byte[] signEnveloped(TestPki pki) throws Exception {
        DocumentBuilderFactory documents = DocumentBuilderFactory.newInstance();
        documents.setNamespaceAware(true);
        Document document = documents.newDocumentBuilder().newDocument();
        Element root = document.createElement("Invoice");
        root.setTextContent("Offline revocation verdict equivalence test");
        document.appendChild(root);

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        KeyInfoFactory kif = factory.getKeyInfoFactory();
        KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(
                kif.newX509Data(Arrays.asList(pki.leaf, pki.ca))));
        Reference reference = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                null, null);
        SignedInfo signedInfo = factory.newSignedInfo(
                factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(reference));
        XMLSignature signature = factory.newXMLSignature(signedInfo, keyInfo, null, "Signature-1", null);
        DOMSignContext context = new DOMSignContext(pki.leafKeys.getPrivate(), root);
        context.setDefaultNamespacePrefix("ds");
        signature.sign(context);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(output));
        return output.toByteArray();
    }

    /** Dogrulama sonucunun zaman-bagimsiz ozeti. */
    private static final class Verdict {
        final List<String> signatures = new ArrayList<>();
        int revocationCount;
        String detailedReport;

        static Verdict of(Reports reports) {
            Verdict v = new Verdict();
            SimpleReport simple = reports.getSimpleReport();
            for (String id : simple.getSignatureIdList()) {
                v.signatures.add(id
                        + " indication=" + simple.getIndication(id)
                        + " subIndication=" + simple.getSubIndication(id)
                        + " errors=" + messages(simple.getAdESValidationErrors(id))
                        + " warnings=" + messages(simple.getAdESValidationWarnings(id))
                        + " infos=" + messages(simple.getAdESValidationInfo(id)));
            }
            v.revocationCount = reports.getDiagnosticData().getAllRevocationData().size();
            v.detailedReport = reports.getXmlDetailedReport()
                    .replaceAll("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d+)?(Z|[+-]\\d{2}:\\d{2})?", "<time>");
            assertTrue(v.detailedReport.contains("<"), "detailed report present");
            return v;
        }

        private static List<String> messages(List<Message> messages) {
            List<String> out = new ArrayList<>();
            for (Message m : messages) {
                out.add(m.getKey() + "=" + m.getValue());
            }
            return out;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Verdict)) {
                return false;
            }
            Verdict other = (Verdict) o;
            return signatures.equals(other.signatures)
                    && revocationCount == other.revocationCount
                    && detailedReport.equals(other.detailedReport);
        }

        @Override
        public int hashCode() {
            return signatures.hashCode();
        }

        @Override
        public String toString() {
            return "Verdict{signatures=" + signatures + ", revocationCount=" + revocationCount + '}';
        }
    }
}
