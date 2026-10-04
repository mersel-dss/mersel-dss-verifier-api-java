package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.TimestampInfo;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AdvancedSignatureEvidenceTest {
    @Test
    void exportsEveryTimestampAndEveryCertificateAndKeepsDetailedFailure() throws Exception {
        AdvancedSignatureVerificationService service = new AdvancedSignatureVerificationService();
        ReflectionTestUtils.setField(service, "revocationInfoExtractor", new RevocationInfoExtractor());
        X509Certificate certificate = CertificateMaterialExtractorTest.certificate("RSA");
        CertificateWrapper leaf = mock(CertificateWrapper.class);
        when(leaf.getId()).thenReturn("CERT-leaf");
        when(leaf.getBinaries()).thenReturn(certificate.getEncoded());
        when(leaf.getNotAfter()).thenReturn(certificate.getNotAfter());
        when(leaf.getNotBefore()).thenReturn(certificate.getNotBefore());
        when(leaf.getReadableCertificateName()).thenReturn("TSA test");
        CertificateWrapper root = mock(CertificateWrapper.class);
        when(root.getId()).thenReturn("CERT-root");
        when(root.getBinaries()).thenReturn(certificate.getEncoded());
        when(root.isTrusted()).thenReturn(true);
        when(leaf.getSigningCertificate()).thenReturn(root);
        TimestampWrapper first = timestamp("TS-one", leaf, root);
        TimestampWrapper second = timestamp("TS-two", leaf, root);
        SignatureWrapper signature = mock(SignatureWrapper.class);
        when(signature.getSigningCertificate()).thenReturn(leaf);
        when(signature.getCertificateChain()).thenReturn(Arrays.asList(leaf, root));
        when(signature.getTimestampList()).thenReturn(Arrays.asList(first, second));
        when(signature.isTrustedChain()).thenReturn(true);
        XmlDetailedReport report = new XmlDetailedReport();
        report.getSignatureOrTimestampOrEvidenceRecord().add(timestampVerdict("TS-one", Indication.PASSED, null));
        report.getSignatureOrTimestampOrEvidenceRecord().add(timestampVerdict("TS-two", Indication.INDETERMINATE, SubIndication.NO_CERTIFICATE_CHAIN_FOUND));
        SignatureInfo info = new SignatureInfo();
        info.setValid(false);
        ReflectionTestUtils.invokeMethod(service, "processSignatureWrapper", info, signature,
                VerificationLevel.COMPREHENSIVE, new DetailedReport(report), true);
        assertEquals(2, info.getTimestampCount());
        assertEquals(2, info.getTimestamps().size());
        assertSame(info.getTimestamps().get(0), info.getTimestampInfo());
        assertTrue(info.getTimestamps().get(0).isValid());
        TimestampInfo failed = info.getTimestamps().get(1);
        assertFalse(failed.isValid(), "Matching imprint must not mask TSA chain failure");
        assertEquals("INDETERMINATE", failed.getIndication());
        assertEquals("NO_CERTIFICATE_CHAIN_FOUND", failed.getSubIndication());
        assertEquals(Boolean.TRUE, failed.getMessageImprintDataIntact());
        assertEquals("CERT-leaf", failed.getTsaCertificate().getCertificateId());
        assertEquals("CERT-root", failed.getTsaCertificate().getIssuerCertificateId());
        assertEquals(2, failed.getCertificateChain().size());
        assertEquals(2, info.getCertificateChain().size());
        assertArrayEquals(certificate.getEncoded(), Base64.getDecoder().decode(failed.getTsaCertificate().getCertificateBase64()));
        assertArrayEquals(certificate.getEncoded(), Base64.getDecoder().decode(info.getCertificateChain().get(1).getCertificateBase64()));
        assertFalse(info.isValid(), "Evidence extraction must not change the signature decision");
    }

    @Test
    void missingDetailedVerdictIsNotReportedAsValidDespiteMatchingImprint() {
        AdvancedSignatureVerificationService service = new AdvancedSignatureVerificationService();
        TimestampWrapper timestamp = timestamp("TS-unknown", null, null);
        TimestampInfo info = ReflectionTestUtils.invokeMethod(service, "extractTimestampInfo", timestamp, null, false);
        assertNotNull(info);
        assertFalse(info.isValid());
        assertNull(info.getIndication());
        assertEquals(Boolean.TRUE, info.getMessageImprintDataIntact());
    }

    private static TimestampWrapper timestamp(String id, CertificateWrapper leaf, CertificateWrapper root) {
        TimestampWrapper wrapper = mock(TimestampWrapper.class);
        when(wrapper.getId()).thenReturn(id);
        when(wrapper.getType()).thenReturn(TimestampType.SIGNATURE_TIMESTAMP);
        when(wrapper.isMessageImprintDataFound()).thenReturn(true);
        when(wrapper.isMessageImprintDataIntact()).thenReturn(true);
        when(wrapper.getSigningCertificate()).thenReturn(leaf);
        when(wrapper.getCertificateChain()).thenReturn(leaf == null ? Collections.emptyList() : Arrays.asList(leaf, root));
        return wrapper;
    }

    private static eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp timestampVerdict(String id, Indication indication, SubIndication subIndication) {
        eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp timestamp = new eu.europa.esig.dss.detailedreport.jaxb.XmlTimestamp();
        timestamp.setId(id);
        XmlConclusion conclusion = new XmlConclusion();
        conclusion.setIndication(indication);
        conclusion.setSubIndication(subIndication);
        timestamp.setConclusion(conclusion);
        return timestamp;
    }
}
