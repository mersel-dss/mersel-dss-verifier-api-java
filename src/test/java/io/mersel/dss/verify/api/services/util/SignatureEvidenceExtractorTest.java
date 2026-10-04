package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.SignedReferenceInfo;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SignatureEvidenceExtractorTest {
    @Test
    void usesDssParentLinksAndReferenceDigestEvidenceWhilePreservingVerdict() {
        XmlSignature parent = new XmlSignature();
        parent.setId("DSS-parent");
        XmlSignature counter = new XmlSignature();
        counter.setId("DSS-counter");
        counter.setParent(parent);
        counter.setCounterSignature(true);
        XmlDigestMatcher matcher = new XmlDigestMatcher();
        matcher.setId("ref-1");
        matcher.setUri("#parent-signature-value");
        matcher.setDocumentName("SignatureValue");
        matcher.setType(DigestMatcherType.COUNTER_SIGNATURE);
        matcher.setDigestMethod(DigestAlgorithm.SHA256);
        matcher.setDigestValue(new byte[] {1, 2, 3});
        matcher.setDataFound(true);
        matcher.setDataIntact(false);
        counter.getDigestMatchers().add(matcher);
        SignatureInfo parentInfo = new SignatureInfo();
        parentInfo.setSignatureId(parent.getId());
        SignatureInfo counterInfo = new SignatureInfo();
        counterInfo.setSignatureId(counter.getId());
        counterInfo.setValid(false);
        counterInfo.setIndication("TOTAL_FAILED");
        SignatureEvidenceExtractor.enrich(counterInfo, new SignatureWrapper(counter));
        SignatureEvidenceExtractor.connectCounterSignatures(Arrays.asList(parentInfo, counterInfo));
        assertEquals("DSS-parent", counterInfo.getParentSignatureId());
        assertEquals(Arrays.asList("DSS-counter"), parentInfo.getCounterSignatureIds());
        SignedReferenceInfo reference = counterInfo.getSignedReferences().get(0);
        assertEquals("#parent-signature-value", reference.getUri());
        assertEquals("AQID", reference.getDigestValue());
        assertTrue(reference.isDataFound());
        assertFalse(reference.isDataIntact());
        assertFalse(counterInfo.isValid());
        assertEquals("TOTAL_FAILED", counterInfo.getIndication());
        assertTrue(counterInfo.getRecommendations().stream().anyMatch(r -> "SIGNED_REFERENCE_INCOMPLETE".equals(r.getCode())));
        assertTrue(counterInfo.getRecommendations().stream().anyMatch(r -> "ARCHIVE_TIMESTAMP_MISSING".equals(r.getCode()) && "INFO".equals(r.getSeverity())));
    }

    @Test
    void mapsDigestAndRevocationWarningsToArchivalWithoutOverridingVerdict() {
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("S1");
        info.setValid(true);
        info.setIndication("TOTAL_PASSED");
        DetailedReport report = mock(DetailedReport.class);
        when(report.getAdESValidationWarnings("S1")).thenReturn(Arrays.asList(
                new Message("ASCCM_DAA_ANS", "Digest is not allowed by policy"),
                new Message("BBB_XCV_IARDPFC_ANS", "No acceptable revocation evidence")));
        SignatureEvidenceExtractor.enrichPolicyRecommendations(info, report);
        assertTrue(info.isValid());
        assertEquals("TOTAL_PASSED", info.getIndication());
        assertTrue(info.getRecommendations().stream().anyMatch(r -> "ARCHIVE_REQUIRED_DIGEST_POLICY".equals(r.getCode())));
        assertTrue(info.getRecommendations().stream().anyMatch(r -> "ARCHIVE_REQUIRED_REVOCATION_EVIDENCE".equals(r.getCode())));
    }

    @Test
    void invalidMissingEvidenceRequiresCompletionAndCannotBeMadeValidByArchiving() {
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("S1");
        info.setValid(false);
        info.setIndication("INDETERMINATE");
        info.setSubIndication("NO_CERTIFICATE_CHAIN_FOUND");
        SignatureEvidenceExtractor.enrichPolicyRecommendations(info, mock(DetailedReport.class));
        assertFalse(info.isValid());
        assertEquals(1, info.getRecommendations().size());
        assertEquals("VALIDATION_EVIDENCE_INCOMPLETE", info.getRecommendations().get(0).getCode());
    }

    @Test
    void doesNotInventLinksForTopLevelOrUnmatchedSignatures() {
        SignatureInfo first = new SignatureInfo();
        first.setSignatureId("same-looking-name-A");
        SignatureInfo second = new SignatureInfo();
        second.setSignatureId("same-looking-name-B");
        second.setCounterSignature(true);
        second.setParentSignatureId("missing-parent");
        SignatureEvidenceExtractor.connectCounterSignatures(Arrays.asList(first, second));
        assertTrue(first.getCounterSignatureIds().isEmpty());
        assertTrue(second.getCounterSignatureIds().isEmpty());
    }
}
