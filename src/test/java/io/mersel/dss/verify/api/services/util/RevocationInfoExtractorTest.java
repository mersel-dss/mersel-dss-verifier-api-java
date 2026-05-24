package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import io.mersel.dss.verify.api.models.RevocationInfo;
import io.mersel.dss.verify.api.models.enums.ChainRevocationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link RevocationInfoExtractor}'un davranışını DSS DiagnosticData mock'ları
 * üzerinden doğrular.
 *
 * <p>Kapsam:
 * <ul>
 *   <li>Hiç revocation yoksa {@code null} döner, {@code isNotRevoked = true} kalır.</li>
 *   <li>GOOD durumlu OCSP token tüm alanlarıyla doğru dönüşür.</li>
 *   <li>REVOKED token GOOD'a göre öncelik kazanır (güvenlik öncelikli seçim).</li>
 *   <li>Birden çok GOOD arasında en güncel {@code productionDate} seçilir.</li>
 *   <li>{@link CertificateWrapper#getCertificateRevocationData()} exception fırlatırsa
 *       defensive fallback devreye girer.</li>
 *   <li>Tek tek alan exception'ları diğer alanların dönüşmesini bloklamaz.</li>
 *   <li>Bir REVOKED token mevcutsa {@code isNotRevoked = false} olur.</li>
 * </ul>
 */
class RevocationInfoExtractorTest {

    private final RevocationInfoExtractor extractor = new RevocationInfoExtractor();

    @Test
    @DisplayName("Cert null ise extractFor null doner, isNotRevoked true kalir")
    void nullCertificate_returnsNullAndNotRevokedTrue() {
        assertNull(extractor.extractFor(null));
        assertTrue(extractor.isNotRevoked(null));
    }

    @Test
    @DisplayName("Revocation listesi bossa extractFor null doner, isNotRevoked true kalir")
    void emptyRevocationList_returnsNullAndNotRevokedTrue() {
        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Collections.emptyList());

        assertNull(extractor.extractFor(cert));
        assertTrue(extractor.isNotRevoked(cert));
    }

    @Test
    @DisplayName("DSS exception firlattiginda defensive null/true doner, akis bloklanmaz")
    void exceptionFromDss_isHandledDefensively() {
        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenThrow(new RuntimeException("simulated DSS failure"));

        assertNull(extractor.extractFor(cert));
        assertTrue(extractor.isNotRevoked(cert));
    }

    @Test
    @DisplayName("Tek GOOD OCSP token tum alanlariyla dogru cevirilir")
    void singleGoodOcspToken_isMappedFully() {
        Date producedAt = new Date(1_700_000_000_000L);
        Date thisUpdate = new Date(1_700_000_000_000L);
        Date nextUpdate = new Date(1_700_003_600_000L);
        CertificateRevocationWrapper rev = mockOcspGood("http://ocsp.kamusm.gov.tr",
                producedAt, thisUpdate, nextUpdate, RevocationOrigin.EXTERNAL);

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Collections.singletonList(rev));

        RevocationInfo info = extractor.extractFor(cert);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource());
        assertEquals("GOOD", info.getStatus());
        assertEquals("EXTERNAL", info.getOrigin());
        assertEquals("http://ocsp.kamusm.gov.tr", info.getResponderUrl());
        assertEquals(producedAt, info.getProducedAt());
        assertEquals(thisUpdate, info.getThisUpdate());
        assertEquals(nextUpdate, info.getNextUpdate());
        assertNull(info.getRevocationDate(), "GOOD durumunda iptal tarihi olmamali");
        assertNull(info.getRevocationReason(), "GOOD durumunda iptal nedeni olmamali");

        // Tek GOOD token => sertifika iptal degil
        assertTrue(extractor.isNotRevoked(cert));
    }

    @Test
    @DisplayName("REVOKED token tum alanlariyla cevirilir; iptal tarihi/nedeni dolar")
    void revokedToken_isMappedWithDateAndReason() {
        Date revokedAt = new Date(1_600_000_000_000L);
        Date producedAt = new Date(1_700_000_000_000L);

        CertificateRevocationWrapper rev = mock(CertificateRevocationWrapper.class);
        when(rev.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(rev.getStatus()).thenReturn(CertificateStatus.REVOKED);
        when(rev.getReason()).thenReturn(RevocationReason.KEY_COMPROMISE);
        when(rev.getRevocationDate()).thenReturn(revokedAt);
        when(rev.getProductionDate()).thenReturn(producedAt);
        when(rev.getOrigin()).thenReturn(RevocationOrigin.EXTERNAL);
        when(rev.getSourceAddress()).thenReturn("http://ocsp.example.com");

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Collections.singletonList(rev));

        RevocationInfo info = extractor.extractFor(cert);

        assertNotNull(info);
        assertEquals("REVOKED", info.getStatus());
        assertEquals("KEY_COMPROMISE", info.getRevocationReason());
        assertEquals(revokedAt, info.getRevocationDate());
        assertEquals(producedAt, info.getProducedAt());

        assertFalse(extractor.isNotRevoked(cert), "REVOKED token varsa isNotRevoked false olmali");
    }

    @Test
    @DisplayName("REVOKED + GOOD birlikteyse REVOKED secilir (guvenlik onceli)")
    void revokedTokenWinsOverGood() {
        Date olderRevokedAt = new Date(1_600_000_000_000L);

        CertificateRevocationWrapper good = mockOcspGood("http://ocsp.example.com",
                new Date(1_700_000_000_000L), null, null, RevocationOrigin.EXTERNAL);

        CertificateRevocationWrapper revoked = mock(CertificateRevocationWrapper.class);
        when(revoked.getRevocationType()).thenReturn(RevocationType.CRL);
        when(revoked.getStatus()).thenReturn(CertificateStatus.REVOKED);
        when(revoked.getRevocationDate()).thenReturn(olderRevokedAt);
        when(revoked.getProductionDate()).thenReturn(new Date(1_650_000_000_000L));
        when(revoked.getOrigin()).thenReturn(RevocationOrigin.CACHED);
        when(revoked.getSourceAddress()).thenReturn("http://crl.example.com/list.crl");

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Arrays.asList(good, revoked));

        RevocationInfo info = extractor.extractFor(cert);

        assertNotNull(info);
        assertEquals("REVOKED", info.getStatus(), "REVOKED, GOOD'a karsi oncelikli olmali");
        assertEquals("CRL", info.getSource());
        assertEquals("CACHED", info.getOrigin());
        assertEquals(olderRevokedAt, info.getRevocationDate());

        assertFalse(extractor.isNotRevoked(cert));
    }

    @Test
    @DisplayName("Coklu GOOD arasinda en guncel productionDate seciilir")
    void multipleGoodTokens_picksMostRecent() {
        Date oldDate = new Date(1_600_000_000_000L);
        Date newDate = new Date(1_700_000_000_000L);

        CertificateRevocationWrapper older = mockOcspGood("http://ocsp.old.example.com",
                oldDate, null, null, RevocationOrigin.CACHED);
        CertificateRevocationWrapper newer = mockOcspGood("http://ocsp.new.example.com",
                newDate, null, null, RevocationOrigin.EXTERNAL);

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Arrays.asList(older, newer));

        RevocationInfo info = extractor.extractFor(cert);

        assertNotNull(info);
        assertEquals("http://ocsp.new.example.com", info.getResponderUrl(),
                "En guncel productionDate'i olan token secilmeli");
        assertEquals("EXTERNAL", info.getOrigin());
        assertEquals(newDate, info.getProducedAt());
    }

    @Test
    @DisplayName("Tek bir alan exception atsa diger alanlar dolmaya devam eder")
    void perFieldExceptionDoesNotBlockOtherFields() {
        CertificateRevocationWrapper rev = mock(CertificateRevocationWrapper.class);
        when(rev.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(rev.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(rev.getProductionDate()).thenReturn(new Date(1_700_000_000_000L));
        when(rev.getOrigin()).thenReturn(RevocationOrigin.EXTERNAL);
        when(rev.getSourceAddress()).thenReturn("http://ocsp.kamusm.gov.tr");
        // Bir alan kasten patliyor:
        when(rev.getThisUpdate()).thenThrow(new RuntimeException("boom"));

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Collections.singletonList(rev));

        RevocationInfo info = extractor.extractFor(cert);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource(), "source dolu kalmali");
        assertEquals("GOOD", info.getStatus(), "status dolu kalmali");
        assertEquals("http://ocsp.kamusm.gov.tr", info.getResponderUrl());
        assertNull(info.getThisUpdate(), "Patlayan alan null kalmali, digerleri etkilenmemeli");
    }

    @Test
    @DisplayName("Bos URL responderUrl alanini doldurmaz")
    void emptyResponderUrl_notSet() {
        CertificateRevocationWrapper rev = mockOcspGood("",
                new Date(1_700_000_000_000L), null, null, RevocationOrigin.EXTERNAL);

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Collections.singletonList(rev));

        RevocationInfo info = extractor.extractFor(cert);

        assertNotNull(info);
        assertNull(info.getResponderUrl(), "Bos string responderUrl olarak set edilmemeli");
    }

    @Test
    @DisplayName("Liste icinde null girisler atlanir, gercek token islenir")
    void nullEntriesInListAreSkipped() {
        CertificateRevocationWrapper rev = mockOcspGood("http://ocsp.example.com",
                new Date(1_700_000_000_000L), null, null, RevocationOrigin.EXTERNAL);

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(Arrays.asList(null, rev, null));

        RevocationInfo info = extractor.extractFor(cert);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource());
        assertTrue(extractor.isNotRevoked(cert));
    }

    private CertificateRevocationWrapper mockOcspGood(String responderUrl,
                                                      Date producedAt,
                                                      Date thisUpdate,
                                                      Date nextUpdate,
                                                      RevocationOrigin origin) {
        CertificateRevocationWrapper rev = mock(CertificateRevocationWrapper.class);
        when(rev.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(rev.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(rev.getProductionDate()).thenReturn(producedAt);
        when(rev.getThisUpdate()).thenReturn(thisUpdate);
        when(rev.getNextUpdate()).thenReturn(nextUpdate);
        when(rev.getOrigin()).thenReturn(origin);
        when(rev.getSourceAddress()).thenReturn(responderUrl);
        return rev;
    }

    // -------------------------------------------------------------------
    // fromToken(...) — ham OCSP/CRL token'lardan RevocationInfo turetme.
    // -------------------------------------------------------------------

    @Test
    @DisplayName("fromToken: null token null doner")
    void fromToken_nullReturnsNull() {
        assertNull(extractor.fromToken(null));
    }

    @Test
    @DisplayName("fromToken: GOOD OCSPToken tum alanlariyla cevrilir")
    void fromToken_goodOcspToken() {
        Date producedAt = new Date(1_700_000_000_000L);
        Date thisUpdate = new Date(1_700_000_000_000L);
        Date nextUpdate = new Date(1_700_003_600_000L);

        OCSPToken ocsp = mock(OCSPToken.class);
        when(ocsp.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(ocsp.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(ocsp.getProductionDate()).thenReturn(producedAt);
        when(ocsp.getThisUpdate()).thenReturn(thisUpdate);
        when(ocsp.getNextUpdate()).thenReturn(nextUpdate);
        when(ocsp.getSourceURL()).thenReturn("http://ocsp.kamusm.gov.tr");
        when(ocsp.getExternalOrigin()).thenReturn(RevocationOrigin.EXTERNAL);

        RevocationInfo info = extractor.fromToken(ocsp);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource());
        assertEquals("GOOD", info.getStatus());
        assertEquals("EXTERNAL", info.getOrigin());
        assertEquals("http://ocsp.kamusm.gov.tr", info.getResponderUrl());
        assertEquals(producedAt, info.getProducedAt());
        assertEquals(thisUpdate, info.getThisUpdate());
        assertEquals(nextUpdate, info.getNextUpdate());
        assertNull(info.getRevocationDate());
        assertNull(info.getRevocationReason());
    }

    @Test
    @DisplayName("fromToken: REVOKED OCSPToken iptal tarihi ve nedeniyle cevrilir")
    void fromToken_revokedOcspToken() {
        Date revokedAt = new Date(1_600_000_000_000L);

        OCSPToken ocsp = mock(OCSPToken.class);
        when(ocsp.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(ocsp.getStatus()).thenReturn(CertificateStatus.REVOKED);
        when(ocsp.getRevocationDate()).thenReturn(revokedAt);
        when(ocsp.getReason()).thenReturn(RevocationReason.KEY_COMPROMISE);
        when(ocsp.getProductionDate()).thenReturn(new Date(1_700_000_000_000L));
        when(ocsp.getSourceURL()).thenReturn("http://ocsp.kamusm.gov.tr");
        when(ocsp.getExternalOrigin()).thenReturn(RevocationOrigin.EXTERNAL);

        RevocationInfo info = extractor.fromToken(ocsp);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource());
        assertEquals("REVOKED", info.getStatus());
        assertEquals(revokedAt, info.getRevocationDate());
        assertEquals("KEY_COMPROMISE", info.getRevocationReason());
    }

    @Test
    @DisplayName("fromToken: CRLToken'i de generic API uzerinden cevirir")
    void fromToken_crlToken() {
        CRLToken crl = mock(CRLToken.class);
        when(crl.getRevocationType()).thenReturn(RevocationType.CRL);
        when(crl.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(crl.getProductionDate()).thenReturn(new Date(1_700_000_000_000L));
        when(crl.getSourceURL()).thenReturn("http://crl.kamusm.gov.tr/list.crl");
        when(crl.getExternalOrigin()).thenReturn(RevocationOrigin.CACHED);

        RevocationInfo info = extractor.fromToken(crl);

        assertNotNull(info);
        assertEquals("CRL", info.getSource());
        assertEquals("GOOD", info.getStatus());
        assertEquals("CACHED", info.getOrigin());
        assertEquals("http://crl.kamusm.gov.tr/list.crl", info.getResponderUrl());
    }

    @Test
    @DisplayName("fromToken: tek bir alan exception atsa diger alanlar cevrilmeye devam eder")
    void fromToken_perFieldExceptionIsTolerated() {
        OCSPToken ocsp = mock(OCSPToken.class);
        when(ocsp.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(ocsp.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(ocsp.getProductionDate()).thenReturn(new Date(1_700_000_000_000L));
        when(ocsp.getSourceURL()).thenReturn("http://ocsp.kamusm.gov.tr");
        when(ocsp.getExternalOrigin()).thenReturn(RevocationOrigin.EXTERNAL);
        // Bir alan patliyor:
        when(ocsp.getThisUpdate()).thenThrow(new RuntimeException("boom"));

        RevocationInfo info = extractor.fromToken(ocsp);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource());
        assertEquals("GOOD", info.getStatus());
        assertEquals("http://ocsp.kamusm.gov.tr", info.getResponderUrl());
        assertNull(info.getThisUpdate());
    }

    @Test
    @DisplayName("fromToken: bos sourceURL responderUrl olarak set edilmez")
    void fromToken_emptySourceUrlSkipped() {
        OCSPToken ocsp = mock(OCSPToken.class);
        when(ocsp.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(ocsp.getStatus()).thenReturn(CertificateStatus.GOOD);
        when(ocsp.getSourceURL()).thenReturn("");

        RevocationInfo info = extractor.fromToken(ocsp);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource());
        assertNull(info.getResponderUrl(), "Bos string responderUrl olarak set edilmemeli");
    }

    @Test
    @DisplayName("fromToken: RevocationToken generic uzerinden de calisir (subtyping)")
    void fromToken_acceptsRevocationTokenBase() {
        // Caller'in mutlaka OCSPToken/CRLToken'a cast etmesi gerekmedigini
        // dogrula — tip-guvenli generic API.
        RevocationToken<?> token = mock(OCSPToken.class);
        when(((OCSPToken) token).getRevocationType()).thenReturn(RevocationType.OCSP);
        when(((OCSPToken) token).getStatus()).thenReturn(CertificateStatus.GOOD);

        RevocationInfo info = extractor.fromToken(token);

        assertNotNull(info);
        assertEquals("OCSP", info.getSource());
        assertEquals("GOOD", info.getStatus());
    }

    // -------------------------------------------------------------------
    // computeChainStatus(...) — zincir geneli ozet enum
    // -------------------------------------------------------------------

    @Test
    @DisplayName("computeChainStatus: null/empty chain -> NOT_CHECKED")
    void chainStatus_nullOrEmpty() {
        assertEquals(ChainRevocationStatus.NOT_CHECKED, extractor.computeChainStatus(null));
        assertEquals(ChainRevocationStatus.NOT_CHECKED, extractor.computeChainStatus(java.util.Collections.emptyList()));
    }

    @Test
    @DisplayName("computeChainStatus: tum zincir GOOD -> ALL_GOOD")
    void chainStatus_allGood() {
        CertificateWrapper leaf = certWithRevocation(CertificateStatus.GOOD);
        CertificateWrapper ca1 = certWithRevocation(CertificateStatus.GOOD);
        CertificateWrapper root = certWithoutRevocationData();

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1, root));

        assertEquals(ChainRevocationStatus.ALL_GOOD, status);
    }

    @Test
    @DisplayName("computeChainStatus: leaf REVOKED -> LEAF_REVOKED (CA durumuna bakilmaz)")
    void chainStatus_leafRevokedWins() {
        CertificateWrapper leaf = certWithRevocation(CertificateStatus.REVOKED);
        CertificateWrapper ca1 = certWithRevocation(CertificateStatus.GOOD);
        CertificateWrapper ca2 = certWithRevocation(CertificateStatus.REVOKED); // ek REVOKED CA

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1, ca2));

        assertEquals(ChainRevocationStatus.LEAF_REVOKED, status,
                "Leaf REVOKED ise diger cert'lerin durumuna bakilmamali");
    }

    @Test
    @DisplayName("computeChainStatus: leaf UNKNOWN -> UNKNOWN (CA REVOKED olsa bile)")
    void chainStatus_leafUnknownWinsOverCaRevoked() {
        CertificateWrapper leaf = certWithRevocation(CertificateStatus.UNKNOWN);
        CertificateWrapper ca1 = certWithRevocation(CertificateStatus.REVOKED);

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1));

        assertEquals(ChainRevocationStatus.UNKNOWN, status);
    }

    @Test
    @DisplayName("computeChainStatus: leaf GOOD + CA REVOKED -> LEAF_GOOD_CA_REVOKED")
    void chainStatus_leafGoodCaRevoked() {
        CertificateWrapper leaf = certWithRevocation(CertificateStatus.GOOD);
        CertificateWrapper ca1 = certWithRevocation(CertificateStatus.GOOD);
        CertificateWrapper ca2 = certWithRevocation(CertificateStatus.REVOKED);
        CertificateWrapper root = certWithoutRevocationData();

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1, ca2, root));

        assertEquals(ChainRevocationStatus.LEAF_GOOD_CA_REVOKED, status);
    }

    @Test
    @DisplayName("computeChainStatus: leaf GOOD + CA UNKNOWN (REVOKED yok) -> UNKNOWN")
    void chainStatus_leafGoodCaUnknown() {
        CertificateWrapper leaf = certWithRevocation(CertificateStatus.GOOD);
        CertificateWrapper ca1 = certWithRevocation(CertificateStatus.UNKNOWN);
        CertificateWrapper root = certWithoutRevocationData();

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1, root));

        assertEquals(ChainRevocationStatus.UNKNOWN, status);
    }

    @Test
    @DisplayName("computeChainStatus: leaf icin revocation yok ama CA icin var -> UNKNOWN (kismi gorus)")
    void chainStatus_leafMissingButCaPresent() {
        CertificateWrapper leaf = certWithoutRevocationData();
        CertificateWrapper ca1 = certWithRevocation(CertificateStatus.GOOD);

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1));

        assertEquals(ChainRevocationStatus.UNKNOWN, status,
                "Leaf icin veri yok ama CA icin var -> kismi gorus -> UNKNOWN");
    }

    @Test
    @DisplayName("computeChainStatus: hicbir cert icin revocation yok -> NOT_CHECKED")
    void chainStatus_nothingChecked() {
        CertificateWrapper leaf = certWithoutRevocationData();
        CertificateWrapper ca1 = certWithoutRevocationData();
        CertificateWrapper root = certWithoutRevocationData();

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1, root));

        assertEquals(ChainRevocationStatus.NOT_CHECKED, status);
    }

    @Test
    @DisplayName("computeChainStatus: REVOKED ve UNKNOWN birlikteyse (CA seviyesinde) REVOKED kazanir")
    void chainStatus_caRevokedTakesPrecedenceOverCaUnknown() {
        CertificateWrapper leaf = certWithRevocation(CertificateStatus.GOOD);
        CertificateWrapper ca1 = certWithRevocation(CertificateStatus.UNKNOWN);
        CertificateWrapper ca2 = certWithRevocation(CertificateStatus.REVOKED);

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Arrays.asList(leaf, ca1, ca2));

        assertEquals(ChainRevocationStatus.LEAF_GOOD_CA_REVOKED, status);
    }

    @Test
    @DisplayName("computeChainStatus: tek elemanli zincir (sadece leaf) - GOOD")
    void chainStatus_singleElementChain() {
        CertificateWrapper leaf = certWithRevocation(CertificateStatus.GOOD);

        ChainRevocationStatus status = extractor.computeChainStatus(java.util.Collections.singletonList(leaf));

        assertEquals(ChainRevocationStatus.ALL_GOOD, status);
    }

    // -- helpers ---------------------------------------------------------

    private CertificateWrapper certWithRevocation(CertificateStatus status) {
        CertificateRevocationWrapper rev = mock(CertificateRevocationWrapper.class);
        when(rev.getStatus()).thenReturn(status);
        when(rev.getRevocationType()).thenReturn(RevocationType.OCSP);
        when(rev.getProductionDate()).thenReturn(new Date(1_700_000_000_000L));

        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(java.util.Collections.singletonList(rev));
        return cert;
    }

    private CertificateWrapper certWithoutRevocationData() {
        CertificateWrapper cert = mock(CertificateWrapper.class);
        when(cert.getCertificateRevocationData()).thenReturn(java.util.Collections.emptyList());
        return cert;
    }
}
