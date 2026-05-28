package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.enumerations.Indication;
import io.mersel.dss.verify.api.models.FailedConstraint;
import io.mersel.dss.verify.api.models.FailureCategory;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@code AdvancedSignatureVerificationService#selectRootCause} private
 * helper'ı için kontrat testi — kategorize liste içinden tek bir
 * {@link FailureCategory#ROOT_CAUSE} satırını seçer; yoksa defansif
 * fallback ile listenin ilk elemanını alır.
 *
 * <p>Helper private olduğu için Spring {@link ReflectionTestUtils} ile
 * çağırıyoruz. {@code collectFailingBbbConstraintDetails}'in çıktısı
 * verildiğinde {@code rootCause} alanı için seçimi nasıl yaptığını
 * doğrulayan en yakın seviye birim testidir.</p>
 */
class AdvancedSignatureVerificationServiceSelectRootCauseTest {

    private final AdvancedSignatureVerificationService service =
            new AdvancedSignatureVerificationService();

    private static final String SIG_ID = "SIG-ROOT";

    /**
     * Canonical: kategorize listede 1 ROOT_CAUSE + 1 DERIVED + 1 CASCADE
     * varken {@code rootCause} alanı ROOT_CAUSE kategorisindeki satırı seçer.
     */
    @Test
    void picks_rootCauseCategory_overDerivedAndCascade() {
        List<FailedConstraint> categorized = collectForCanonicalKeyUsageChain();
        FailedConstraint selected = invokeSelectRootCause(categorized);

        assertNotNull(selected);
        assertEquals("BBB_XCV_ISCGKU", selected.getKey(),
                "Üç-aşamalı zincirden tek ROOT_CAUSE satırı seçilmeli.");
        assertEquals(FailureCategory.ROOT_CAUSE, selected.getCategory(),
                "Seçilen satırın kategorisi ROOT_CAUSE olmalı.");
    }

    /**
     * DSS gezme sırasında ilk ROOT_CAUSE satırı kazanır. Birden fazla
     * ROOT_CAUSE varsa (örn. iki SubXCV içinde ayrı KeyUsage failure)
     * deterministik olarak ilk seçilir.
     */
    @Test
    void picks_firstRootCause_whenMultipleExist() {
        FailedConstraint first = new FailedConstraint(
                "BBB_XCV_ISCGKU", "First leaf cert KeyUsage", FailureCategory.ROOT_CAUSE);
        FailedConstraint second = new FailedConstraint(
                "BBB_XCV_ISCGKU", "Counter signer KeyUsage", FailureCategory.ROOT_CAUSE);
        FailedConstraint derived = new FailedConstraint(
                "BBB_XCV_SUB", "Roll-up", FailureCategory.DERIVED);

        FailedConstraint selected = invokeSelectRootCause(
                java.util.Arrays.asList(first, derived, second));

        assertEquals("First leaf cert KeyUsage", selected.getMessage(),
                "Liste sırasındaki ilk ROOT_CAUSE seçilir (DSS gezme sırası).");
    }

    /**
     * Defansif fallback — hiç ROOT_CAUSE yoksa (DSS yeni sürümünde
     * whitelist eksik veya beklenmedik blok ilişkisi), listenin ilk
     * elemanı seçilir. Operatör hiçbir zaman bilgisiz kalmaz.
     */
    @Test
    void fallsBack_toFirstElement_whenNoRootCauseExists() {
        FailedConstraint derived = new FailedConstraint(
                "BBB_XCV_SUB", "Only derived", FailureCategory.DERIVED);
        FailedConstraint cascade = new FailedConstraint(
                "BBB_SAV_ANS", "Only cascade", FailureCategory.CASCADE);

        FailedConstraint selected = invokeSelectRootCause(
                java.util.Arrays.asList(derived, cascade));

        assertNotNull(selected,
                "Fallback aktif olmalı — null dönmek bilgi kaybıdır.");
        assertEquals("BBB_XCV_SUB", selected.getKey(),
                "Defansif fallback: listenin ilk elemanı.");
    }

    @Test
    void returnsNull_forEmptyList() {
        assertNull(invokeSelectRootCause(java.util.Collections.emptyList()));
    }

    @Test
    void returnsNull_forNullList() {
        assertNull(invokeSelectRootCause(null));
    }

    /**
     * {@code collectFailingBbbConstraintDetails} + {@code selectRootCause}
     * uçtan uca: kullanıcının canonical KeyUsage hata senaryosu — pipeline
     * 3 NOT_OK constraint üretir; selectRootCause yalnız BBB_XCV_ISCGKU'yu seçer.
     */
    @Test
    void integration_canonicalChain_yieldsSingleKeyUsageRootCause() {
        List<FailedConstraint> categorized = collectForCanonicalKeyUsageChain();
        FailedConstraint selected = invokeSelectRootCause(categorized);

        assertEquals(3, categorized.size(),
                "Pipeline 3 NOT_OK üretti (root + derived + cascade).");
        assertEquals("BBB_XCV_ISCGKU", selected.getKey(),
                "selectRootCause filtreler — tek somut sebep operatöre gider.");
    }

    private List<FailedConstraint> collectForCanonicalKeyUsageChain() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);

        XmlXCV xcv = new XmlXCV();
        XmlConclusion conclusion = new XmlConclusion();
        conclusion.setIndication(Indication.INDETERMINATE);
        xcv.setConclusion(conclusion);
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "KeyUsage check?", "KeyUsage uygunsuz", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        xcv.getConstraint().add(constraint("BBB_XCV_SUB",
                "SubXCV valid?", "SubXCV not valid", XmlStatus.NOT_OK));
        bbb.setXCV(xcv);

        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ISQPMDOSPP",
                "Signed properties present?", "Not present", XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        return service.collectFailingBbbConstraintDetails(wrap(bbb), SIG_ID);
    }

    private static FailedConstraint invokeSelectRootCause(List<FailedConstraint> list) {
        return (FailedConstraint) ReflectionTestUtils.invokeMethod(
                AdvancedSignatureVerificationService.class,
                "selectRootCause",
                list);
    }

    private static XmlConstraint constraint(String key, String nameValue,
                                            String errorValue, XmlStatus status) {
        XmlConstraint c = new XmlConstraint();
        c.setStatus(status);
        XmlMessage name = new XmlMessage();
        name.setKey(key);
        name.setValue(nameValue);
        c.setName(name);
        XmlMessage err = new XmlMessage();
        err.setKey(key + "_ANS");
        err.setValue(errorValue);
        c.setError(err);
        return c;
    }

    private static DetailedReport wrap(XmlBasicBuildingBlocks bbb) {
        XmlDetailedReport report = new XmlDetailedReport();
        report.getBasicBuildingBlocks().add(bbb);
        return new DetailedReport(report);
    }
}
