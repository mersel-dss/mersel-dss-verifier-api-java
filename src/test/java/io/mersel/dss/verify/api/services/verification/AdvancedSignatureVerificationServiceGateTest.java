package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlFC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlISC;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlPSV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlVCI;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AdvancedSignatureVerificationService}'in iki yardımcı katmanı için
 * birim testler:
 *
 * <ol>
 *   <li><b>{@code collectAllBbbFailureKeys}</b> — Gate v2'nin temel taşı:
 *       FC/ISC/VCI/CV/SAV/XCV-top/SubXCV/PSV tüm bloklarındaki NOT_OK
 *       constraint key'lerini tek set olarak döner. Universal allow-list
 *       mantığının kaynak verisi; herhangi bir blok atlanırsa güvenlik
 *       açığı doğar.</li>
 *   <li><b>{@code collectFailingBbbConstraintMessages}</b> — opaque DSS
 *       constraint key'lerini ({@code BBB_XCV_ISCGKU} vb.) DSS'in
 *       I18nProvider'ı tarafından doldurulmuş insan-okur mesajlarla
 *       birlikte {@code "[KEY] mesaj"} formatına çeviren enrichment.</li>
 * </ol>
 */
class AdvancedSignatureVerificationServiceGateTest {

    private final AdvancedSignatureVerificationService service =
            new AdvancedSignatureVerificationService();

    private static final String SIG_ID = "SIG-1";
    private static final String ALLOWED_SAV_KEY = "BBB_SAV_ISQPMDOSPP";

    // =========================================================================
    // Bölüm 1: collectAllBbbFailureKeys — Gate v2 temel taşı
    // Allow-list mantığının kaynak verisi (KAPSAYAN BLOKLAR: FC, ISC, VCI,
    // CV, SAV, XCV-top, SubXCV[*], PSV).
    // =========================================================================

    @Test
    void collectAllBbbFailureKeys_returnsEmpty_whenNoFailures() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(constraint("BBB_SAV_OK", "ok", null, XmlStatus.OK)));

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.isEmpty(),
                "Hiçbir NOT_OK yokken set boş olmalı (gate edge-case: "
                        + "no_failure_observed).");
    }

    @Test
    void collectAllBbbFailureKeys_capturesSavOnlyAllowedKey() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(constraint(ALLOWED_SAV_KEY,
                "Is the message-digest or SignedProperties present?",
                "Neither message-digest nor SignedProperties is present!",
                XmlStatus.NOT_OK)));

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertEquals(Collections.singleton(ALLOWED_SAV_KEY), keys,
                "Allow-list happy-path: yalnız BBB_SAV_ISQPMDOSPP — gate "
                        + "geçer (subset of ALLOWED).");
    }

    @Test
    void collectAllBbbFailureKeys_capturesFcFailureSeparately() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlFC fc = new XmlFC();
        fc.getConstraint().add(constraint("BBB_FC_IEFF",
                "Does the signature format correspond to an expected format?",
                "The signature does not correspond to the expected format(s)!",
                XmlStatus.NOT_OK));
        bbb.setFC(fc);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.contains("BBB_FC_IEFF"),
                "FC blok'undaki FAIL gözlenmeli — gate v1'de bu atlanıyordu.");
    }

    @Test
    void collectAllBbbFailureKeys_capturesCvHashMismatch() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlCV cv = new XmlCV();
        cv.getConstraint().add(constraint("BBB_CV_IRDOI",
                "Is the reference data object intact?",
                "The reference data object is not intact!",
                XmlStatus.NOT_OK));
        bbb.setCV(cv);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.contains("BBB_CV_IRDOI"),
                "CV hash mismatch (içerik manipülasyonu sinyali) "
                        + "yakalanmalı; gate v1'de gözden kaçıyordu.");
    }

    @Test
    void collectAllBbbFailureKeys_capturesIscFailure() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlISC isc = new XmlISC();
        isc.getConstraint().add(constraint("BBB_ICS_ISCI",
                "Can the signing certificate be identified?",
                "The signing certificate cannot be identified!",
                XmlStatus.NOT_OK));
        bbb.setISC(isc);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.contains("BBB_ICS_ISCI"),
                "ISC blok'undaki FAIL gözlenmeli — gate v1'de bu atlanıyordu.");
    }

    @Test
    void collectAllBbbFailureKeys_capturesVciFailure() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlVCI vci = new XmlVCI();
        vci.getConstraint().add(constraint("BBB_VCI_ISPK",
                "Is the signature policy known?",
                "The signature policy is not known!",
                XmlStatus.NOT_OK));
        bbb.setVCI(vci);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.contains("BBB_VCI_ISPK"),
                "VCI blok'undaki FAIL gözlenmeli — gate v1'de bu atlanıyordu.");
    }

    @Test
    void collectAllBbbFailureKeys_capturesPsvFailure() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlPSV psv = new XmlPSV();
        psv.getConstraint().add(constraint("PSV_IPSVC",
                "Is past signature validation conclusive?",
                "Past signature validation is not conclusive!",
                XmlStatus.NOT_OK));
        bbb.setPSV(psv);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.contains("PSV_IPSVC"),
                "PSV blok'undaki FAIL gözlenmeli — gate v1'de bu atlanıyordu.");
    }

    @Test
    void collectAllBbbFailureKeys_capturesXcvTopAndSubFailures() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_CCCBB",
                "Can the certificate chain be built till a trust anchor?",
                "The certificate chain is not trusted, it does not contain a trust anchor.",
                XmlStatus.NOT_OK));
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "Does the certificate have an expected key-usage?",
                "The certificate does not have an expected key-usage!",
                XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.contains("BBB_XCV_CCCBB"), "XCV top-level FAIL");
        assertTrue(keys.contains("BBB_XCV_ISCGKU"), "SubXCV FAIL");
    }

    @Test
    void collectAllBbbFailureKeys_aggregatesMultipleBlocks() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(constraint(ALLOWED_SAV_KEY, "sav-q", "sav-e", XmlStatus.NOT_OK)));
        XmlCV cv = new XmlCV();
        cv.getConstraint().add(constraint("BBB_CV_IRDOI", "cv-q", "cv-e", XmlStatus.NOT_OK));
        bbb.setCV(cv);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU", "xcv-q", "xcv-e", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertEquals(3, keys.size(),
                "Birden fazla blokta FAIL varsa hepsi tek set'te toplanmalı.");
        assertTrue(keys.contains(ALLOWED_SAV_KEY));
        assertTrue(keys.contains("BBB_CV_IRDOI"));
        assertTrue(keys.contains("BBB_XCV_ISCGKU"));
    }

    @Test
    void collectAllBbbFailureKeys_ignoresWarningsAndOk() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(
                constraint("BBB_SAV_OK", "ok", null, XmlStatus.OK),
                constraint("BBB_SAV_WARN", "warn", "warn-msg", XmlStatus.WARNING),
                constraint("BBB_SAV_INFO", "info", null, XmlStatus.INFORMATION)));

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(keys.isEmpty(),
                "WARNING/INFORMATION/OK constraint'ler set'e EKLENMEMELİ — "
                        + "yalnız NOT_OK. WARN olduğu için legacy gate'i bozmuyordu, "
                        + "v2'de bu davranış korunmalı.");
    }

    @Test
    void collectAllBbbFailureKeys_returnsEmpty_whenDetailedReportNull() {
        Set<String> keys = service.collectAllBbbFailureKeys(null, SIG_ID);
        assertTrue(keys.isEmpty(), "Null güvenli — boş set döner.");
    }

    @Test
    void collectAllBbbFailureKeys_returnsEmpty_whenSignatureIdNotFound() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(constraint(ALLOWED_SAV_KEY, "q", "e", XmlStatus.NOT_OK)));

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), "UNKNOWN");

        assertTrue(keys.isEmpty(),
                "Bilinmeyen signatureId için boş set — gate de tolerance "
                        + "uygulamaz (no_failure_observed).");
    }

    @Test
    void collectAllBbbFailureKeys_isSubsetOfAllowedForHappyPath() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(constraint(ALLOWED_SAV_KEY, "q", "e", XmlStatus.NOT_OK)));

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertTrue(AdvancedSignatureVerificationService.ALLOWED_TOLERANCE_FAILURE_KEYS
                        .containsAll(keys),
                "Happy-path: gözlenen set allow-list'in ALT-KÜMESİ olmalı "
                        + "(gate geçer).");
    }

    @Test
    void collectAllBbbFailureKeys_isNotSubsetOfAllowedWhenExtraFailExists() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(constraint(ALLOWED_SAV_KEY, "q", "e", XmlStatus.NOT_OK)));
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU", "q", "e", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        Set<String> keys = service.collectAllBbbFailureKeys(wrap(bbb), SIG_ID);

        assertFalse(AdvancedSignatureVerificationService.ALLOWED_TOLERANCE_FAILURE_KEYS
                        .containsAll(keys),
                "SAV-only allowed + XCV KeyUsage hatası: allow-list ihlali — "
                        + "gate KAPANMALI (unallowed_failure_key).");
    }

    @Test
    void allowedToleranceSubIndications_containsOnlySigConstraintsFailure() {
        assertEquals(1, AdvancedSignatureVerificationService
                        .ALLOWED_TOLERANCE_SUB_INDICATIONS.size(),
                "Whitelist taxonomy lock: yalnız tek SubIndication izinli olmalı; "
                        + "yeni eklenir ise explicit code review gerektirir.");
        assertTrue(AdvancedSignatureVerificationService
                        .ALLOWED_TOLERANCE_SUB_INDICATIONS
                        .contains(eu.europa.esig.dss.enumerations.SubIndication.SIG_CONSTRAINTS_FAILURE),
                "İzinli tek değer SIG_CONSTRAINTS_FAILURE.");
    }

    @Test
    void allowedToleranceFailureKeys_containsOnlyBbbSavIsqpmdospp() {
        assertEquals(1, AdvancedSignatureVerificationService
                        .ALLOWED_TOLERANCE_FAILURE_KEYS.size(),
                "Whitelist lock: yalnız tek FAIL key izinli; genişletme "
                        + "code review gerektirir.");
        assertTrue(AdvancedSignatureVerificationService
                        .ALLOWED_TOLERANCE_FAILURE_KEYS.contains(ALLOWED_SAV_KEY));
    }

    // =========================================================================
    // Bölüm 2: collectFailingBbbConstraintMessages — DSS i18n enrichment
    // (Mevcut davranışın regresyon koruması — gate ile alakasız.)
    // =========================================================================

    @Test
    void collectFailingBbbConstraintMessages_emitsKeyUsageFailureWithReadableText() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "Does the certificate have an expected key-usage?",
                "The certificate does not have an expected key-usage!",
                XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);
        DetailedReport report = wrap(bbb);

        List<String> lines = service.collectFailingBbbConstraintMessages(report, SIG_ID);

        assertEquals(1, lines.size());
        assertEquals("[BBB_XCV_ISCGKU] The certificate does not have an expected key-usage!",
                lines.get(0));
    }

    @Test
    void collectFailingBbbConstraintMessages_collectsFromMultipleBlocksInOrder() {
        XmlBasicBuildingBlocks bbb = bbbWithId();

        XmlFC fc = new XmlFC();
        fc.getConstraint().add(constraint("BBB_FC_IEFF",
                "Does the signature format correspond to an expected format?",
                "The signature does not correspond to the expected format(s)!",
                XmlStatus.NOT_OK));
        bbb.setFC(fc);

        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ISCDC",
                "Is the cryptographic constraints OK?",
                "The cryptographic algorithm is no longer reliable!",
                XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_CCCBB",
                "Can the certificate chain be built till a trust anchor?",
                "The certificate chain is not trusted, it does not contain a trust anchor.",
                XmlStatus.NOT_OK));
        bbb.setXCV(xcv);

        List<String> lines = service.collectFailingBbbConstraintMessages(wrap(bbb), SIG_ID);

        assertEquals(3, lines.size());
        assertTrue(lines.get(0).startsWith("[BBB_FC_IEFF] "));
        assertTrue(lines.get(1).startsWith("[BBB_SAV_ISCDC] "));
        assertTrue(lines.get(2).startsWith("[BBB_XCV_CCCBB] "));
    }

    @Test
    void collectFailingBbbConstraintMessages_appendsAdditionalInfoWhenPresent() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        XmlConstraint c = constraint("BBB_XCV_ISCGKU",
                "Does the certificate have an expected key-usage?",
                "The certificate does not have an expected key-usage!",
                XmlStatus.NOT_OK);
        c.setAdditionalInfo("CN=EKİNCİLER DEMİR (serial=3290032427)");
        sub.getConstraint().add(c);
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<String> lines = service.collectFailingBbbConstraintMessages(wrap(bbb), SIG_ID);

        assertEquals(1, lines.size());
        assertTrue(lines.get(0).contains("does not have an expected key-usage!"),
                "Ana mesaj korunmalı.");
        assertTrue(lines.get(0).endsWith(" — CN=EKİNCİLER DEMİR (serial=3290032427)"),
                "AdditionalInfo \" — \" ile birleştirilmeli.");
    }

    @Test
    void collectFailingBbbConstraintMessages_fallsBackToConstraintNameWhenErrorEmpty() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_CCCBB",
                "Can the certificate chain be built till a trust anchor?",
                /*errorValue*/ null,
                XmlStatus.NOT_OK));
        bbb.setXCV(xcv);

        List<String> lines = service.collectFailingBbbConstraintMessages(wrap(bbb), SIG_ID);

        assertEquals(1, lines.size());
        assertEquals("[BBB_XCV_CCCBB] Can the certificate chain be built till a trust anchor?",
                lines.get(0));
    }

    @Test
    void collectFailingBbbConstraintMessages_skipsWarningsAndOkConstraints() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_OK", "ok", null, XmlStatus.OK));
        sav.getConstraint().add(constraint("BBB_SAV_WARN", "warn", "just a warn", XmlStatus.WARNING));
        sav.getConstraint().add(constraint("BBB_SAV_INFO", "info", null, XmlStatus.INFORMATION));
        sav.getConstraint().add(constraint("BBB_SAV_ISQPMDOSPP",
                "Is the message-digest or SignedProperties present?",
                "Neither message-digest nor SignedProperties is present!",
                XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        List<String> lines = service.collectFailingBbbConstraintMessages(wrap(bbb), SIG_ID);

        assertEquals(1, lines.size(), "Yalnız NOT_OK constraint'ler dönmeli.");
        assertTrue(lines.get(0).startsWith("[BBB_SAV_ISQPMDOSPP] "));
    }

    @Test
    void collectFailingBbbConstraintMessages_dedupesIdenticalLines() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV s1 = new XmlSubXCV();
        s1.setId("CERT-A");
        s1.getConstraint().add(constraint("BBB_XCV_ICTIVRSC",
                "Is the current time in the validity range?",
                "The current time is not in the validity range of the signer's certificate!",
                XmlStatus.NOT_OK));
        XmlSubXCV s2 = new XmlSubXCV();
        s2.setId("CERT-B");
        s2.getConstraint().add(constraint("BBB_XCV_ICTIVRSC",
                "Is the current time in the validity range?",
                "The current time is not in the validity range of the signer's certificate!",
                XmlStatus.NOT_OK));
        xcv.getSubXCV().add(s1);
        xcv.getSubXCV().add(s2);
        bbb.setXCV(xcv);

        List<String> lines = service.collectFailingBbbConstraintMessages(wrap(bbb), SIG_ID);

        assertEquals(1, lines.size(),
                "Aynı [KEY] mesaj satırı çift sayılmamalı (LinkedHashSet dedup).");
    }

    @Test
    void collectFailingBbbConstraintMessages_keepsSimilarLinesIfAdditionalInfoDiffers() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV s1 = new XmlSubXCV();
        s1.setId("CERT-A");
        XmlConstraint c1 = constraint("BBB_XCV_ICTIVRSC",
                "Is the current time in the validity range?",
                "The current time is not in the validity range of the signer's certificate!",
                XmlStatus.NOT_OK);
        c1.setAdditionalInfo("CN=Cert A");
        s1.getConstraint().add(c1);
        XmlSubXCV s2 = new XmlSubXCV();
        s2.setId("CERT-B");
        XmlConstraint c2 = constraint("BBB_XCV_ICTIVRSC",
                "Is the current time in the validity range?",
                "The current time is not in the validity range of the signer's certificate!",
                XmlStatus.NOT_OK);
        c2.setAdditionalInfo("CN=Cert B");
        s2.getConstraint().add(c2);
        xcv.getSubXCV().add(s1);
        xcv.getSubXCV().add(s2);
        bbb.setXCV(xcv);

        List<String> lines = service.collectFailingBbbConstraintMessages(wrap(bbb), SIG_ID);

        assertEquals(2, lines.size(),
                "AdditionalInfo farklıysa satırlar farklı; dedup uygulanmamalı.");
    }

    @Test
    void collectFailingBbbConstraintMessages_returnsEmpty_whenReportIsNull() {
        assertEquals(0, service.collectFailingBbbConstraintMessages(null, SIG_ID).size());
    }

    @Test
    void collectFailingBbbConstraintMessages_returnsEmpty_whenSignatureIdNotFound() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        bbb.setSAV(savWith(constraint(ALLOWED_SAV_KEY, "q", "e", XmlStatus.NOT_OK)));

        assertEquals(0, service.collectFailingBbbConstraintMessages(wrap(bbb), "UNKNOWN").size(),
                "Yanlış signatureId için boş liste dönmeli.");
    }

    @Test
    void collectFailingBbbConstraintMessages_handlesEmptyKeyGracefully() {
        XmlBasicBuildingBlocks bbb = bbbWithId();
        XmlSAV sav = new XmlSAV();
        XmlConstraint c = new XmlConstraint();
        c.setStatus(XmlStatus.NOT_OK);
        XmlMessage err = new XmlMessage();
        err.setValue("Catastrophic constraint failed.");
        c.setError(err);
        sav.getConstraint().add(c);
        bbb.setSAV(sav);

        List<String> lines = service.collectFailingBbbConstraintMessages(wrap(bbb), SIG_ID);

        assertEquals(1, lines.size());
        assertEquals("Catastrophic constraint failed.", lines.get(0),
                "Key yoksa yalnız mesaj döner (köşeli parantez yok).");
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private static XmlBasicBuildingBlocks bbbWithId() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        return bbb;
    }

    private static DetailedReport wrap(XmlBasicBuildingBlocks bbb) {
        XmlDetailedReport jaxb = new XmlDetailedReport();
        jaxb.getBasicBuildingBlocks().add(bbb);
        return new DetailedReport(jaxb);
    }

    private static XmlSAV savWith(XmlConstraint... constraints) {
        XmlSAV sav = new XmlSAV();
        for (XmlConstraint c : constraints) {
            sav.getConstraint().add(c);
        }
        return sav;
    }

    private static XmlConstraint constraint(String key, String nameValue,
                                            String errorValue, XmlStatus status) {
        XmlConstraint c = new XmlConstraint();
        XmlMessage name = new XmlMessage();
        name.setKey(key);
        name.setValue(nameValue);
        c.setName(name);
        if (errorValue != null) {
            XmlMessage err = new XmlMessage();
            err.setKey(key + "_ANS");
            err.setValue(errorValue);
            c.setError(err);
        }
        c.setStatus(status);
        return c;
    }

    /** Compile-time sanity: helper gerçekten bir {@link XmlConstraintsConclusion}
     * argümanını kabul ediyor mu? (Dökümantasyonun blok inheritance'ına
     * bağlı kalmasını sabitler — tip imzasında kayma olursa burası kırılır.) */
    @SuppressWarnings("unused")
    private static void compileTimeContract(XmlConstraintsConclusion block) { /* no-op */ }
}
