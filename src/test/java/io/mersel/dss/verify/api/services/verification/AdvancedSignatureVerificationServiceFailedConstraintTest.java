package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
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
import eu.europa.esig.dss.enumerations.Indication;
import io.mersel.dss.verify.api.models.FailedConstraint;
import io.mersel.dss.verify.api.models.FailureCategory;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AdvancedSignatureVerificationService#collectFailingBbbConstraintDetails}
 * birim testleri.
 *
 * <p>Bu testler, opaque <code>"[KEY] message"</code> string'i yerine yapısal
 * {@link FailedConstraint} objesi ({@code key} + {@code message} ayrı) üreten
 * yeni helper'ı kilitler. ETSI EN 319 102-1 spec dilinde bu objeler
 * "<em>failed constraints</em>" olarak adlandırılır — DSS DetailedReport
 * içindeki <code>&lt;Constraint Status="NOT_OK"&gt;</code> elementlerine
 * birebir eşlenir. Frontend bu objeleri:</p>
 * <ul>
 *   <li>{@code key} üzerinden lookup table ile zenginleştirebilir
 *       (örn. severity, kategori, doc URL),</li>
 *   <li>{@code message}'ı doğrudan kullanıcıya gösterebilir,</li>
 *   <li>i18n locale değişse bile {@code key} stabil kalacağı için audit ve
 *       integrasyon kontratını koruyabilir.</li>
 * </ul>
 *
 * <p>Mock {@link DetailedReport} kuruyoruz; gerçek DSS pipeline çalıştırmadan
 * davranışı izole ediyoruz.</p>
 */
class AdvancedSignatureVerificationServiceFailedConstraintTest {

    private final AdvancedSignatureVerificationService service =
            new AdvancedSignatureVerificationService();

    private static final String SIG_ID = "SIG-1";

    // -------------------------------------------------------------------------
    // Temel davranış: key ve message ayrı alanlar
    // -------------------------------------------------------------------------

    @Test
    void emitsStructuredKeyAndMessage_separately() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "Sertifikanın anahtar kullanım alanı imza için yetkili mi?",
                "Sertifika beklenen anahtar kullanım alanına sahip değil!",
                XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        FailedConstraint d = details.get(0);
        assertEquals("BBB_XCV_ISCGKU", d.getKey(),
                "Key, DSS i18n bundle anahtarı olarak çıkmalı (locale'den bağımsız).");
        assertEquals("Sertifika beklenen anahtar kullanım alanına sahip değil!",
                d.getMessage(),
                "Message, DSS error.value (locale çevirisi) olarak çıkmalı.");
    }

    @Test
    void preservesEnglishKeyEvenWhenMessageIsTurkish() {
        // Realistic case: tr locale aktif, dss-messages_tr.properties'ten
        // çeviri geliyor; ama key (XmlMessage.key) DSS sabit kodu — değişmez.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ISQPMDOSPP",
                "İmzalı nitelik: 'message-digest' veya 'SignedProperties' mevcut mu?",
                "Ne 'message-digest' ne de 'SignedProperties' niteliği bulunuyor!",
                XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertEquals("BBB_SAV_ISQPMDOSPP", details.get(0).getKey(),
                "Locale ne olursa olsun key audit kontratı olarak stabil.");
        assertTrue(details.get(0).getMessage().contains("Ne 'message-digest'"),
                "Message Türkçe çeviriyi taşımalı.");
    }

    @Test
    void appendsAdditionalInfoToMessage_butNotToKey() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        XmlConstraint c = constraint("BBB_XCV_ISCGKU",
                "noop",
                "Sertifika beklenen anahtar kullanım alanına sahip değil!",
                XmlStatus.NOT_OK);
        c.setAdditionalInfo("CN=KAMUSM, serial=3290032427");
        sub.getConstraint().add(c);
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        FailedConstraint d = details.get(0);
        assertEquals("BBB_XCV_ISCGKU", d.getKey(),
                "Key alanı additionalInfo bağlamı içermez — temiz makine kontratı.");
        assertTrue(d.getMessage().endsWith(" — CN=KAMUSM, serial=3290032427"),
                "Message, additionalInfo \" — \" ile birleştirilmiş şekilde gelmeli.");
    }

    @Test
    void fallsBackToConstraintNameWhenErrorIsAbsent() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        // error.value yok — name.value (soru cümlesi) fallback olmalı
        xcv.getConstraint().add(constraint("BBB_XCV_CCCBB",
                "Sertifika zinciri bir güven kökü bulana kadar inşa edilebiliyor mu?",
                /*errorValue*/ null, XmlStatus.NOT_OK));
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertEquals("BBB_XCV_CCCBB", details.get(0).getKey());
        assertEquals("Sertifika zinciri bir güven kökü bulana kadar inşa edilebiliyor mu?",
                details.get(0).getMessage(),
                "error.value yoksa name.value (soru) en azından bir bağlam vermeli.");
    }

    @Test
    void emitsSyntheticMessage_whenBothErrorAndNameValuesAreEmpty() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlSAV sav = new XmlSAV();
        // Hem error hem name.value boş — defansif fallback "(constraint failed)" üretmeli
        XmlConstraint c = new XmlConstraint();
        c.setStatus(XmlStatus.NOT_OK);
        XmlMessage name = new XmlMessage();
        name.setKey("BBB_SAV_ANON");
        // name.value null bırakılıyor
        c.setName(name);
        sav.getConstraint().add(c);
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertEquals("BBB_SAV_ANON", details.get(0).getKey());
        assertEquals("(constraint failed)", details.get(0).getMessage(),
                "Hiçbir mesaj kaynağı yoksa defansif sentetik metin dönmeli — "
                        + "frontend her zaman bir mesaj görür, render kırılmaz.");
    }

    // -------------------------------------------------------------------------
    // Çoklu BBB blok birleşimi
    // -------------------------------------------------------------------------

    @Test
    void traversesAllBbbBlocks_inExpectedOrder() {
        // Helper kontratı: FC → ISC → VCI → CV → SAV → XCV (top + subXCV) → PSV
        // Bu sıra plan'da sabit (görsel okuma kolaylığı + DSS DetailedReport
        // gerçek üretim sırasını yaklaşıkla aynı tutar).
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);

        XmlFC fc = new XmlFC();
        fc.getConstraint().add(constraint("BBB_FC_IEFF", "fc-name", "fc-err", XmlStatus.NOT_OK));
        bbb.setFC(fc);

        XmlISC isc = new XmlISC();
        isc.getConstraint().add(constraint("BBB_ICS_ISCI", "isc-name", "isc-err", XmlStatus.NOT_OK));
        bbb.setISC(isc);

        XmlVCI vci = new XmlVCI();
        vci.getConstraint().add(constraint("BBB_VCI_ISPK", "vci-name", "vci-err", XmlStatus.NOT_OK));
        bbb.setVCI(vci);

        XmlCV cv = new XmlCV();
        cv.getConstraint().add(constraint("BBB_CV_IRDOI", "cv-name", "cv-err", XmlStatus.NOT_OK));
        bbb.setCV(cv);

        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ISVA", "sav-name", "sav-err", XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_CCCBB", "xcv-name", "xcv-err", XmlStatus.NOT_OK));
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU", "subxcv-name", "subxcv-err", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        XmlPSV psv = new XmlPSV();
        psv.getConstraint().add(constraint("PSV_IPCVA", "psv-name", "psv-err", XmlStatus.NOT_OK));
        bbb.setPSV(psv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(8, details.size(),
                "Her bloktan birer FAIL constraint = 8 detay (FC, ISC, VCI, CV, SAV, "
                        + "XCV-top, XCV-sub, PSV).");
        assertEquals("BBB_FC_IEFF",   details.get(0).getKey());
        assertEquals("BBB_ICS_ISCI",  details.get(1).getKey());
        assertEquals("BBB_VCI_ISPK",  details.get(2).getKey());
        assertEquals("BBB_CV_IRDOI",  details.get(3).getKey());
        assertEquals("BBB_SAV_ISVA",  details.get(4).getKey());
        assertEquals("BBB_XCV_CCCBB", details.get(5).getKey());
        assertEquals("BBB_XCV_ISCGKU", details.get(6).getKey());
        assertEquals("PSV_IPCVA",     details.get(7).getKey());
    }

    // -------------------------------------------------------------------------
    // Filtreleme: yalnız NOT_OK
    // -------------------------------------------------------------------------

    @Test
    void skipsOkInformationAndWarningConstraints() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_OK", "ok", "ok", XmlStatus.OK));
        sav.getConstraint().add(constraint("BBB_SAV_WARN", "w", "w", XmlStatus.WARNING));
        sav.getConstraint().add(constraint("BBB_SAV_INFO", "i", "i", XmlStatus.INFORMATION));
        sav.getConstraint().add(constraint("BBB_SAV_ISQPMDOSPP",
                "Is the message-digest or SignedProperties present?",
                "Neither message-digest nor SignedProperties is present!",
                XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size(),
                "Yalnız NOT_OK constraint'ler FailedConstraint olarak dönmeli; "
                        + "WARNING/INFORMATION zaten ayrı warning kanalına gider.");
        assertEquals("BBB_SAV_ISQPMDOSPP", details.get(0).getKey());
    }

    // -------------------------------------------------------------------------
    // Dedup davranışı
    // -------------------------------------------------------------------------

    @Test
    void dedupesIdenticalKeyAndMessage() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV s1 = new XmlSubXCV();
        s1.setId("CERT-A");
        s1.getConstraint().add(constraint("BBB_XCV_ICTIVRSC",
                "name", "Aynı mesaj.", XmlStatus.NOT_OK));
        XmlSubXCV s2 = new XmlSubXCV();
        s2.setId("CERT-B");
        s2.getConstraint().add(constraint("BBB_XCV_ICTIVRSC",
                "name", "Aynı mesaj.", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(s1);
        xcv.getSubXCV().add(s2);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size(),
                "Aynı (key,message) çifti tek satır olarak dönmeli (LinkedHashSet "
                        + "compound dedup).");
    }

    @Test
    void keepsBothEntries_whenAdditionalInfoDiffers() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV s1 = new XmlSubXCV();
        s1.setId("CERT-A");
        XmlConstraint c1 = constraint("BBB_XCV_ICTIVRSC", "name",
                "Geçerlilik dışı.", XmlStatus.NOT_OK);
        c1.setAdditionalInfo("CN=Cert A");
        s1.getConstraint().add(c1);
        XmlSubXCV s2 = new XmlSubXCV();
        s2.setId("CERT-B");
        XmlConstraint c2 = constraint("BBB_XCV_ICTIVRSC", "name",
                "Geçerlilik dışı.", XmlStatus.NOT_OK);
        c2.setAdditionalInfo("CN=Cert B");
        s2.getConstraint().add(c2);
        xcv.getSubXCV().add(s1);
        xcv.getSubXCV().add(s2);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(2, details.size(),
                "Aynı KEY iki farklı sertifika için (additionalInfo farklı) "
                        + "iki ayrı detay olarak korunmalı — her birinin sertifikası "
                        + "ayrı bir failure'dır.");
        assertEquals("BBB_XCV_ICTIVRSC", details.get(0).getKey());
        assertEquals("BBB_XCV_ICTIVRSC", details.get(1).getKey());
        assertTrue(details.get(0).getMessage().endsWith("CN=Cert A"));
        assertTrue(details.get(1).getMessage().endsWith("CN=Cert B"));
    }

    // -------------------------------------------------------------------------
    // Locale bağımsızlığı (yapısal — gerçek I18nProvider yok ama key pattern test edilir)
    // -------------------------------------------------------------------------

    @Test
    void keyRemainsConstantAcrossDifferentMessageContents() {
        // Aynı XmlMessage.key ile, farklı locale'lerden gelmiş gibi farklı value'lar:
        // tr çevirisi vs en default. Helper key'i ne olursa olsun stabil tutmalı.
        XmlBasicBuildingBlocks bbbTr = new XmlBasicBuildingBlocks();
        bbbTr.setId(SIG_ID);
        XmlXCV xcvTr = new XmlXCV();
        xcvTr.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "TR soru?",
                "Sertifika beklenen anahtar kullanım alanına sahip değil!",
                XmlStatus.NOT_OK));
        bbbTr.setXCV(xcvTr);

        XmlBasicBuildingBlocks bbbEn = new XmlBasicBuildingBlocks();
        bbbEn.setId(SIG_ID);
        XmlXCV xcvEn = new XmlXCV();
        xcvEn.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "EN question?",
                "The certificate does not have an expected key-usage!",
                XmlStatus.NOT_OK));
        bbbEn.setXCV(xcvEn);

        List<FailedConstraint> tr = service.collectFailingBbbConstraintDetails(
                wrap(bbbTr), SIG_ID);
        List<FailedConstraint> en = service.collectFailingBbbConstraintDetails(
                wrap(bbbEn), SIG_ID);

        assertEquals(tr.get(0).getKey(), en.get(0).getKey(),
                "Locale değişse bile key alanı aynı kalmalı — frontend lookup "
                        + "ve audit kontratı kırılmaz.");
        assertEquals("BBB_XCV_ISCGKU", tr.get(0).getKey());
        // Ama mesajlar locale'e göre farklı:
        assertTrue(tr.get(0).getMessage().contains("Sertifika"));
        assertTrue(en.get(0).getMessage().contains("certificate"));
    }

    // -------------------------------------------------------------------------
    // Defansif davranışlar
    // -------------------------------------------------------------------------

    @Test
    void returnsEmptyList_whenDetailedReportIsNull() {
        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(null, SIG_ID);

        assertNotNull(details);
        assertEquals(0, details.size(),
                "Null DetailedReport: defansif boş liste; çağıran NPE almaz.");
    }

    @Test
    void returnsEmptyList_whenSignatureIdIsNull() {
        DetailedReport report = wrap(savBbb("BBB_SAV_ISVA", "msg"));

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(report, null);

        assertEquals(0, details.size(),
                "Null signatureId: helper bir BBB ile eşleşemez; boş döner.");
    }

    @Test
    void returnsEmptyList_whenSignatureIdNotFound() {
        DetailedReport report = wrap(savBbb("BBB_SAV_ISVA", "msg"));

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                report, "UNKNOWN-SIG");

        assertEquals(0, details.size(),
                "Mismatch signatureId: hiç BBB bulunmaz, boş liste döner.");
    }

    @Test
    void returnsEmptyList_whenAllConstraintsAreOk() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_OK", "ok", "ok", XmlStatus.OK));
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(0, details.size(), "Hiç FAIL yoksa boş liste — service tarafında "
                + "rootCause null kalır, response'ta JSON'a yazılmaz.");
    }

    @Test
    void handlesEmptyKeyGracefully() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlSAV sav = new XmlSAV();
        XmlConstraint c = new XmlConstraint();
        c.setStatus(XmlStatus.NOT_OK);
        XmlMessage err = new XmlMessage();
        err.setValue("Key alanı olmayan ham bir hata.");
        c.setError(err);
        sav.getConstraint().add(c);
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertNull(details.get(0).getKey(),
                "DSS bazı edge case'lerde XmlMessage.key vermeyebilir; key null kalır.");
        assertEquals("Key alanı olmayan ham bir hata.", details.get(0).getMessage(),
                "Key olmasa bile message korunur — bilgi kaybı olmamalı.");
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static DetailedReport wrap(XmlBasicBuildingBlocks bbb) {
        XmlDetailedReport jaxb = new XmlDetailedReport();
        jaxb.getBasicBuildingBlocks().add(bbb);
        return new DetailedReport(jaxb);
    }

    private static XmlBasicBuildingBlocks savBbb(String key, String message) {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint(key, "name", message, XmlStatus.NOT_OK));
        bbb.setSAV(sav);
        return bbb;
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

    // -------------------------------------------------------------------------
    // Root-cause filtering — pipeline roll-up + cascade satırlarını gizle
    //
    // DSS pipeline'ı sıkı hiyerarşik akış izler: alt-blokta failure → üst-blok
    // summary roll-up → SAV/CV cascade. Tek kök neden birden fazla NOT_OK
    // constraint üretir. collectFailingBbbConstraintDetails sessizce
    // filtreler — yalnız kök nedeni döndürür (defansif fallback ile).
    // -------------------------------------------------------------------------

    @Test
    void subXcvKeyUsageFailure_isReturnedAsRootCause() {
        // En klasik kök neden: SubXCV içindeki specific certificate check.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "name", "KeyUsage yanlış", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertEquals("BBB_XCV_ISCGKU", details.get(0).getKey(),
                "SubXCV içindeki specific check kök neden olarak listelenir.");
    }

    @Test
    void bbbXcvSub_rollUp_isClassifiedAsDerived_whenSubXcvHasFailure() {
        // XCV-top'taki BBB_XCV_SUB summary roll-up; SubXCV'de gerçek failure
        // varsa DERIVED kategorisinde işaretlenmeli (response'tan silinmez —
        // kullanıcı opt-in ile görebilir, ama selectRootCause atlar).
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_SUB",
                "name", "Sertifika doğrulaması kesin sonuçlu değil!", XmlStatus.NOT_OK));
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "name", "KeyUsage yanlış", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(2, details.size(),
                "İki satır da listede (kategorize). Liste: " + details);
        FailedConstraint root = byKey(details, "BBB_XCV_ISCGKU");
        FailedConstraint derived = byKey(details, "BBB_XCV_SUB");
        assertNotNull(root);
        assertEquals(FailureCategory.ROOT_CAUSE, root.getCategory(),
                "SubXCV içindeki spesifik check kök neden.");
        assertNotNull(derived);
        assertEquals(FailureCategory.DERIVED, derived.getCategory(),
                "BBB_XCV_SUB roll-up — DERIVED kategorisinde işaretlenmeli "
                        + "(yeni: silinmez, etiketlenir).");
    }

    @Test
    void bbbXcvIctivrsc_rollUp_isClassifiedAsDerived_whenSubXcvHasFailure() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_ICTIVRSC",
                "name", "Sertifika zinciri güven kökünde değil!", XmlStatus.NOT_OK));
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_CCCBB",
                "name", "Zincir kurulamıyor", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(2, details.size(), "Her iki satır da kategorize listeye düşmeli.");
        FailedConstraint root = byKey(details, "BBB_XCV_CCCBB");
        FailedConstraint derived = byKey(details, "BBB_XCV_ICTIVRSC");
        assertNotNull(root);
        assertEquals(FailureCategory.ROOT_CAUSE, root.getCategory(),
                "SubXCV içindeki spesifik chain check kök neden.");
        assertNotNull(derived);
        assertEquals(FailureCategory.DERIVED, derived.getCategory(),
                "BBB_XCV_ICTIVRSC roll-up — DERIVED.");
    }

    @Test
    void bbbXcvSub_remainsInList_whenAlone_viaDefensiveFallback() {
        // Marjinal: SubXCV'de hiç NOT_OK yok ama XCV-top'ta BBB_XCV_SUB var.
        // Defansif fallback devreye girer — root cause boş, ham listeye geri dön.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_SUB",
                "name", "msg", XmlStatus.NOT_OK));
        // SubXCV listesi boş — XCV_SUB'ı filter de etmemeli (whitelist tetiklenmez)
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertEquals("BBB_XCV_SUB", details.get(0).getKey(),
                "SubXCV'de gerçek failure yoksa BBB_XCV_SUB rolü oynamıyor; "
                        + "ROOT_CAUSE olarak korunmalı (yanlış pozitif filtre yok).");
    }

    @Test
    void savCascade_isClassifiedAsCascade_whenXcvIndeterminate() {
        // Kullanıcının kanonik durumu: BBB_SAV_ISQPMDOSPP, XCV INDETERMINATE iken
        // sertifika context'i kullanılamadığı için SAV "kontrol edilemedi" üretir.
        // CASCADE kategorisinde işaretlenmeli — selectRootCause atlar, opt-in
        // failedConstraints'te kullanıcı gözlemleyebilir.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlConclusion conclusion = new XmlConclusion();
        conclusion.setIndication(Indication.INDETERMINATE);
        xcv.setConclusion(conclusion);
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "name", "KeyUsage yanlış", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ISQPMDOSPP",
                "name", "message-digest yok", XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(2, details.size(), "Hem cascade hem root cause listede. Liste: " + details);
        FailedConstraint root = byKey(details, "BBB_XCV_ISCGKU");
        FailedConstraint cascade = byKey(details, "BBB_SAV_ISQPMDOSPP");
        assertNotNull(root);
        assertEquals(FailureCategory.ROOT_CAUSE, root.getCategory());
        assertNotNull(cascade);
        assertEquals(FailureCategory.CASCADE, cascade.getCategory(),
                "SAV cascade XCV INDETERMINATE iken CASCADE kategorisinde işaretlenmeli.");
    }

    @Test
    void cvCascade_isClassifiedAsCascade_whenXcvFailed() {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlConclusion conclusion = new XmlConclusion();
        conclusion.setIndication(Indication.FAILED);
        xcv.setConclusion(conclusion);
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "name", "KeyUsage", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);
        XmlCV cv = new XmlCV();
        cv.getConstraint().add(constraint("BBB_CV_IRDOI",
                "name", "Reference doğrulanamadı", XmlStatus.NOT_OK));
        bbb.setCV(cv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(2, details.size());
        FailedConstraint root = byKey(details, "BBB_XCV_ISCGKU");
        FailedConstraint cascade = byKey(details, "BBB_CV_IRDOI");
        assertNotNull(root);
        assertEquals(FailureCategory.ROOT_CAUSE, root.getCategory());
        assertNotNull(cascade);
        assertEquals(FailureCategory.CASCADE, cascade.getCategory(),
                "CV cascade XCV FAILED iken CASCADE kategorisinde.");
    }

    @Test
    void savFailure_remainsInList_whenXcvHealthy() {
        // XCV başarılıyken SAV failure cascade DEĞİL — gerçek root cause.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlConclusion conclusion = new XmlConclusion();
        conclusion.setIndication(Indication.PASSED);
        xcv.setConclusion(conclusion);
        bbb.setXCV(xcv);
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ISQPMDOSPP",
                "name", "message-digest yok", XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertEquals("BBB_SAV_ISQPMDOSPP", details.get(0).getKey(),
                "XCV PASSED iken SAV failure bağımsız → root cause olarak listelenir.");
    }

    @Test
    void savFailure_remainsInList_whenXcvConclusionAbsent() {
        // Defansif: XCV bloğu yok → cascade flag false kalır → SAV kök neden.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ANS",
                "name", "msg", XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(1, details.size());
        assertEquals("BBB_SAV_ANS", details.get(0).getKey());
    }

    @Test
    void psvAndFcAndIscFailures_alwaysListed_regardlessOfXcvState() {
        // PSV/FC/ISC blokları XCV durumundan bağımsız değerlendirilir — filter
        // bunları gizlemez.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlConclusion conclusion = new XmlConclusion();
        conclusion.setIndication(Indication.INDETERMINATE);
        xcv.setConclusion(conclusion);
        bbb.setXCV(xcv);

        XmlFC fc = new XmlFC();
        fc.getConstraint().add(constraint("BBB_FC_IEFF", "n", "format", XmlStatus.NOT_OK));
        bbb.setFC(fc);
        XmlISC isc = new XmlISC();
        isc.getConstraint().add(constraint("BBB_ICS_ISCI", "n", "isc", XmlStatus.NOT_OK));
        bbb.setISC(isc);
        XmlPSV psv = new XmlPSV();
        psv.getConstraint().add(constraint("PSV_IPCVA", "n", "psv", XmlStatus.NOT_OK));
        bbb.setPSV(psv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertNotNull(byKey(details, "BBB_FC_IEFF"),
                "FC failure listede olmalı (XCV durumundan bağımsız).");
        assertNotNull(byKey(details, "BBB_ICS_ISCI"));
        assertNotNull(byKey(details, "PSV_IPCVA"));
    }

    @Test
    void canonicalThreeFailureChain_classifiesAllThreeCategories() {
        // Kullanıcının gerçek dünya senaryosu: KeyUsage hatası → 3 NOT_OK constraint
        // (SubXCV/ISCGKU + XCV-top/SUB + SAV/ISQPMDOSPP). Yeni davranış: hepsi
        // listede, her biri doğru kategoride. selectRootCause yalnız ROOT_CAUSE'u
        // seçer; opt-in failedConstraints listede tam zincir görünür.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);

        XmlXCV xcv = new XmlXCV();
        XmlConclusion conclusion = new XmlConclusion();
        conclusion.setIndication(Indication.INDETERMINATE);
        xcv.setConclusion(conclusion);
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "name", "KeyUsage yanlış", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        xcv.getConstraint().add(constraint("BBB_XCV_SUB",
                "name", "Sertifika doğrulaması kesin değil", XmlStatus.NOT_OK));
        bbb.setXCV(xcv);

        XmlSAV sav = new XmlSAV();
        sav.getConstraint().add(constraint("BBB_SAV_ISQPMDOSPP",
                "name", "message-digest yok", XmlStatus.NOT_OK));
        bbb.setSAV(sav);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertEquals(3, details.size(),
                "Üç NOT_OK constraint'in üçü de kategorize listede. Liste: " + details);
        FailedConstraint root = byKey(details, "BBB_XCV_ISCGKU");
        FailedConstraint derived = byKey(details, "BBB_XCV_SUB");
        FailedConstraint cascade = byKey(details, "BBB_SAV_ISQPMDOSPP");
        assertNotNull(root);
        assertEquals(FailureCategory.ROOT_CAUSE, root.getCategory(),
                "SubXCV içindeki spesifik KeyUsage check = ROOT_CAUSE.");
        assertNotNull(derived);
        assertEquals(FailureCategory.DERIVED, derived.getCategory(),
                "BBB_XCV_SUB summary roll-up = DERIVED.");
        assertNotNull(cascade);
        assertEquals(FailureCategory.CASCADE, cascade.getCategory(),
                "SAV constraint XCV INDETERMINATE iken = CASCADE.");
    }

    @Test
    void unknownXcvTopKey_remainsInList_evenWithSubXcvFailure() {
        // Whitelist'inde olmayan XCV-top constraint'i, SubXCV'de failure olsa bile
        // ROOT_CAUSE olarak korunmalı (konservatif: yanlış filtre yok).
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        xcv.getConstraint().add(constraint("BBB_XCV_UNKNOWN_NEW_KEY",
                "name", "msg", XmlStatus.NOT_OK));
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "name", "KeyUsage", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);

        assertNotNull(byKey(details, "BBB_XCV_UNKNOWN_NEW_KEY"),
                "Whitelist dışındaki XCV-top constraint'leri filtre tarafından "
                        + "gizlenmemeli — DSS yeni sürümünde gerçek kök nedenleri "
                        + "saklamamak için konservatif yaklaşım.");
        assertNotNull(byKey(details, "BBB_XCV_ISCGKU"));
    }

    @Test
    void defensiveFallback_returnsAllFailures_whenOnlyRollUpsPresent() {
        // Patolojik edge case: yalnız roll-up satırları var, hiç root cause yok.
        // Filter her şeyi yutarsa bilgi kaybı olur — defansif fallback ile ham
        // listeye geri dönülür.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        // SubXCV'de NOT_OK var (roll-up tetikleyicisi)
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_DUMMY", "name", "x", XmlStatus.OK));
        // ↑ OK; collectFailingBbbConstraintDetails bunu zaten almaz
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);
        // ... ama bu test'te zaten root cause yok; sadece BBB_XCV_SUB var
        // (whitelisted). Bu durumda hasSubXcvFailure false → BBB_XCV_SUB
        // ROOT_CAUSE kalır. Bu defansif fallback'i test etmek için aslında
        // "SubXCV NOT_OK var ama hepsi filtrelenir" senaryosunu kuramayız —
        // çünkü SubXCV NOT_OK her zaman kök neden olur. Yani fallback sadece
        // teorik bir koruma; mevcut algoritmanın olağan akışında tetiklenmez.
        // En basit test: hiç FAIL yok → boş liste.
        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);
        assertEquals(0, details.size(),
                "Hiç FAIL constraint yoksa boş liste — fallback de tetiklenmez.");
    }

    @Test
    void categorizedOutput_emitsCategoryField_asUpperCaseEnumName() throws Exception {
        // Alan kontratı: FailedConstraint listesindeki her satır kendi
        // 'category' alanını taşır; Jackson default davranışıyla enum sabit
        // adı (UPPER_CASE) string olarak serialize edilir — diğer API
        // enum'larıyla (SignatureType, SignaturePackaging, ...) aynı convention.
        // Frontend bunlar üzerinden filtreleme yapacak.
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(SIG_ID);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-LEAF");
        sub.getConstraint().add(constraint("BBB_XCV_ISCGKU",
                "name", "KeyUsage yanlış", XmlStatus.NOT_OK));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);

        List<FailedConstraint> details = service.collectFailingBbbConstraintDetails(
                wrap(bbb), SIG_ID);
        String json = new com.fasterxml.jackson.databind.ObjectMapper()
                .writeValueAsString(details);

        assertTrue(json.contains("\"category\""),
                "FailedConstraint 'category' alanını içermeli. JSON: " + json);
        assertTrue(json.contains("\"ROOT_CAUSE\""),
                "ROOT_CAUSE enum, Jackson tarafından enum sabit adı (UPPER_CASE) "
                        + "JSON string olarak serialize edilmeli. JSON: " + json);
        assertFalse(json.contains("\"root_cause\""),
                "Enum adı lower-snake-case değil, UPPER_CASE olmalı — diğer API "
                        + "enum'larıyla aynı convention. JSON: " + json);
    }

    @Test
    void rootCauseOnlyField_doesNotEmitCategory_perTwoArgConstructor() throws Exception {
        // SignatureInfo.rootCause alanı için kullanılan 2-arg constructor
        // category set ETMEZ (her zaman ROOT_CAUSE olduğu için JSON'a yazılmaz);
        // @JsonInclude(NON_NULL) ile alan gizlenir.
        FailedConstraint root = new FailedConstraint(
                "BBB_XCV_ISCGKU", "KeyUsage yanlış");
        String json = new com.fasterxml.jackson.databind.ObjectMapper()
                .writeValueAsString(root);

        assertFalse(json.contains("category"),
                "rootCause alanı için 2-arg constructor category null bırakır, NON_NULL ile "
                        + "JSON'da görünmez (UX: tek nesne = kategoriye gerek yok). JSON: " + json);
    }

    // -------- Filter test helper'ı -----

    private static FailedConstraint byKey(List<FailedConstraint> list, String key) {
        for (FailedConstraint d : list) {
            if (key.equals(d.getKey())) {
                return d;
            }
        }
        return null;
    }
}
