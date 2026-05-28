package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import io.mersel.dss.verify.api.models.FailedConstraint;
import io.mersel.dss.verify.api.models.FailureCategory;
import io.mersel.dss.verify.api.models.TimestampInfo;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code AdvancedSignatureVerificationService.extractTimestampInfo}
 * private helper'ının imza simetrisinde {@code rootCause} ve opt-in
 * {@code failedConstraints} alanlarını doldurması için kontrat testi.
 *
 * <p>Önceki davranışta {@link TimestampInfo}'da {@code rootCause} ve
 * {@code failedConstraints} alanları getter/setter'larıyla kontratta
 * vardı ama service tarafında <strong>hiç</strong> set edilmiyordu —
 * hayalet kontrat. Bu sınıf, alanların gerçekten timestamp BBB
 * bloğundan dolduğunu kilitleyen regresyon kanıtıdır.</p>
 *
 * <p>Mockito ile minimal {@link TimestampWrapper} kuruyoruz; manuel olarak
 * üretilmiş {@link DetailedReport} ile timestamp BBB bloğunu eşliyoruz.
 * Method private olduğu için Spring {@link ReflectionTestUtils} ile
 * çağrılır.</p>
 */
class AdvancedSignatureVerificationServiceTimestampInfoTest {

    private final AdvancedSignatureVerificationService service =
            new AdvancedSignatureVerificationService();

    private static final String TS_ID = "TS-1";

    @Test
    void rootCause_isSet_fromTimestampBbbBlock_evenWithOptInFalse() {
        // Default davranış (opt-in kapalı): TimestampInfo.rootCause hala
        // dolar — önceki versiyonda hayalet alan idi, bu test onun
        // gerçekten doldurulduğunu kilitler.
        TimestampWrapper wrapper = mockTimestampWrapper(TS_ID);
        DetailedReport detailedReport = detailedReportWithTimestampBbb(TS_ID,
                "BBB_XCV_ISCGKU", "TSA sertifikası KeyUsage uygunsuz");

        TimestampInfo result = invokeExtractTimestampInfo(wrapper, detailedReport, false);

        assertNotNull(result.getRootCause(),
                "rootCause timestamp BBB bloğundan çekilip TimestampInfo'ya yazılmalı.");
        assertEquals("BBB_XCV_ISCGKU", result.getRootCause().getKey());
        assertNull(result.getFailedConstraints(),
                "Opt-in kapalıyken failedConstraints null kalmalı (NON_NULL).");
    }

    @Test
    void failedConstraints_isFilled_whenIncludeFlagIsTrue() {
        TimestampWrapper wrapper = mockTimestampWrapper(TS_ID);
        DetailedReport detailedReport = detailedReportWithTimestampBbb(TS_ID,
                "BBB_XCV_ISCGKU", "TSA sertifikası KeyUsage uygunsuz");

        TimestampInfo result = invokeExtractTimestampInfo(wrapper, detailedReport, true);

        assertNotNull(result.getFailedConstraints(),
                "Opt-in true iken failedConstraints liste olarak set edilmeli.");
        assertEquals(1, result.getFailedConstraints().size());
        FailedConstraint fc = result.getFailedConstraints().get(0);
        assertEquals("BBB_XCV_ISCGKU", fc.getKey());
        assertEquals(FailureCategory.ROOT_CAUSE, fc.getCategory(),
                "Imza tarafıyla aynı sınıflandırma kuralları timestamp için de geçerli.");
    }

    @Test
    void failedConstraints_isEmptyArray_whenOptInTrue_butNoFailures() {
        // Timestamp BBB bloğu var ama hiç FAIL constraint yok (TSA sağlıklı).
        // Opt-in açık: alan boş array olarak set edilmeli (frontend "alan
        // istendi mi?" sınamasından kurtulur).
        TimestampWrapper wrapper = mockTimestampWrapper(TS_ID);
        DetailedReport detailedReport = detailedReportWithEmptyTimestampBbb(TS_ID);

        TimestampInfo result = invokeExtractTimestampInfo(wrapper, detailedReport, true);

        assertNotNull(result.getFailedConstraints(),
                "Opt-in açıkken alan null kalmamalı — boş bile olsa set edilmeli.");
        assertTrue(result.getFailedConstraints().isEmpty());
        assertNull(result.getRootCause(),
                "FAIL yoksa rootCause null kalmalı (NON_NULL ile JSON'a yazılmaz).");
    }

    @Test
    void noFields_areSet_whenDetailedReportIsNull() {
        // Defansif kontrat: detailedReport null ise alanlar null kalır;
        // diğer alanlar (valid, time, type, tsaName) zarar görmez.
        TimestampWrapper wrapper = mockTimestampWrapper(TS_ID);

        TimestampInfo result = invokeExtractTimestampInfo(wrapper, null, true);

        assertNull(result.getRootCause());
        assertNull(result.getFailedConstraints());
        // Eski alanlar hala doldurulmuş olmalı
        assertEquals(true, result.isValid());
    }

    @Test
    void noFields_areSet_whenTimestampIdIsNull() {
        // Edge case: TimestampWrapper.getId() null dönerse BBB lookup
        // anlamsız → alanlar null kalır.
        TimestampWrapper wrapper = mockTimestampWrapper(null);
        DetailedReport detailedReport = detailedReportWithTimestampBbb(TS_ID,
                "BBB_XCV_ISCGKU", "msg");

        TimestampInfo result = invokeExtractTimestampInfo(wrapper, detailedReport, true);

        assertNull(result.getRootCause());
        assertNull(result.getFailedConstraints());
    }

    @Test
    void noFields_areSet_whenTimestampBbbDoesNotExist() {
        // BBB pipeline'ında bu timestamp ID için entry yok (örn. başka
        // timestamp'in BBB'si var). Helper boş liste döner; rootCause
        // null kalır, opt-in açıksa failedConstraints boş array.
        TimestampWrapper wrapper = mockTimestampWrapper(TS_ID);
        DetailedReport detailedReport = detailedReportWithTimestampBbb(
                "OTHER-TS-ID", "BBB_XCV_ISCGKU", "msg");

        TimestampInfo resultDefault = invokeExtractTimestampInfo(wrapper, detailedReport, false);
        assertNull(resultDefault.getRootCause(),
                "Eşleşen BBB entry yoksa rootCause null kalmalı.");
        assertNull(resultDefault.getFailedConstraints(),
                "Opt-in kapalıyken failedConstraints zaten null.");

        TimestampInfo resultOptIn = invokeExtractTimestampInfo(wrapper, detailedReport, true);
        assertNotNull(resultOptIn.getFailedConstraints(),
                "Opt-in açıkken alan boş listeyle set edilir.");
        assertTrue(resultOptIn.getFailedConstraints().isEmpty());
    }

    // ---------- helpers ----------

    private TimestampInfo invokeExtractTimestampInfo(
            TimestampWrapper wrapper,
            DetailedReport detailedReport,
            boolean includeFailedConstraints) {
        return (TimestampInfo) ReflectionTestUtils.invokeMethod(
                service,
                "extractTimestampInfo",
                wrapper, detailedReport, includeFailedConstraints);
    }

    private static TimestampWrapper mockTimestampWrapper(String id) {
        TimestampWrapper m = Mockito.mock(TimestampWrapper.class);
        Mockito.when(m.getId()).thenReturn(id);
        Mockito.when(m.isMessageImprintDataFound()).thenReturn(true);
        Mockito.when(m.isMessageImprintDataIntact()).thenReturn(true);
        Mockito.when(m.getProductionTime()).thenReturn(new Date());
        Mockito.when(m.getType()).thenReturn(null);
        Mockito.when(m.getSigningCertificate()).thenReturn(null);
        return m;
    }

    private static DetailedReport detailedReportWithTimestampBbb(
            String bbbId, String constraintKey, String message) {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(bbbId);
        XmlXCV xcv = new XmlXCV();
        XmlSubXCV sub = new XmlSubXCV();
        sub.setId("CERT-TSA");
        sub.getConstraint().add(constraint(constraintKey, message));
        xcv.getSubXCV().add(sub);
        bbb.setXCV(xcv);
        return wrap(bbb);
    }

    private static DetailedReport detailedReportWithEmptyTimestampBbb(String bbbId) {
        XmlBasicBuildingBlocks bbb = new XmlBasicBuildingBlocks();
        bbb.setId(bbbId);
        // Hiç FAIL constraint eklemiyoruz
        return wrap(bbb);
    }

    private static DetailedReport wrap(XmlBasicBuildingBlocks bbb) {
        XmlDetailedReport report = new XmlDetailedReport();
        report.getBasicBuildingBlocks().add(bbb);
        return new DetailedReport(report);
    }

    private static XmlConstraint constraint(String key, String message) {
        XmlConstraint c = new XmlConstraint();
        c.setStatus(XmlStatus.NOT_OK);
        XmlMessage name = new XmlMessage();
        name.setKey(key);
        name.setValue("name");
        c.setName(name);
        XmlMessage err = new XmlMessage();
        err.setKey(key + "_ANS");
        err.setValue(message);
        c.setError(err);
        return c;
    }
}
