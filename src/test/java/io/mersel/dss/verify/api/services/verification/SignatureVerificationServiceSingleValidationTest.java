package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.models.enums.SignatureType;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * <strong>Triple Validation Bug regresyon kanıtı</strong> —
 * {@link SignatureVerificationService#parseVerificationResult(Reports,
 * VerificationLevel)} ve bağlı yardımcılar yalnızca <em>tek</em>
 * {@link Reports} nesnesini okur, DSS pipeline'ı yeniden tetiklemez.
 *
 * <p>Önceki sürümde aynı doküman 3 kez {@code validator.validateDocument()}
 * ile doğrulanıyordu (satır 125, 283, 374): bir kez ana akış, bir kez
 * sertifika bilgilerini almak için {@code populateSignatureInfo}, bir kez
 * imza tipini belirlemek için {@code determineSignatureType}. Bu hem
 * performans bombasıydı (DSS pipeline + OCSP/CRL fetch × 3) hem de
 * <em>tutarlılık riski</em> (OCSP responder farklı saniyede farklı cevap
 * verebilir, {@code BestSignatureTime} kayabilir, KeyUsage gibi
 * constraint'lerin verdict'i değişebilir).</p>
 *
 * <p><strong>Bu sınıfın görevi:</strong> Fix'in geriye düşmemesini
 * kilitlemek. {@link Reports} mock'unun yöntem çağrı sayılarını sayıp
 * üst sınırlarda kalıp kalmadıklarını assert ediyoruz. Yarın kim
 * <em>tekrar</em> bir başka {@code reports.getDiagnosticData()} cycle'ı
 * eklerse veya bir {@code validateDocument()} çağrısı sızdırırsa
 * test patlar.</p>
 *
 * <h3>Kontrat sabitleri</h3>
 * <ul>
 *   <li><b>{@code getSimpleReport()}</b>: ≥1 (parseVerificationResult,
 *       populateSignatureInfo, createValidationDetails, determineSignatureType
 *       hepsi aynı nesneden okur — memoized OK).</li>
 *   <li><b>{@code getDiagnosticData()}</b>: ≥0 (yalnız populateSignatureInfo'da
 *       sertifika bilgisi için bir kez per signature). Tek imza: 1, hiçbir
 *       imza: 0.</li>
 *   <li><b>Hiçbir başka API çağrılmamalı</b> — özellikle yeni bir DSS
 *       pipeline tetikleme yok.</li>
 * </ul>
 */
class SignatureVerificationServiceSingleValidationTest {

    private final SignatureVerificationService service = new SignatureVerificationService();

    /**
     * Happy path: tek imza, BASIC seviye — Reports tek nesne olarak
     * geçilir ve {@code getDiagnosticData()} EN FAZLA 1 kez çağrılır
     * (sertifika bilgisi için). Bu, "her şey bir kez koşturulsun"
     * kontratının kanonik kanıtı.
     */
    @Test
    void parseVerificationResult_invokesReports_atMostOnce_perDataKind() {
        Reports reports = mock(Reports.class);
        SimpleReport simpleReport = mock(SimpleReport.class);
        DiagnosticData diagnosticData = mock(DiagnosticData.class);

        when(reports.getSimpleReport()).thenReturn(simpleReport);
        when(reports.getDiagnosticData()).thenReturn(diagnosticData);
        when(simpleReport.getSignatureIdList()).thenReturn(Collections.singletonList("SIG-1"));
        when(simpleReport.getIndication("SIG-1")).thenReturn(Indication.TOTAL_PASSED);
        when(simpleReport.getJaxbModel()).thenReturn(new XmlSimpleReport());
        when(simpleReport.isValid("SIG-1")).thenReturn(true);
        when(simpleReport.getSignatureFormat("SIG-1")).thenReturn(null);
        when(simpleReport.getBestSignatureTime("SIG-1")).thenReturn(null);
        when(diagnosticData.getSignatures()).thenReturn(Collections.emptyList());

        VerificationResult result = service.parseVerificationResult(reports, VerificationLevel.SIMPLE);

        assertNotNull(result, "Sonuç dönmeli.");
        assertTrue(result.isValid(), "TOTAL_PASSED → isValid=true beklenir.");
        assertEquals("VALID", result.getStatus(), "Status alanı VALID olmalı.");

        // KRİTİK KONTRAT: DiagnosticData yalnızca 1 kez alınır (signatures
        // boş bile olsa populateSignatureInfo bir kez okur). Yarın
        // tekrar 2x'e çıkarsa fix gerilemiştir.
        verify(reports, times(1)).getDiagnosticData();

        // SimpleReport memoized — birden fazla yardımcı okuyabilir ama
        // hepsi aynı nesneye refer eder. ≥1 yeterli.
        verify(reports, atLeastOnce()).getSimpleReport();
    }

    /**
     * Çoklu imza: her imza için DiagnosticData TAM N kez alınır (her
     * signature loop iterasyonunda populateSignatureInfo bir kez okur).
     * Önceki bug'da `validator.validateDocument()` her iterasyonda
     * tetikleniyordu — şimdi yalnızca getDiagnosticData() çağrılıyor,
     * pipeline yeniden çalışmıyor.
     */
    @Test
    void parseVerificationResult_multiSignature_invokesGetDiagnosticData_oncePerSignature() {
        Reports reports = mock(Reports.class);
        SimpleReport simpleReport = mock(SimpleReport.class);
        DiagnosticData diagnosticData = mock(DiagnosticData.class);

        List<String> signatureIds = Arrays.asList("SIG-A", "SIG-B", "SIG-C");
        when(reports.getSimpleReport()).thenReturn(simpleReport);
        when(reports.getDiagnosticData()).thenReturn(diagnosticData);
        when(simpleReport.getSignatureIdList()).thenReturn(signatureIds);
        for (String id : signatureIds) {
            when(simpleReport.getIndication(id)).thenReturn(Indication.TOTAL_PASSED);
            when(simpleReport.isValid(id)).thenReturn(true);
            when(simpleReport.getSignatureFormat(id)).thenReturn(null);
            when(simpleReport.getBestSignatureTime(id)).thenReturn(null);
        }
        when(simpleReport.getJaxbModel()).thenReturn(new XmlSimpleReport());
        when(diagnosticData.getSignatures()).thenReturn(Collections.emptyList());

        VerificationResult result = service.parseVerificationResult(reports, VerificationLevel.SIMPLE);

        assertTrue(result.isValid());
        assertEquals(3, result.getSignatures().size());

        // 3 imza için tam 3 kez getDiagnosticData() (her signature loop
        // iterasyonunda populateSignatureInfo bir kez). Hiç ek pipeline
        // tetiklemesi YOK.
        verify(reports, times(signatureIds.size())).getDiagnosticData();
    }

    /**
     * COMPREHENSIVE seviye: createValidationDetails de SimpleReport
     * üzerinden okur, ek bir DSS pipeline tetikleme yapmaz.
     */
    @Test
    void parseVerificationResult_comprehensive_doesNotTriggerExtraDiagnosticData() {
        Reports reports = mock(Reports.class);
        SimpleReport simpleReport = mock(SimpleReport.class);
        DiagnosticData diagnosticData = mock(DiagnosticData.class);

        when(reports.getSimpleReport()).thenReturn(simpleReport);
        when(reports.getDiagnosticData()).thenReturn(diagnosticData);
        when(simpleReport.getSignatureIdList()).thenReturn(Collections.singletonList("SIG-1"));
        when(simpleReport.getIndication("SIG-1")).thenReturn(Indication.TOTAL_PASSED);
        when(simpleReport.isValid("SIG-1")).thenReturn(true);
        when(simpleReport.getJaxbModel()).thenReturn(new XmlSimpleReport());
        when(simpleReport.getSignatureFormat("SIG-1")).thenReturn(null);
        when(simpleReport.getBestSignatureTime("SIG-1")).thenReturn(new Date());
        when(diagnosticData.getSignatures()).thenReturn(Collections.emptyList());

        VerificationResult result = service.parseVerificationResult(reports,
                VerificationLevel.COMPREHENSIVE);

        assertNotNull(result.getValidationDetails(),
                "COMPREHENSIVE seviyede validationDetails dolmalı.");

        // COMPREHENSIVE seviyesi createValidationDetails'i tetikler ama
        // o da SimpleReport'tan okur — pipeline yeniden koşmaz.
        verify(reports, times(1)).getDiagnosticData();
    }

    /**
     * İmza bulunmayan doküman: SimpleReport'tan boş liste döner, hiç
     * imza işlenmediği için DiagnosticData ZERO TIMES çağrılır.
     */
    @Test
    void parseVerificationResult_noSignatures_doesNotCallGetDiagnosticData() {
        Reports reports = mock(Reports.class);
        SimpleReport simpleReport = mock(SimpleReport.class);

        when(reports.getSimpleReport()).thenReturn(simpleReport);
        when(simpleReport.getSignatureIdList()).thenReturn(Collections.emptyList());

        VerificationResult result = service.parseVerificationResult(reports, VerificationLevel.SIMPLE);

        assertNotNull(result);
        assertFalse(result.isValid());
        assertEquals("NO_SIGNATURE_FOUND", result.getStatus());

        // İmza yoksa DiagnosticData hiç alınmaz; pipeline tetikleme
        // riski yok.
        verify(reports, never()).getDiagnosticData();
        assertNull(result.getSignatureType(),
                "İmza yoksa signatureType da set edilmemeli.");
    }

    /**
     * <b>InOrder kontrat</b>: Çağrı sırası önemli olabilir — SimpleReport
     * önce alınır (signatureIdList için), sonra her imza loop'unda
     * DiagnosticData alınır. Bu sıra, gelecekteki refactoring'in yine
     * aynı tek-validation kalıbını koruduğunu kanıtlar.
     */
    @Test
    void parseVerificationResult_simpleReportFirst_thenDiagnosticData_inOrder() {
        Reports reports = mock(Reports.class);
        SimpleReport simpleReport = mock(SimpleReport.class);
        DiagnosticData diagnosticData = mock(DiagnosticData.class);

        when(reports.getSimpleReport()).thenReturn(simpleReport);
        when(reports.getDiagnosticData()).thenReturn(diagnosticData);
        when(simpleReport.getSignatureIdList()).thenReturn(Collections.singletonList("SIG-1"));
        when(simpleReport.getIndication("SIG-1")).thenReturn(Indication.TOTAL_PASSED);
        when(simpleReport.isValid("SIG-1")).thenReturn(true);
        when(simpleReport.getJaxbModel()).thenReturn(new XmlSimpleReport());
        when(simpleReport.getSignatureFormat("SIG-1")).thenReturn(null);
        when(simpleReport.getBestSignatureTime("SIG-1")).thenReturn(null);
        when(diagnosticData.getSignatures()).thenReturn(Collections.emptyList());

        service.parseVerificationResult(reports, VerificationLevel.SIMPLE);

        InOrder inOrder = inOrder(reports);
        inOrder.verify(reports, atLeastOnce()).getSimpleReport();
        inOrder.verify(reports, times(1)).getDiagnosticData();
    }

    /**
     * SignatureFormat XAdES dönerse signatureType=XADES set edilmeli.
     * determineSignatureType da SimpleReport üzerinden okur — pipeline
     * tetikleme yok.
     */
    @Test
    void determineSignatureType_readsFromSimpleReport_withoutRevalidation() {
        Reports reports = mock(Reports.class);
        SimpleReport simpleReport = mock(SimpleReport.class);
        DiagnosticData diagnosticData = mock(DiagnosticData.class);

        when(reports.getSimpleReport()).thenReturn(simpleReport);
        when(reports.getDiagnosticData()).thenReturn(diagnosticData);
        when(simpleReport.getSignatureIdList()).thenReturn(Collections.singletonList("SIG-1"));
        when(simpleReport.getIndication("SIG-1")).thenReturn(Indication.TOTAL_PASSED);
        when(simpleReport.isValid("SIG-1")).thenReturn(true);
        when(simpleReport.getJaxbModel()).thenReturn(new XmlSimpleReport());
        when(simpleReport.getSignatureFormat("SIG-1"))
                .thenReturn(eu.europa.esig.dss.enumerations.SignatureLevel.XAdES_BASELINE_B);
        when(simpleReport.getBestSignatureTime("SIG-1")).thenReturn(null);
        when(diagnosticData.getSignatures()).thenReturn(Collections.emptyList());

        VerificationResult result = service.parseVerificationResult(reports, VerificationLevel.SIMPLE);

        assertEquals(SignatureType.XADES, result.getSignatureType(),
                "XAdES formatından SignatureType.XADES set edilmeli.");
        verify(reports, times(1)).getDiagnosticData();
    }
}
