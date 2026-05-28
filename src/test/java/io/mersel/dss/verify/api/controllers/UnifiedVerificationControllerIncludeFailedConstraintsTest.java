package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.models.FailedConstraint;
import io.mersel.dss.verify.api.models.FailureCategory;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.timestamp.AdvancedTimestampVerificationService;
import io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.multipart.MultipartFile;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@link UnifiedVerificationController} için
 * {@code includeFailedConstraints} query parameter kontratı testi.
 *
 * <p>Davranış garantileri:</p>
 * <ul>
 *   <li>Default davranış (parametre yok / <code>false</code>): service'in
 *       4-arg overload'u {@code includeFailedConstraints=false} ile çağrılır;
 *       response'taki her {@link SignatureInfo#getFailedConstraints()
 *       signatures[i].failedConstraints} alanı JSON'a yazılmaz
 *       (NON_NULL — service tarafı zaten null bırakmıştır).</li>
 *   <li>Açık davranış (<code>true</code>): service'in 4-arg overload'u
 *       {@code includeFailedConstraints=true} ile çağrılır; service liste
 *       doldurursa her imzada {@code failedConstraints} alanı görünür ve
 *       kategorize satırları taşır ({@code ROOT_CAUSE}, {@code DERIVED},
 *       {@code CASCADE}).</li>
 *   <li>{@code rootCause} alanı her iki durumda da bağımsızdır — opt-in
 *       parametresinden etkilenmez (default davranışta da dolar).</li>
 * </ul>
 *
 * <p>Standalone MockMvc kullanılır — Spring context yüklenmez (hızlı
 * unit-style test). Service field injection için {@link ReflectionTestUtils}.
 * MockMvc Spring Boot autoconfig'ini yüklemediği için global
 * {@code spring.jackson.default-property-inclusion} property burada
 * uygulanmaz; assertion'lar yalnız class-level {@code @JsonInclude(NON_NULL)}
 * davranışına dayanır.</p>
 */
class UnifiedVerificationControllerIncludeFailedConstraintsTest {

    private MockMvc mockMvc;
    private AdvancedSignatureVerificationService verificationService;

    @BeforeEach
    void setUp() {
        verificationService = mock(AdvancedSignatureVerificationService.class);
        AdvancedTimestampVerificationService timestampService =
                mock(AdvancedTimestampVerificationService.class);

        UnifiedVerificationController controller = new UnifiedVerificationController();
        ReflectionTestUtils.setField(
                controller, "advancedSignatureVerificationService", verificationService);
        ReflectionTestUtils.setField(
                controller, "advancedTimestampVerificationService", timestampService);

        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void omittedParam_passesFalse_andResponseHasNoFailedConstraints() throws Exception {
        // Service stub: yalnız rootCause dolu (default davranış). failedConstraints
        // alanını set ETMEZ (null kalır).
        VerificationResult stubbed = stubInvalidWithRootCauseOnly();
        when(verificationService.verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(false)))
                .thenReturn(stubbed);

        MockMultipartFile signedDocument = new MockMultipartFile(
                "signedDocument", "imza.xml", "text/xml", "<xml/>".getBytes());

        String body = mockMvc.perform(multipart("/api/v1/verify/signature")
                        .file(signedDocument)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // Service'in 4-arg overload'u false ile çağrılmalı (default değer).
        verify(verificationService).verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(false));

        // failedConstraints alanı service tarafında null bırakıldı → JSON'a yazılmamalı.
        assertFalse(body.contains("failedConstraints"),
                "includeFailedConstraints gönderilmediğinde response'ta failedConstraints "
                        + "alanı GÖRÜNMEMELİ. Body: " + body);
        // rootCause her zaman dönmeli — opt-in flag'inden bağımsız.
        assertTrue(body.contains("\"rootCause\""),
                "rootCause alanı default davranışta da görünmeli. Body: " + body);
    }

    @Test
    void explicitFalse_passesFalse_andResponseHasNoFailedConstraints() throws Exception {
        VerificationResult stubbed = stubInvalidWithRootCauseOnly();
        when(verificationService.verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(false)))
                .thenReturn(stubbed);

        MockMultipartFile signedDocument = new MockMultipartFile(
                "signedDocument", "imza.xml", "text/xml", "<xml/>".getBytes());

        String body = mockMvc.perform(multipart("/api/v1/verify/signature")
                        .file(signedDocument)
                        .param("includeFailedConstraints", "false")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        verify(verificationService).verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(false));
        assertFalse(body.contains("failedConstraints"),
                "includeFailedConstraints=false explicit verildiğinde de alan görünmemeli. "
                        + "Body: " + body);
    }

    @Test
    void explicitTrue_passesTrue_andResponseHasCategorizedFailedConstraints() throws Exception {
        // Service stub: hem rootCause hem failedConstraints (3 satır, 3 kategori) dolu.
        VerificationResult stubbed = stubInvalidWithFullFailedConstraints();
        when(verificationService.verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(true)))
                .thenReturn(stubbed);

        MockMultipartFile signedDocument = new MockMultipartFile(
                "signedDocument", "imza.xml", "text/xml", "<xml/>".getBytes());

        String body = mockMvc.perform(multipart("/api/v1/verify/signature")
                        .file(signedDocument)
                        .param("includeFailedConstraints", "true")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // Service'in 4-arg overload'u true ile çağrılmalı.
        verify(verificationService).verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(true));

        // failedConstraints listesi response'ta görünmeli.
        assertTrue(body.contains("\"failedConstraints\""),
                "includeFailedConstraints=true ile failedConstraints alanı response'ta "
                        + "GÖRÜNMELİ. Body: " + body);
        // Üç kategori de JSON string olarak göründüğünden emin ol — frontend
        // bunlar üzerinden filtreleme yapacak. Tüm API enum'larıyla aynı
        // convention (UPPER_CASE, enum sabit adı).
        assertTrue(body.contains("\"ROOT_CAUSE\""),
                "ROOT_CAUSE kategorisi JSON string olarak görünmeli. Body: " + body);
        assertTrue(body.contains("\"DERIVED\""),
                "DERIVED kategorisi JSON string olarak görünmeli. Body: " + body);
        assertTrue(body.contains("\"CASCADE\""),
                "CASCADE kategorisi JSON string olarak görünmeli. Body: " + body);
        // DSS sabit kodları stabil — locale değişse bile aynı kalır.
        assertTrue(body.contains("BBB_XCV_ISCGKU"),
                "Root cause key'i JSON içeriğinde görünmeli. Body: " + body);
        assertTrue(body.contains("BBB_XCV_SUB"),
                "Derived key'i JSON içeriğinde görünmeli. Body: " + body);
        assertTrue(body.contains("BBB_SAV_ISQPMDOSPP"),
                "Cascade key'i JSON içeriğinde görünmeli. Body: " + body);
    }

    @Test
    void includeFailedConstraints_alsoSupportedOn_xadesEndpoint() throws Exception {
        VerificationResult stubbed = stubInvalidWithFullFailedConstraints();
        when(verificationService.verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(true)))
                .thenReturn(stubbed);

        MockMultipartFile signedDocument = new MockMultipartFile(
                "signedDocument", "imza.xml", "text/xml", "<xml/>".getBytes());

        String body = mockMvc.perform(multipart("/api/v1/verify/xades")
                        .file(signedDocument)
                        .param("includeFailedConstraints", "true")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // Legacy /xades endpoint'i de aynı parametreyi destekler — geriye uyumluluk
        // için tutulan endpoint, yeni alanı sessizce yutmuyor.
        verify(verificationService).verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(true));
        assertTrue(body.contains("\"failedConstraints\""),
                "Legacy /xades endpoint'inde de failedConstraints alanı response'ta "
                        + "görünmeli. Body: " + body);
    }

    @Test
    void controller_doesNotEmit_legacyDetailedReportField() throws Exception {
        // Top-level detailedReport alanı tamamen kaldırıldı (XML/JSON ham JAXB
        // varyantları artık API'de yok). Service stub default davranışla cevap
        // versin; response'ta o alanın hiç görünmediğini doğrula.
        VerificationResult stubbed = stubInvalidWithRootCauseOnly();
        when(verificationService.verifySignature(
                any(MultipartFile.class), any(), any(VerificationLevel.class), eq(false)))
                .thenReturn(stubbed);

        MockMultipartFile signedDocument = new MockMultipartFile(
                "signedDocument", "imza.xml", "text/xml", "<xml/>".getBytes());

        String body = mockMvc.perform(multipart("/api/v1/verify/signature")
                        .file(signedDocument)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertFalse(body.contains("detailedReport"),
                "Eski 'detailedReport' alanı response'ta görünmemeli "
                        + "(API'den tamamen kaldırıldı). Body: " + body);
        assertEquals(true, body.contains("\"status\":\"INVALID\""));
    }

    /**
     * Sentetik VerificationResult: tek imzada yalnız {@code rootCause} dolu,
     * {@code failedConstraints} null. Default davranışı (opt-in kapalı)
     * simüle eder.
     */
    private static VerificationResult stubInvalidWithRootCauseOnly() {
        VerificationResult result = new VerificationResult(false, "INVALID");
        SignatureInfo sig = new SignatureInfo();
        sig.setSignatureId("S-FAKE");
        sig.setValid(false);
        sig.setRootCause(new FailedConstraint(
                "BBB_XCV_ISCGKU",
                "İmzacı sertifikası, beklenen anahtar kullanım alanına sahip değil!"));
        result.setSignatures(Collections.singletonList(sig));
        result.setSignatureCount(1);
        return result;
    }

    /**
     * Sentetik VerificationResult: kullanıcının canonical "şifreleme
     * sertifikasıyla imzalama" senaryosunu temsil eder — KeyUsage root cause +
     * XCV-top derived + SAV cascade. Opt-in davranışı simüle eder.
     */
    private static VerificationResult stubInvalidWithFullFailedConstraints() {
        VerificationResult result = new VerificationResult(false, "INVALID");
        SignatureInfo sig = new SignatureInfo();
        sig.setSignatureId("S-FAKE");
        sig.setValid(false);

        FailedConstraint rootCause = new FailedConstraint(
                "BBB_XCV_ISCGKU",
                "İmzacı sertifikası, beklenen anahtar kullanım alanına sahip değil!",
                FailureCategory.ROOT_CAUSE);
        FailedConstraint derived = new FailedConstraint(
                "BBB_XCV_SUB",
                "SubXCV sonucu geçerli mi?",
                FailureCategory.DERIVED);
        FailedConstraint cascade = new FailedConstraint(
                "BBB_SAV_ISQPMDOSPP",
                "İmzalı qualifying property mevcut mu?",
                FailureCategory.CASCADE);

        sig.setRootCause(rootCause);
        sig.setFailedConstraints(Arrays.asList(rootCause, derived, cascade));

        result.setSignatures(Collections.singletonList(sig));
        result.setSignatureCount(1);
        return result;
    }
}
