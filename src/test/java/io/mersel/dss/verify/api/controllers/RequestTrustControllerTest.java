package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.GlobalExceptionHandler;
import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.dtos.TimestampVerificationResponseDto;
import io.mersel.dss.verify.api.services.certificate.*;
import io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService;
import io.mersel.dss.verify.api.services.timestamp.AdvancedTimestampVerificationService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class RequestTrustControllerTest {
    AdvancedSignatureVerificationService signatures = mock(AdvancedSignatureVerificationService.class);
    AdvancedTimestampVerificationService timestamps = mock(AdvancedTimestampVerificationService.class);
    MockMvc mvc(boolean enabled) {
        UnifiedVerificationController controller = new UnifiedVerificationController();
        ReflectionTestUtils.setField(controller, "advancedSignatureVerificationService", signatures);
        ReflectionTestUtils.setField(controller, "advancedTimestampVerificationService", timestamps);
        ReflectionTestUtils.setField(controller, "requestTrustFactory", new RequestTrustFactory(enabled));
        return MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new GlobalExceptionHandler()).build();
    }
    MockMultipartFile document() { return new MockMultipartFile("signedDocument", "test.xml", "text/xml", "<test/>".getBytes()); }
    @Test void disabledCustomAndUnknownModeAreRejectedBeforeVerification() throws Exception {
        MockMvc mvc = mvc(false);
        mvc.perform(multipart("/api/v1/verify/signature").file(document()).param("trustMode", "CUSTOM").accept(org.springframework.http.MediaType.APPLICATION_JSON)).andExpect(status().isBadRequest());
        mvc.perform(multipart("/api/v1/verify/signature").file(document()).param("trustMode", "OTHER")).andExpect(status().isBadRequest());
        verifyNoInteractions(signatures);
    }
    @Test void serverModeCannotSilentlyIgnoreUploadedRoots() throws Exception {
        mvc(true).perform(multipart("/api/v1/verify/signature").file(document())
            .file(new MockMultipartFile("trustedCertificates", "bad.cer", "application/pkix-cert", new byte[]{1})))
            .andExpect(status().isBadRequest());
        verifyNoInteractions(signatures);
    }
    @Test void customEmptyIsForwardedWithoutFallbackIncludingLegacyAliases() throws Exception {
        when(signatures.verifySignature(any(), any(), any(), anyBoolean(), any())).thenAnswer(call -> {
            RequestTrustContext trust = call.getArgument(4);
            VerificationResult result = new VerificationResult(false, "NO_SIGNATURE_FOUND"); result.setTrustContext(trust.evidence(false)); return result;
        });
        MockMvc mvc = mvc(true);
        for (String endpoint : new String[]{"signature", "xades", "pades", "cades"}) {
            mvc.perform(multipart("/api/v1/verify/" + endpoint).file(document()).param("trustMode", "CUSTOM").accept(org.springframework.http.MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()).andExpect(jsonPath("$.trustContext.mode").value("CUSTOM"))
                .andExpect(jsonPath("$.trustContext.certificateCount").value(0)).andExpect(jsonPath("$.trustContext.anchors").isEmpty());
        }
        verify(signatures, times(4)).verifySignature(any(), any(), any(), anyBoolean(), any());
        verify(signatures, never()).verifySignature(any(), any(), any(), anyBoolean());
    }
    @Test void customTimestampRequiresCertificateValidationAndForwardsEmptyRoots() throws Exception {
        MockMultipartFile file = new MockMultipartFile("timestampFile", "test.tsr", "application/timestamp-reply", new byte[]{1});
        MockMvc mvc = mvc(true);
        mvc.perform(multipart("/api/v1/verify/timestamp").file(file).param("trustMode", "CUSTOM").param("validateCertificate", "false"))
            .andExpect(status().isBadRequest());
        verifyNoInteractions(timestamps);
        when(timestamps.verifyTimestamp(any(), any(), eq(true), any())).thenAnswer(call -> {
            RequestTrustContext trust = call.getArgument(3);
            TimestampVerificationResponseDto result = new TimestampVerificationResponseDto(false, "INVALID_FORMAT"); result.setTrustContext(trust.evidence(false)); return result;
        });
        mvc.perform(multipart("/api/v1/verify/timestamp").file(file).param("trustMode", "CUSTOM").accept(org.springframework.http.MediaType.APPLICATION_JSON))
            .andExpect(status().isOk()).andExpect(jsonPath("$.trustContext.mode").value("CUSTOM"));
    }
}
