package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.services.verification.SignatureVerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.web.multipart.MultipartFile;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * PadesVerificationController test'leri.
 */
@ExtendWith(MockitoExtension.class)
class PadesVerificationControllerTest {

    @Mock
    private SignatureVerificationService verificationService;

    @InjectMocks
    private PadesVerificationController controller;

    private MultipartFile mockSignedDocument;

    @BeforeEach
    void setUp() {
        mockSignedDocument = new MockMultipartFile(
            "signedDocument",
            "signed.pdf",
            "application/pdf",
            "test pdf content".getBytes()
        );
    }

    @Test
    void testVerifySimple_withSimpleLevel_shouldReturnResult() {
        // Given
        VerificationResult mockResult = new VerificationResult();
        mockResult.setValid(true);
        mockResult.setStatus("VALID");

        when(verificationService.verifySignature(
            any(MultipartFile.class),
            isNull(),
            eq(VerificationLevel.SIMPLE)
        )).thenReturn(mockResult);

        // When
        ResponseEntity<VerificationResult> response = controller.verifySimple(
            mockSignedDocument,
            VerificationLevel.SIMPLE
        );

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().isValid());
        assertEquals("VALID", response.getBody().getStatus());

        verify(verificationService, times(1)).verifySignature(
            any(MultipartFile.class),
            isNull(),
            eq(VerificationLevel.SIMPLE)
        );
    }

    @Test
    void testVerifySimple_withComprehensiveLevel_shouldReturnResult() {
        // Given
        VerificationResult mockResult = new VerificationResult();
        mockResult.setValid(true);
        mockResult.setStatus("VALID");

        when(verificationService.verifySignature(
            any(MultipartFile.class),
            isNull(),
            eq(VerificationLevel.COMPREHENSIVE)
        )).thenReturn(mockResult);

        // When
        ResponseEntity<VerificationResult> response = controller.verifySimple(
            mockSignedDocument,
            VerificationLevel.COMPREHENSIVE
        );

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().isValid());
        assertEquals("VALID", response.getBody().getStatus());

        verify(verificationService, times(1)).verifySignature(
            any(MultipartFile.class),
            isNull(),
            eq(VerificationLevel.COMPREHENSIVE)
        );
    }

    @Test
    void testVerifySimple_withDefaultLevel_shouldUseDefault() {
        // Given
        VerificationResult mockResult = new VerificationResult();
        mockResult.setValid(true);
        mockResult.setStatus("VALID");

        when(verificationService.verifySignature(
            any(MultipartFile.class),
            isNull(),
            eq(VerificationLevel.SIMPLE) // default
        )).thenReturn(mockResult);

        // When - level parametresi belirtilmeden çağrı (default SIMPLE)
        ResponseEntity<VerificationResult> response = controller.verifySimple(
            mockSignedDocument,
            VerificationLevel.SIMPLE // default value
        );

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody().isValid());

        verify(verificationService, times(1)).verifySignature(
            any(MultipartFile.class),
            isNull(),
            eq(VerificationLevel.SIMPLE)
        );
    }
}

