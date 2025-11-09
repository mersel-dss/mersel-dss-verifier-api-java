package io.mersel.dss.verify.api;

import io.mersel.dss.verify.api.exceptions.CertificateException;
import io.mersel.dss.verify.api.exceptions.InvalidDocumentException;
import io.mersel.dss.verify.api.exceptions.TimestampException;
import io.mersel.dss.verify.api.exceptions.VerificationException;
import io.mersel.dss.verify.api.models.ErrorResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Global exception handler test'leri.
 */
class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler exceptionHandler;
    private WebRequest webRequest;

    @BeforeEach
    void setUp() {
        exceptionHandler = new GlobalExceptionHandler();
        webRequest = mock(WebRequest.class);
        when(webRequest.getDescription(false)).thenReturn("uri=/api/v1/verify/pades");
    }

    @Test
    void testHandleVerificationException() {
        // Given
        VerificationException exception = new VerificationException("Doğrulama başarısız");

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleVerificationException(exception, webRequest);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("VERIFICATION_ERROR", response.getBody().getError());
        assertEquals("Doğrulama başarısız", response.getBody().getMessage());
        assertNotNull(response.getBody().getTimestamp());
    }

    @Test
    void testHandleCertificateException() {
        // Given
        CertificateException exception = new CertificateException("Sertifika geçersiz");

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleCertificateException(exception, webRequest);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("CERTIFICATE_ERROR", response.getBody().getError());
        assertEquals("Sertifika geçersiz", response.getBody().getMessage());
    }

    @Test
    void testHandleTimestampException() {
        // Given
        TimestampException exception = new TimestampException("Zaman damgası doğrulama hatası");

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleTimestampException(exception, webRequest);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("TIMESTAMP_ERROR", response.getBody().getError());
        assertEquals("Zaman damgası doğrulama hatası", response.getBody().getMessage());
    }

    @Test
    void testHandleInvalidDocumentException() {
        // Given
        InvalidDocumentException exception = new InvalidDocumentException("Geçersiz belge formatı");

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleInvalidDocumentException(exception, webRequest);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("INVALID_DOCUMENT", response.getBody().getError());
        assertEquals("Geçersiz belge formatı", response.getBody().getMessage());
    }

    @Test
    void testHandleMaxUploadSizeExceededException() {
        // Given
        MaxUploadSizeExceededException exception = 
            new MaxUploadSizeExceededException(200 * 1024 * 1024L);

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleMaxUploadSizeExceededException(exception, webRequest);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.PAYLOAD_TOO_LARGE, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("FILE_TOO_LARGE", response.getBody().getError());
        assertTrue(response.getBody().getMessage().contains("çok büyük"));
    }

    @Test
    void testHandleIllegalArgumentException() {
        // Given
        IllegalArgumentException exception = new IllegalArgumentException("Geçersiz parametre");

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleIllegalArgumentException(exception, webRequest);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("INVALID_ARGUMENT", response.getBody().getError());
        assertEquals("Geçersiz parametre", response.getBody().getMessage());
    }

    @Test
    void testHandleGlobalException() {
        // Given
        Exception exception = new RuntimeException("Beklenmeyen hata");

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleGlobalException(exception, webRequest);

        // Then
        assertNotNull(response);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("INTERNAL_ERROR", response.getBody().getError());
        assertTrue(response.getBody().getMessage().contains("Beklenmeyen bir hata"));
    }

    @Test
    void testErrorResponsePath() {
        // Given
        VerificationException exception = new VerificationException("Test");
        when(webRequest.getDescription(false)).thenReturn("uri=/api/v1/verify/xades");

        // When
        ResponseEntity<ErrorResponse> response = 
            exceptionHandler.handleVerificationException(exception, webRequest);

        // Then
        assertNotNull(response.getBody());
        assertEquals("/api/v1/verify/xades", response.getBody().getPath());
    }
}

