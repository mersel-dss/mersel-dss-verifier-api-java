package io.mersel.dss.verify.api;

import io.mersel.dss.verify.api.exceptions.CertificateException;
import io.mersel.dss.verify.api.exceptions.InvalidDocumentException;
import io.mersel.dss.verify.api.exceptions.TimestampException;
import io.mersel.dss.verify.api.exceptions.VerificationException;
import io.mersel.dss.verify.api.models.ErrorResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * Global Exception Handler
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(VerificationException.class)
    public ResponseEntity<ErrorResponse> handleVerificationException(
            VerificationException ex, WebRequest request) {
        logger.error("Verification error: {}", ex.getMessage(), ex);
        
        ErrorResponse error = new ErrorResponse(
            "VERIFICATION_ERROR",
            ex.getMessage(),
            "İmza doğrulama işlemi sırasında bir hata oluştu"
        );
        error.setPath(request.getDescription(false).replace("uri=", ""));
        
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(CertificateException.class)
    public ResponseEntity<ErrorResponse> handleCertificateException(
            CertificateException ex, WebRequest request) {
        logger.error("Certificate error: {}", ex.getMessage(), ex);
        
        ErrorResponse error = new ErrorResponse(
            "CERTIFICATE_ERROR",
            ex.getMessage(),
            "Sertifika işleme sırasında bir hata oluştu"
        );
        error.setPath(request.getDescription(false).replace("uri=", ""));
        
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(TimestampException.class)
    public ResponseEntity<ErrorResponse> handleTimestampException(
            TimestampException ex, WebRequest request) {
        logger.error("Timestamp error: {}", ex.getMessage(), ex);
        
        ErrorResponse error = new ErrorResponse(
            "TIMESTAMP_ERROR",
            ex.getMessage(),
            "Zaman damgası işleme sırasında bir hata oluştu"
        );
        error.setPath(request.getDescription(false).replace("uri=", ""));
        
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InvalidDocumentException.class)
    public ResponseEntity<ErrorResponse> handleInvalidDocumentException(
            InvalidDocumentException ex, WebRequest request) {
        logger.error("Invalid document error: {}", ex.getMessage(), ex);
        
        ErrorResponse error = new ErrorResponse(
            "INVALID_DOCUMENT",
            ex.getMessage(),
            "Geçersiz doküman formatı"
        );
        error.setPath(request.getDescription(false).replace("uri=", ""));
        
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorResponse> handleMaxUploadSizeExceededException(
            MaxUploadSizeExceededException ex, WebRequest request) {
        logger.error("File size limit exceeded: {}", ex.getMessage());
        
        ErrorResponse error = new ErrorResponse(
            "FILE_TOO_LARGE",
            "Yüklenen dosya boyutu çok büyük",
            "Maksimum dosya boyutu: 200MB"
        );
        error.setPath(request.getDescription(false).replace("uri=", ""));
        
        return new ResponseEntity<>(error, HttpStatus.PAYLOAD_TOO_LARGE);
    }

    @ExceptionHandler(io.mersel.dss.verify.api.exceptions.TrustConflictException.class)
    public ResponseEntity<ErrorResponse> handleTrustConflict(io.mersel.dss.verify.api.exceptions.TrustConflictException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(new ErrorResponse("TRUST_CHANGED", ex.getMessage(), "Aktif kök kümesini yenileyin"));
    }

    @ExceptionHandler(io.mersel.dss.verify.api.exceptions.PolicyActivationException.class)
    public ResponseEntity<ErrorResponse> handlePolicyActivation(
            io.mersel.dss.verify.api.exceptions.PolicyActivationException ex, WebRequest request) {
        // Mesaj kullanıcı XML'inden parça içerebilir; log'a yalnız hata kodu yazılır.
        logger.warn("Policy activation rejected: {}", ex.getError());
        // 503 POLICY_UNAVAILABLE güncel policyId'yi taşır: istemci onunla bir politika etkinleştirip kurtarabilir.
        ErrorResponse error = ex.getPolicyId() != null
                ? new io.mersel.dss.verify.api.models.PolicyErrorResponse(ex.getError(), ex.getMessage(),
                        ex.getDetails(), ex.getPolicyId(), ex.getActivationEnabled())
                : new ErrorResponse(ex.getError(), ex.getMessage(), ex.getDetails());
        error.setPath(request.getDescription(false).replace("uri=", ""));
        // Açık JSON: GET /api/v1/policy/active/xml "Accept: application/xml" ile çağrılsa da 503 gövdesi aynıdır.
        return ResponseEntity.status(ex.getStatus()).contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .body(error);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(
            IllegalArgumentException ex, WebRequest request) {
        logger.error("Illegal argument: {}", ex.getMessage(), ex);
        
        ErrorResponse error = new ErrorResponse(
            "INVALID_ARGUMENT",
            ex.getMessage(),
            "Geçersiz parametre değeri"
        );
        error.setPath(request.getDescription(false).replace("uri=", ""));
        
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(
            Exception ex, WebRequest request) {
        logger.error("Unexpected error: {}", ex.getMessage(), ex);
        
        ErrorResponse error = new ErrorResponse(
            "INTERNAL_ERROR",
            "Beklenmeyen bir hata oluştu",
            "Hata detayı: " + ex.getMessage()
        );
        error.setPath(request.getDescription(false).replace("uri=", ""));
        
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}

