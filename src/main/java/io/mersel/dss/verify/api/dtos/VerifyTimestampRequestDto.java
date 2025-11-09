package io.mersel.dss.verify.api.dtos;

import org.springframework.web.multipart.MultipartFile;

/**
 * Zaman damgası doğrulama isteği DTO
 */
public class VerifyTimestampRequestDto {
    private MultipartFile timestampToken;
    private MultipartFile originalData; // Timestamp'in uygulandığı orijinal veri
    private boolean validateCertificate = true;

    // Getters and Setters
    public MultipartFile getTimestampToken() {
        return timestampToken;
    }

    public void setTimestampToken(MultipartFile timestampToken) {
        this.timestampToken = timestampToken;
    }

    public MultipartFile getOriginalData() {
        return originalData;
    }

    public void setOriginalData(MultipartFile originalData) {
        this.originalData = originalData;
    }

    public boolean isValidateCertificate() {
        return validateCertificate;
    }

    public void setValidateCertificate(boolean validateCertificate) {
        this.validateCertificate = validateCertificate;
    }
}

