package io.mersel.dss.verify.api.dtos;

import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import org.springframework.web.multipart.MultipartFile;

/**
 * İmza doğrulama isteği DTO
 */
public class VerifySignatureRequestDto {
    private MultipartFile signedDocument;
    private MultipartFile originalDocument; // Detached imzalar için
    private VerificationLevel level = VerificationLevel.SIMPLE;
    private boolean validateCertificateChain = true;
    private boolean checkRevocation = true;
    private boolean validateTimestamp = true;

    // Getters and Setters
    public MultipartFile getSignedDocument() {
        return signedDocument;
    }

    public void setSignedDocument(MultipartFile signedDocument) {
        this.signedDocument = signedDocument;
    }

    public MultipartFile getOriginalDocument() {
        return originalDocument;
    }

    public void setOriginalDocument(MultipartFile originalDocument) {
        this.originalDocument = originalDocument;
    }

    public VerificationLevel getLevel() {
        return level;
    }

    public void setLevel(VerificationLevel level) {
        this.level = level;
    }

    public boolean isValidateCertificateChain() {
        return validateCertificateChain;
    }

    public void setValidateCertificateChain(boolean validateCertificateChain) {
        this.validateCertificateChain = validateCertificateChain;
    }

    public boolean isCheckRevocation() {
        return checkRevocation;
    }

    public void setCheckRevocation(boolean checkRevocation) {
        this.checkRevocation = checkRevocation;
    }

    public boolean isValidateTimestamp() {
        return validateTimestamp;
    }

    public void setValidateTimestamp(boolean validateTimestamp) {
        this.validateTimestamp = validateTimestamp;
    }
}

