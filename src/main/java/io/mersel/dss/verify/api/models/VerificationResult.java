package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mersel.dss.verify.api.models.enums.SignatureType;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * İmza doğrulama sonucu modeli
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationResult {
    private boolean valid;
    private String status;
    private SignatureType signatureType;
    private Date verificationTime;
    private Integer signatureCount;
    private List<SignatureInfo> signatures = new ArrayList<>();
    private List<String> errors = new ArrayList<>();
    private List<String> warnings = new ArrayList<>();
    private ValidationDetails validationDetails;

    public VerificationResult() {
        this.verificationTime = new Date();
    }

    public VerificationResult(boolean valid, String status) {
        this();
        this.valid = valid;
        this.status = status;
    }

    // Getters and Setters
    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public SignatureType getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(SignatureType signatureType) {
        this.signatureType = signatureType;
    }

    public Date getVerificationTime() {
        return verificationTime;
    }

    public void setVerificationTime(Date verificationTime) {
        this.verificationTime = verificationTime;
    }

    public List<SignatureInfo> getSignatures() {
        return signatures;
    }

    public void setSignatures(List<SignatureInfo> signatures) {
        this.signatures = signatures;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public void addError(String error) {
        this.errors.add(error);
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }

    public void addWarning(String warning) {
        this.warnings.add(warning);
    }

    public ValidationDetails getValidationDetails() {
        return validationDetails;
    }

    public void setValidationDetails(ValidationDetails validationDetails) {
        this.validationDetails = validationDetails;
    }

    public Integer getSignatureCount() {
        return signatureCount;
    }

    public void setSignatureCount(Integer signatureCount) {
        this.signatureCount = signatureCount;
    }
}

