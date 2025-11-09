package io.mersel.dss.verify.api.dtos;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mersel.dss.verify.api.models.CertificateInfo;

import java.util.Date;
import java.util.List;

/**
 * Zaman damgası doğrulama yanıt DTO
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TimestampVerificationResponseDto {
    private boolean valid;
    private String status;
    private Date timestampTime;
    private String tsaName;
    private String digestAlgorithm;
    private String messageImprint;
    private CertificateInfo tsaCertificate;
    private List<String> errors;
    private List<String> warnings;
    private Date verificationTime;

    public TimestampVerificationResponseDto() {
        this.verificationTime = new Date();
    }

    public TimestampVerificationResponseDto(boolean valid, String status) {
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

    public Date getTimestampTime() {
        return timestampTime;
    }

    public void setTimestampTime(Date timestampTime) {
        this.timestampTime = timestampTime;
    }

    public String getTsaName() {
        return tsaName;
    }

    public void setTsaName(String tsaName) {
        this.tsaName = tsaName;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getMessageImprint() {
        return messageImprint;
    }

    public void setMessageImprint(String messageImprint) {
        this.messageImprint = messageImprint;
    }

    public CertificateInfo getTsaCertificate() {
        return tsaCertificate;
    }

    public void setTsaCertificate(CertificateInfo tsaCertificate) {
        this.tsaCertificate = tsaCertificate;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public void setWarnings(List<String> warnings) {
        this.warnings = warnings;
    }

    public Date getVerificationTime() {
        return verificationTime;
    }

    public void setVerificationTime(Date verificationTime) {
        this.verificationTime = verificationTime;
    }
}

