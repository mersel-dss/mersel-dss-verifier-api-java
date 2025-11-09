package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Date;
import java.util.List;

/**
 * Zaman damgası bilgisi modeli
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TimestampInfo {
    private boolean valid;
    private Date timestampTime;
    private String timestampType;
    private CertificateInfo tsaCertificate;
    private String digestAlgorithm;
    private String messageImprint;
    private String serialNumber;
    private String tsaName;
    private List<String> validationErrors;

    // Getters and Setters
    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public Date getTimestampTime() {
        return timestampTime;
    }

    public void setTimestampTime(Date timestampTime) {
        this.timestampTime = timestampTime;
    }

    public String getTimestampType() {
        return timestampType;
    }

    public void setTimestampType(String timestampType) {
        this.timestampType = timestampType;
    }

    public CertificateInfo getTsaCertificate() {
        return tsaCertificate;
    }

    public void setTsaCertificate(CertificateInfo tsaCertificate) {
        this.tsaCertificate = tsaCertificate;
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

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getTsaName() {
        return tsaName;
    }

    public void setTsaName(String tsaName) {
        this.tsaName = tsaName;
    }

    public List<String> getValidationErrors() {
        return validationErrors;
    }

    public void setValidationErrors(List<String> validationErrors) {
        this.validationErrors = validationErrors;
    }
}

