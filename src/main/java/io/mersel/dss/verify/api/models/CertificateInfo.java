package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Date;

/**
 * Sertifika bilgisi modeli
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertificateInfo {
    private String subject;
    private String commonName;
    private String issuerDN;
    private String serialNumber;
    private String subjectSerialNumber;
    private Date notBefore;
    private Date notAfter;
    private String keyUsage;
    private String publicKeyAlgorithm;
    private Integer publicKeySize;
    private String signatureAlgorithm;
    private boolean trusted;
    private boolean expired;
    private boolean revoked;
    private String revocationReason;
    private Date revocationTime;

    // Getters and Setters
    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String subjectDN) {
        this.commonName = subjectDN;
    }

    public String getIssuerDN() {
        return issuerDN;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getSubjectSerialNumber() {
        return subjectSerialNumber;
    }

    public void setSubjectSerialNumber(String subjectSerialNumber) {
        this.subjectSerialNumber = subjectSerialNumber;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    public Integer getPublicKeySize() {
        return publicKeySize;
    }

    public void setPublicKeySize(Integer publicKeySize) {
        this.publicKeySize = publicKeySize;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public boolean isTrusted() {
        return trusted;
    }

    public void setTrusted(boolean trusted) {
        this.trusted = trusted;
    }

    public boolean isExpired() {
        return expired;
    }

    public void setExpired(boolean expired) {
        this.expired = expired;
    }

    public boolean isRevoked() {
        return revoked;
    }

    public void setRevoked(boolean revoked) {
        this.revoked = revoked;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public Date getRevocationTime() {
        return revocationTime;
    }

    public void setRevocationTime(Date revocationTime) {
        this.revocationTime = revocationTime;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }
}

