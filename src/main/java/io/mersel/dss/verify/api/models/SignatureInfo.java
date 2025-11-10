package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Date;
import java.util.List;

/**
 * İmza bilgisi modeli
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SignatureInfo {
    private String signatureId;
    private boolean valid;
    private String signatureFormat;
    private String signatureLevel;
    private Date signingTime;
    private Date claimedSigningTime;
    private CertificateInfo signerCertificate;
    private List<CertificateInfo> certificateChain;
    private TimestampInfo timestampInfo;
    private String signatureAlgorithm;
    private String digestAlgorithm;
    private List<String> validationErrors;
    private List<String> validationWarnings;
    private String indication; // TOTAL_PASSED, PASSED, FAILED, etc.
    private String subIndication; // Sub-indication if any
    private QualificationDetails qualificationDetails; // Yasal seviye bilgileri
    private Integer timestampCount; // Timestamp sayısı
    private String policyIdentifier; // Policy ID (XAdES-EPES için)
    private ValidationDetails validationDetails; // Detaylı validation bilgileri

    // Getters and Setters
    public String getSignatureId() {
        return signatureId;
    }

    public void setSignatureId(String signatureId) {
        this.signatureId = signatureId;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getSignatureFormat() {
        return signatureFormat;
    }

    public void setSignatureFormat(String signatureFormat) {
        this.signatureFormat = signatureFormat;
    }

    public String getSignatureLevel() {
        return signatureLevel;
    }

    public void setSignatureLevel(String signatureLevel) {
        this.signatureLevel = signatureLevel;
    }

    public Date getSigningTime() {
        return signingTime;
    }

    public void setSigningTime(Date signingTime) {
        this.signingTime = signingTime;
    }

    public Date getClaimedSigningTime() {
        return claimedSigningTime;
    }

    public void setClaimedSigningTime(Date claimedSigningTime) {
        this.claimedSigningTime = claimedSigningTime;
    }

    public CertificateInfo getSignerCertificate() {
        return signerCertificate;
    }

    public void setSignerCertificate(CertificateInfo signerCertificate) {
        this.signerCertificate = signerCertificate;
    }

    public List<CertificateInfo> getCertificateChain() {
        return certificateChain;
    }

    public void setCertificateChain(List<CertificateInfo> certificateChain) {
        this.certificateChain = certificateChain;
    }

    public TimestampInfo getTimestampInfo() {
        return timestampInfo;
    }

    public void setTimestampInfo(TimestampInfo timestampInfo) {
        this.timestampInfo = timestampInfo;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public List<String> getValidationErrors() {
        return validationErrors;
    }

    public void setValidationErrors(List<String> validationErrors) {
        this.validationErrors = validationErrors;
    }

    public List<String> getValidationWarnings() {
        return validationWarnings;
    }

    public void setValidationWarnings(List<String> validationWarnings) {
        this.validationWarnings = validationWarnings;
    }

    public String getIndication() {
        return indication;
    }

    public void setIndication(String indication) {
        this.indication = indication;
    }

    public String getSubIndication() {
        return subIndication;
    }

    public void setSubIndication(String subIndication) {
        this.subIndication = subIndication;
    }

    public QualificationDetails getQualificationDetails() {
        return qualificationDetails;
    }

    public void setQualificationDetails(QualificationDetails qualificationDetails) {
        this.qualificationDetails = qualificationDetails;
    }

    public Integer getTimestampCount() {
        return timestampCount;
    }

    public void setTimestampCount(Integer timestampCount) {
        this.timestampCount = timestampCount;
    }

    public String getPolicyIdentifier() {
        return policyIdentifier;
    }

    public void setPolicyIdentifier(String policyIdentifier) {
        this.policyIdentifier = policyIdentifier;
    }

    public ValidationDetails getValidationDetails() {
        return validationDetails;
    }

    public void setValidationDetails(ValidationDetails validationDetails) {
        this.validationDetails = validationDetails;
    }
}

