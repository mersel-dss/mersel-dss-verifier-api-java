package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Date;
import java.util.List;

/**
 * Sertifika bilgisi modeli
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CertificateInfo {
    /** Certificate material is exported by the backend from the certificate used by DSS. Base64 encodes X.509 DER; fingerprints are uppercase hexadecimal. */
    private String certificateId;
    private String issuerCertificateId;
    private String certificateBase64;
    private String sha256Fingerprint;
    private String sha1Fingerprint;
    private List<String> certificatePolicyOids;
    private List<String> keyUsages;
    private List<String> extendedKeyUsages;
    private List<String> criticalExtensionOids;
    private List<String> nonCriticalExtensionOids;
    private List<String> subjectAlternativeNames;
    private Boolean certificateAuthority;
    private Integer basicConstraints;

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
    private boolean valid;
    private boolean revoked;
    private String revocationReason;
    private Date revocationTime;
    private Date revocationDate;
    /**
     * OCSP/CRL kaynaklı zengin iptal detayı. Online doğrulama kapalıysa veya
     * sertifika için DSS revocation data üretemediyse {@code null} kalır ve
     * {@code @JsonInclude(NON_NULL)} sayesinde response'a düşmez.
     */
    private RevocationInfo revocation;

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

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public Date getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    public RevocationInfo getRevocation() {
        return revocation;
    }

    public void setRevocation(RevocationInfo revocation) {
        this.revocation = revocation;
    }

    public String getCertificateId() { return certificateId; }
    public void setCertificateId(String certificateId) { this.certificateId = certificateId; }

    public String getIssuerCertificateId() { return issuerCertificateId; }
    public void setIssuerCertificateId(String issuerCertificateId) { this.issuerCertificateId = issuerCertificateId; }

    public String getCertificateBase64() { return certificateBase64; }
    public void setCertificateBase64(String certificateBase64) { this.certificateBase64 = certificateBase64; }

    public String getSha256Fingerprint() { return sha256Fingerprint; }
    public void setSha256Fingerprint(String sha256Fingerprint) { this.sha256Fingerprint = sha256Fingerprint; }

    public String getSha1Fingerprint() { return sha1Fingerprint; }
    public void setSha1Fingerprint(String sha1Fingerprint) { this.sha1Fingerprint = sha1Fingerprint; }

    public List<String> getCertificatePolicyOids() { return certificatePolicyOids; }
    public void setCertificatePolicyOids(List<String> certificatePolicyOids) { this.certificatePolicyOids = certificatePolicyOids; }

    public List<String> getKeyUsages() { return keyUsages; }
    public void setKeyUsages(List<String> keyUsages) { this.keyUsages = keyUsages; }

    public List<String> getExtendedKeyUsages() { return extendedKeyUsages; }
    public void setExtendedKeyUsages(List<String> extendedKeyUsages) { this.extendedKeyUsages = extendedKeyUsages; }

    public List<String> getCriticalExtensionOids() { return criticalExtensionOids; }
    public void setCriticalExtensionOids(List<String> criticalExtensionOids) { this.criticalExtensionOids = criticalExtensionOids; }

    public List<String> getNonCriticalExtensionOids() { return nonCriticalExtensionOids; }
    public void setNonCriticalExtensionOids(List<String> nonCriticalExtensionOids) { this.nonCriticalExtensionOids = nonCriticalExtensionOids; }

    public List<String> getSubjectAlternativeNames() { return subjectAlternativeNames; }
    public void setSubjectAlternativeNames(List<String> subjectAlternativeNames) { this.subjectAlternativeNames = subjectAlternativeNames; }

    public Boolean getCertificateAuthority() { return certificateAuthority; }
    public void setCertificateAuthority(Boolean certificateAuthority) { this.certificateAuthority = certificateAuthority; }

    public Integer getBasicConstraints() { return basicConstraints; }
    public void setBasicConstraints(Integer basicConstraints) { this.basicConstraints = basicConstraints; }
}
