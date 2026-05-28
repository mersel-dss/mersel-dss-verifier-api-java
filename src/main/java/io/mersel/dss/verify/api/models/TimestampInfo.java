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

    /**
     * Bu zaman damgasının DSS validation pipeline'ında <em>tek bir kök neden</em>
     * (root cause) constraint'i. Bkz. {@link SignatureInfo#getRootCause()}
     * dokümantasyonu — aynı sözleşmeyi taşır: pipeline-side-effect satırları
     * (XCV-top roll-up + SAV/CV cascade) sessizce filtrelenir, yalnız gerçek
     * kök neden döner. Birden fazla kök neden varsa DSS gezme sırasına göre
     * ilki seçilir; defansif fallback ile hiç kök neden tespit edilemezse
     * ham FAIL listesinden ilk satır seçilir. {@code null} → bu zaman
     * damgasında FAIL constraint yok (geçerli).
     *
     * <p>Eksiksiz audit için (tüm root cause'lar + roll-up/cascade satırları)
     * {@link #getFailedConstraints() failedConstraints} alanı opt-in olarak
     * doldurulabilir.</p>
     */
    private FailedConstraint rootCause;

    /**
     * Bu zaman damgasının DSS validation pipeline'ındaki <em>tüm</em> BBB
     * FAIL constraint'leri, {@link FailureCategory kategorize edilmiş} halde —
     * opt-in alan. Yalnız {@code ?includeFailedConstraints=true} query
     * parameter'i ile istendiğinde doldurulur; default <code>null</code>
     * kalır ({@code @JsonInclude(NON_NULL)} ile JSON'a yazılmaz).
     *
     * <p>Bkz. {@link SignatureInfo#getFailedConstraints()} dokümantasyonu —
     * aynı sözleşme: {@link FailureCategory#ROOT_CAUSE} (pipeline'ın
     * gerçek başarısızlık sebepleri), {@link FailureCategory#DERIVED}
     * (XCV-top summary roll-up), {@link FailureCategory#CASCADE}
     * (SAV/CV downstream yan ürün).</p>
     */
    private List<FailedConstraint> failedConstraints;

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

    public FailedConstraint getRootCause() {
        return rootCause;
    }

    public void setRootCause(FailedConstraint rootCause) {
        this.rootCause = rootCause;
    }

    public List<FailedConstraint> getFailedConstraints() {
        return failedConstraints;
    }

    public void setFailedConstraints(List<FailedConstraint> failedConstraints) {
        this.failedConstraints = failedConstraints;
    }
}

