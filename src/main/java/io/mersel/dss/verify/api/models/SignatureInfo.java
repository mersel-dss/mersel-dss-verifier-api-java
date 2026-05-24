package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mersel.dss.verify.api.models.enums.ChainRevocationStatus;
import io.mersel.dss.verify.api.models.enums.SignaturePackaging;

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
    /**
     * XAdES paketleme tipi — W3C XMLDSig terminolojisi
     * ({@link SignaturePackaging#ENVELOPED} / {@link SignaturePackaging#ENVELOPING}
     * / {@link SignaturePackaging#DETACHED}). XAdES dışı (CAdES/PAdES)
     * imzalar için {@code null} — JSON çıktısına da düşmez
     * ({@code NON_NULL}).
     *
     * <p>Hesaplama {@code AdvancedSignatureVerificationService} içinde
     * W3C XMLDSig kurallarına göre {@code ds:SignedInfo/ds:Reference}
     * {@code Type} attribute'u ve {@code Transform} listesi üzerinden
     * tip-bazlı (sıra-bağımsız) yapılır — TÜBİTAK BES'in pozisyonel
     * beklentisine bağımlı değildir.</p>
     *
     * @see <a href="https://www.w3.org/TR/xmldsig-core/#sec-Signature">W3C XMLDSig §4.3</a>
     * @see <a href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/">ETSI EN 319 132-1</a>
     */
    private SignaturePackaging signaturePackaging;
    private Date signingTime;
    private Date claimedSigningTime;
    private CertificateInfo signerCertificate;
    private List<CertificateInfo> certificateChain;
    /**
     * İmzanın sertifika zinciri (leaf + intermediate CA'lar) için
     * revocation durumunun kompakt özeti. SIMPLE mod response'unda da
     * görünür — kullanıcı zincirin tamamına dair detayı görmek için
     * COMPREHENSIVE kullanmak zorunda kalmadan tek bakışta doğru
     * kararı verebilsin.
     *
     * <p>Doğrulama <em>kararını</em> etkilemez; DSS policy zincirin
     * tamamını {@code SigningCertificate} + {@code CACertificate} blokları
     * üzerinden zaten kontrol eder. Bu alan yalnız UI/audit görünürlüğü
     * için.</p>
     *
     * @see ChainRevocationStatus
     */
    private ChainRevocationStatus chainRevocationStatus;
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

    /**
     * Mersel DSS Verifier'ın bu imza için DSS kararını <em>override
     * ettiği</em> tüm durumlar. Boş veya null ise: DSS'in kararı aynen
     * kullanıldı, hiçbir Mersel-spesifik tolerans uygulanmadı.
     *
     * <p>Audit/compliance için kritik alan — operatör veya denetleyici "bu
     * imza neden VALID gösterildi?" diye sorduğunda her override'ın gerekçesi
     * + DSS'in orijinal kararı + somut delil burada raporlanır.</p>
     *
     * @see AppliedSuppression
     * @see io.mersel.dss.verify.api.models.enums.SuppressionCode
     */
    private List<AppliedSuppression> appliedSuppressions;

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

    public SignaturePackaging getSignaturePackaging() {
        return signaturePackaging;
    }

    public void setSignaturePackaging(SignaturePackaging signaturePackaging) {
        this.signaturePackaging = signaturePackaging;
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

    public ChainRevocationStatus getChainRevocationStatus() {
        return chainRevocationStatus;
    }

    public void setChainRevocationStatus(ChainRevocationStatus chainRevocationStatus) {
        this.chainRevocationStatus = chainRevocationStatus;
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

    public List<AppliedSuppression> getAppliedSuppressions() {
        return appliedSuppressions;
    }

    public void setAppliedSuppressions(List<AppliedSuppression> appliedSuppressions) {
        this.appliedSuppressions = appliedSuppressions;
    }
}

