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

    /**
     * Bu imzanın DSS validation pipeline'ında <em>tek bir kök neden</em>
     * (root cause) constraint'i — ETSI EN 319 102-1 spec dilinde
     * <em>failed constraint</em>. {@link FailedConstraint#getKey() key}
     * DSS sabit kodu (locale'den bağımsız);
     * {@link FailedConstraint#getMessage() message} configured locale'de
     * (default Türkçe) insan mesajı.
     *
     * <h3>Niçin tek nesne (liste değil)?</h3>
     * <p>DSS validation pipeline'ı sıkı hiyerarşik akış izler — tek bir
     * kök neden (örn. KeyUsage uygunsuz) <em>her zaman</em> birden fazla
     * NOT_OK constraint üretir (XCV-top summary roll-up + SAV/CV cascade).
     * Frontend bu satırları liste olarak alıp eşit ağırlıkta gösterirse
     * operatör "üç ayrı sorun var" sanır; oysa yalnız bir tane gerçek
     * kök neden vardır. Bu alan yalnız <em>tek</em> kök nedeni taşır;
     * pipeline-side-effect satırları (roll-up + cascade) sessizce filtrelenir.</p>
     *
     * <p><b>Birden fazla gerçek kök neden varsa</b> (örn. iki ayrı
     * sertifika için iki ayrı KeyUsage failure — counter signer + signer):
     * DSS DetailedReport gezme sırasına göre <em>ilk</em> root cause
     * seçilir (deterministik: FC → ISC → VCI → CV → SAV → XCV-top →
     * SubXCV[0] → SubXCV[1] → ... → PSV). Operatör tüm root cause'ları
     * ve roll-up/cascade satırlarını görmek istiyorsa
     * {@code ?includeFailedConstraints=true} parametresi ile
     * {@link #getFailedConstraints() failedConstraints} alanını
     * isteyebilir (her satır kendi {@link FailureCategory category}
     * bilgisini taşır).</p>
     *
     * <p><b>Defansif fallback</b>: Filter sonrası kök neden tespit
     * edilemezse (DSS yeni sürümünde whitelist eksik), ham FAIL listesinden
     * ilk satır seçilir; operatör hiçbir zaman bilgisiz kalmaz.</p>
     *
     * <p><b>{@link #validationErrors} ile farkı</b>: {@code validationErrors}
     * üst-seviye DSS verdict özetini ({@code "İmza geçersiz: INDETERMINATE
     * (CHAIN_CONSTRAINTS_FAILURE)"}) ve geriye dönük operatör mesajlarını
     * tutmaya devam eder. {@code rootCause} ise gerçek kök nedenin yapısal
     * (key + message) sunumudur; frontend bu kodu doğrudan dispatch
     * ederek özel yönlendirme/UI yapabilir (regex ile parse etmek gerekmez).</p>
     *
     * <p>Tolerans uygulanmış imzalar için <code>null</code> döner —
     * {@code MDSS-XADES-LEGACY-TR-TYPE-URI} gibi suppression akışları
     * verdict'i VALID'e çevirdiğinde BBB FAIL'leri zaten konu dışıdır.
     * {@code @JsonInclude(NON_NULL)} ile JSON çıktısında alan görünmez.</p>
     *
     * @see FailedConstraint
     * @see #getFailedConstraints()
     */
    private FailedConstraint rootCause;

    /**
     * Bu imzanın DSS validation pipeline'ındaki <em>tüm</em> BBB FAIL
     * constraint'leri, {@link FailureCategory kategorize edilmiş} halde —
     * opt-in alan. Yalnız {@code ?includeFailedConstraints=true} query
     * parameter'i ile istendiğinde doldurulur; default <code>null</code>
     * kalır ({@code @JsonInclude(NON_NULL)} ile JSON'a yazılmaz, response
     * şişmez).
     *
     * <h3>Niçin opt-in?</h3>
     * <p>{@link #rootCause} default davranışta operatöre yeterlidir —
     * tek aksiyon alabileceği somut neden. Liste sadece audit/forensic,
     * "neden bu satır seçildi?" sorusu, veya frontend'de gelişmiş bir
     * detay paneli için anlamlı; her zaman dönmek istemci kontratını
     * gereksiz şişirir.</p>
     *
     * <h3>İçerik</h3>
     * <p>Tüm BBB FAIL constraint'leri:</p>
     * <ul>
     *   <li>{@link FailureCategory#ROOT_CAUSE} — pipeline'ın gerçek
     *       başarısızlık sebepleri (SubXCV içindeki spesifik check'ler,
     *       FC/ISC/VCI/PSV bağımsız failure'lar, XCV-top'un whitelist
     *       dışı key'leri).</li>
     *   <li>{@link FailureCategory#DERIVED} — XCV-top summary roll-up
     *       satırları ({@code BBB_XCV_SUB}, {@code BBB_XCV_ICTIVRSC}).</li>
     *   <li>{@link FailureCategory#CASCADE} — SAV/CV bloklarındaki
     *       downstream yan ürün satırları (XCV INDETERMINATE/FAILED
     *       olduğunda).</li>
     * </ul>
     *
     * <p>Sıra deterministik: BBB gezme sırası (FC → ISC → VCI → CV →
     * SAV → XCV-top → SubXCV[0..n] → PSV). Aynı {@code (key, message)}
     * çifti tekrar etmez.</p>
     *
     * <p>{@link #rootCause} alanı bu listenin {@code ROOT_CAUSE}
     * kategorisindeki ilk satırıdır — frontend tek aksiyon mesajı için
     * doğrudan {@code rootCause}'u kullanır; tüm detay için listeyi
     * gezer.</p>
     *
     * @see FailureCategory
     * @see FailedConstraint
     */
    private List<FailedConstraint> failedConstraints;

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

    /**
     * Mersel DSS Verifier'ın bu imzayı reddederken <em>DSS'in soyut
     * <code>SubIndication</code>'ına ek olarak</em> Türkiye ekosistemine
     * özgü tanı kodlarıyla zenginleştirdiği gerekçeler. Boş veya null ise:
     * DSS'in jenerik subIndication'ı tek başına yeterli kabul edildi, ek
     * Türkiye-spesifik bir patoloji tespit edilmedi.
     *
     * <p>{@link #appliedSuppressions} ile karşılaştırması: orada DSS
     * kararını override ederiz (INVALID → VALID); burada DSS kararını
     * destekleriz (INVALID → INVALID) ama "neden" sorusuna kataloglu kod
     * + kanıt + dokümantasyon ile cevap veririz.</p>
     *
     * <p>İmzanın <code>valid</code> alanı bu liste dolu olsa bile
     * <code>false</code> kalır — rejection'lar verdict'i değiştirmez,
     * tanılayıcı zenginleştirir.</p>
     *
     * @see AppliedRejection
     * @see io.mersel.dss.verify.api.models.enums.RejectionCode
     */
    private List<AppliedRejection> appliedRejections;

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

    public List<AppliedRejection> getAppliedRejections() {
        return appliedRejections;
    }

    public void setAppliedRejections(List<AppliedRejection> appliedRejections) {
        this.appliedRejections = appliedRejections;
    }
}

