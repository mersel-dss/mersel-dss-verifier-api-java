package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Mersel DSS Verifier'ın bir imza üzerinde DSS'in kararını bilinçli olarak
 * <strong>override ettiği</strong> her durum için yapılandırılmış bir kayıt.
 *
 * <p>İlke: bizim verifier "DSS dedi ki invalid, biz diyoruz ki valid" tarzı
 * her kararı <em>açık ve makine-okunaklı</em> şekilde raporlar. Audit,
 * compliance ve operasyonel görünürlük için kritik:</p>
 * <ul>
 *   <li><b>Audit</b>: regülatör veya kurumsal müşteri "bu imza neden VALID
 *       gösterildi?" diye sorduğunda response içinde kanıt + sebep var.</li>
 *   <li><b>Observability</b>: <code>code</code> alanı Prometheus metric
 *       label'ı ya da log filter olarak kullanılabilir
 *       (<code>mersel_dss_suppression_applied_total{code="…"}</code>).</li>
 *   <li><b>Support</b>: kullanıcı support ticket'ında <code>code</code>
 *       referans verir, dökümentasyon URL'si tek tıkla erişilebilir.</li>
 * </ul>
 *
 * <p><b>Hangi durumlar burada raporlanır?</b> Yalnızca DSS kararının
 * <em>geçersiz → geçerli</em> yönüne çevrildiği veya ek validasyon
 * uyguladığımız durumlar. Sıradan validation warning'leri (DSS'in zaten
 * uyardığı şeyler) buraya YAZILMAZ — onlar
 * {@link SignatureInfo#getValidationWarnings()} altında kalır.</p>
 *
 * <p><b>Schema kararlılığı</b>: <code>code</code> alanı kararlı bir API
 * kontratıdır; bir kez yayınlandığında değiştirilmez.
 * {@link io.mersel.dss.verify.api.models.enums.SuppressionCode} enum'una
 * yeni değerler eklenebilir, mevcut değerler renaming yapılmaz.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AppliedSuppression {

    /**
     * Kararlı, makine-okunaklı kod (örn. <code>MDSS-XADES-LEGACY-TR-TYPE-URI</code>).
     * Bu projeden kayıtlı tüm değerler için bkz.
     * {@link io.mersel.dss.verify.api.models.enums.SuppressionCode}.
     */
    private String code;

    /** İnsan-okunaklı kısa başlık (operatör dashboard'larında listelenebilir). */
    private String title;

    /**
     * Türkçe, son kullanıcıya / operatöre yönelik açıklayıcı metin.
     * "Niye geçti?" sorusunun cevabı.
     */
    private String reason;

    /**
     * Override'ın güvenlik etkisi:
     * <ul>
     *   <li><code>INFO</code> — tasarımdan sapma ama güvenlik etkisi yok
     *       (örn. üretici Type URI yazım hatası, kriptografi sağlam).</li>
     *   <li><code>WARN</code> — operatörün dikkat etmesi önerilir.</li>
     *   <li><code>CRITICAL</code> — operatör eylem almalı (gelecekte).</li>
     * </ul>
     */
    private String severity;

    /**
     * DSS'in <em>orijinal</em> indication'ı (override öncesi). Audit için
     * kritik: "DSS aslında ne demişti, biz ne yaptık" sorusuna kesin cevap.
     */
    private String originalIndication;

    /** DSS'in orijinal subIndication'ı (override öncesi). */
    private String originalSubIndication;

    /**
     * Override'ı tetikleyen somut delil. Free-form key/value; her
     * <code>code</code>'a göre içeriği değişir. Örnek:
     * <pre>
     *   { "detectedTypeUri": "http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties" }
     * </pre>
     *
     * <p>İstemcinin bu içeriği parse'lerken <code>code</code>'a göre branch
     * etmesi beklenir; aynı koda ait field'lar zamanla genişleyebilir,
     * ama mevcut field'lar removed/renamed yapılmaz.</p>
     */
    private Map<String, Object> evidence;

    /**
     * Bu code için Mersel docs URL'i. Operatör tek tıkla detaylı sebebi
     * + tolerans kuralını + kapatma yönergesini görür.
     */
    private String docsUrl;

    // -------------------------------------------------------------------------
    // Audit metadata (gate v2.0+). Forensic-grade kayıt için her override
    // kararına eklenir. Önceki sürümlere zarar vermeyen ek alanlar — eski
    // 8-args constructor da korunur, yeni alanlar yalnız audit-builder
    // pattern'le doldurulur.
    // -------------------------------------------------------------------------

    /**
     * Tolerance gate'inin <em>sürüm</em> kodu. Pipeline mantığı değiştikçe
     * artar (örn. {@code "v2.0"}); audit reviewer'ı geriye dönük olarak
     * "bu kayıt hangi gate sıkılığıyla üretildi?" sorusuna cevap verebilir.
     *
     * <p>Şu an kullanılan değer:
     * {@code AdvancedSignatureVerificationService#TOLERANCE_GATE_VERSION}.
     * Bir sonraki gate sürümünde bu sabit artırılırsa, eski kayıtlardaki
     * versiyon string'i dokunulmaz kalır — tarihsel forensic için.</p>
     */
    private String gateVersion;

    /**
     * Tolerance gate'inin pozitif tarafta beklediği <strong>tek izinli FAIL
     * constraint key</strong> set'i (örn. {@code ["BBB_SAV_ISQPMDOSPP"]}).
     * Bu set <em>dışında</em> herhangi bir BBB bloğunda NOT_OK constraint
     * varsa gate kapanır. Audit için kritik: yarın gate sıkılığı azalırsa
     * (set genişlerse) eski kayıtlarda hangi izin verilenler varmış kanıtı
     * kalır.
     */
    private Set<String> allowedFailureKeys;

    /**
     * Gate inceleme sırasında <strong>fiilen gözlenen</strong> tüm BBB FAIL
     * constraint key'lerinin set'i (FC/ISC/VCI/CV/SAV/XCV-top/SubXCV/PSV
     * bloklarının birleşimi). Tolerance uygulandığı için bu set
     * {@link #allowedFailureKeys}'in alt-kümesidir. Saldırı ya da regresyon
     * tespiti için: operatör bu set'i incelediğinde "DSS hangi constraint'lerle
     * INVALID dedi?"ye birebir cevap alır.
     */
    private Set<String> observedFailureKeys;

    /**
     * Doğrulamaya giren <em>imzalı doküman</em> byte'larının SHA-256 hash'i
     * (hex). Forensic dispute'ta "tam olarak hangi byte dizisi tolere
     * edildi?" sorusunun cevabı; receiver başka kaynaktan aldığı kopyayla
     * hash karşılaştırabilir. ECDSA preprocessor sonrası halini ifade eder
     * (gate tam o byte dizisi üzerinde karar verdiği için).
     */
    private String documentSha256;

    /**
     * Doğrulamaya giren imzalı doküman byte uzunluğu (preprocess sonrası).
     * Pratik dispute ve sızdırma tespitinde hash ile birlikte ikincil
     * sinyal — aynı hash farklı uzunluk teorik olarak imkânsız ama
     * forensic format/encoding ipucu sağlar.
     */
    private Long documentSizeBytes;

    public AppliedSuppression() {}

    public AppliedSuppression(String code, String title, String reason,
                              String severity, String originalIndication,
                              String originalSubIndication,
                              Map<String, Object> evidence, String docsUrl) {
        this.code = code;
        this.title = title;
        this.reason = reason;
        this.severity = severity;
        this.originalIndication = originalIndication;
        this.originalSubIndication = originalSubIndication;
        this.evidence = evidence != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(evidence))
                : null;
        this.docsUrl = docsUrl;
    }

    /**
     * Audit-zengin constructor (gate v2.0+). Eski 8-args constructor'a ek
     * olarak forensic alanları doldurur; yeni alanlardan herhangi biri
     * {@code null} olabilir (örn. test/legacy çağrılarında). JSON
     * serialization {@code @JsonInclude(NON_NULL)} ile null alanları
     * gizler, dolayısıyla wire format'ı koşullu olarak genişler.
     *
     * <p><em>Tarihsel not:</em> Eski sürümlerde bir
     * {@code reValidationVerdict} alanı vardı; v2.2'de re-validation
     * katmanı kaldırıldığı için alan da kaldırıldı. Eski JSON kayıtlarını
     * deserialize ederken Jackson bu alanı sessizce yok sayar.</p>
     */
    public AppliedSuppression(String code, String title, String reason,
                              String severity, String originalIndication,
                              String originalSubIndication,
                              Map<String, Object> evidence, String docsUrl,
                              String gateVersion,
                              Set<String> allowedFailureKeys,
                              Set<String> observedFailureKeys,
                              String documentSha256,
                              Long documentSizeBytes) {
        this(code, title, reason, severity, originalIndication,
                originalSubIndication, evidence, docsUrl);
        this.gateVersion = gateVersion;
        this.allowedFailureKeys = allowedFailureKeys != null
                ? Collections.unmodifiableSet(new LinkedHashSet<>(allowedFailureKeys))
                : null;
        this.observedFailureKeys = observedFailureKeys != null
                ? Collections.unmodifiableSet(new LinkedHashSet<>(observedFailureKeys))
                : null;
        this.documentSha256 = documentSha256;
        this.documentSizeBytes = documentSizeBytes;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getOriginalIndication() {
        return originalIndication;
    }

    public void setOriginalIndication(String originalIndication) {
        this.originalIndication = originalIndication;
    }

    public String getOriginalSubIndication() {
        return originalSubIndication;
    }

    public void setOriginalSubIndication(String originalSubIndication) {
        this.originalSubIndication = originalSubIndication;
    }

    public Map<String, Object> getEvidence() {
        return evidence;
    }

    public void setEvidence(Map<String, Object> evidence) {
        this.evidence = evidence != null
                ? Collections.unmodifiableMap(new LinkedHashMap<>(evidence))
                : null;
    }

    public String getDocsUrl() {
        return docsUrl;
    }

    public void setDocsUrl(String docsUrl) {
        this.docsUrl = docsUrl;
    }

    public String getGateVersion() {
        return gateVersion;
    }

    public void setGateVersion(String gateVersion) {
        this.gateVersion = gateVersion;
    }

    public Set<String> getAllowedFailureKeys() {
        return allowedFailureKeys;
    }

    public void setAllowedFailureKeys(Set<String> allowedFailureKeys) {
        this.allowedFailureKeys = allowedFailureKeys != null
                ? Collections.unmodifiableSet(new LinkedHashSet<>(allowedFailureKeys))
                : null;
    }

    public Set<String> getObservedFailureKeys() {
        return observedFailureKeys;
    }

    public void setObservedFailureKeys(Set<String> observedFailureKeys) {
        this.observedFailureKeys = observedFailureKeys != null
                ? Collections.unmodifiableSet(new LinkedHashSet<>(observedFailureKeys))
                : null;
    }

    public String getDocumentSha256() {
        return documentSha256;
    }

    public void setDocumentSha256(String documentSha256) {
        this.documentSha256 = documentSha256;
    }

    public Long getDocumentSizeBytes() {
        return documentSizeBytes;
    }

    public void setDocumentSizeBytes(Long documentSizeBytes) {
        this.documentSizeBytes = documentSizeBytes;
    }
}
