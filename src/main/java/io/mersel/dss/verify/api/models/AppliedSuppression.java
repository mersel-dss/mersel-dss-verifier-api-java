package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

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
}
