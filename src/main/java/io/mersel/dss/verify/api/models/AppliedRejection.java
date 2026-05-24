package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Mersel DSS Verifier'ın bir imzayı reddederken, DSS'in jenerik
 * <code>SubIndication</code>'ından öte <strong>Türkiye ekosistemine
 * özgü bir tanı kodu</strong> raporladığı kayıt.
 *
 * <p>İlke: DSS "SIG_CONSTRAINTS_FAILURE" diyor; bu, eIDAS terminolojisinde
 * doğru ama bir operatör için belirsiz. Biz örneğin "XAdES imza yalnızca
 * bir ds:Reference taşıyor; SignedProperties imza kapsamına alınmamış"
 * gibi <em>somut, aksiyon alınabilir</em> bir gerekçeyle yanıtı
 * zenginleştiririz. İmzanın <code>valid</code> alanı yine <code>false</code>
 * kalır — yani DSS'in kararını override etmiyoruz, sadece neden
 * reddettiğimizi tanı kodu ile kataloglu olarak söylüyoruz.</p>
 *
 * <p><b>{@link AppliedSuppression} ile farkı</b>:</p>
 * <ul>
 *   <li><b>AppliedSuppression</b> — DSS INVALID dedi, biz VALID dedik
 *       (override). Verdict elevate edildi.</li>
 *   <li><b>AppliedRejection</b> — DSS INVALID dedi, biz de INVALID
 *       diyoruz (destek). Verdict aynı kalıyor; sadece Türkiye-spesifik
 *       gerekçe kodu eklendi.</li>
 * </ul>
 *
 * <p><b>Schema kararlılığı</b>: <code>code</code> alanı kararlı bir API
 * kontratıdır; bir kez yayınlandığında değiştirilmez.
 * {@link io.mersel.dss.verify.api.models.enums.RejectionCode} enum'una
 * yeni değerler eklenebilir, mevcut değerler renaming yapılmaz.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AppliedRejection {

    /**
     * Kararlı, makine-okunaklı kod (örn.
     * <code>MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE</code>). Bu projeden
     * kayıtlı tüm değerler için bkz.
     * {@link io.mersel.dss.verify.api.models.enums.RejectionCode}.
     */
    private String code;

    /** İnsan-okunaklı kısa başlık (operatör dashboard'larında listelenebilir). */
    private String title;

    /**
     * Türkçe, son kullanıcıya / operatöre yönelik açıklayıcı metin.
     * "Niye reddedildi?" sorusunun cevabı.
     */
    private String reason;

    /**
     * Tanının ağırlığı:
     * <ul>
     *   <li><code>ERROR</code> — imza reddedildi, kullanıcı eylemi gerekli
     *       (yeniden imzalama veya kaynaktan düzeltme).</li>
     *   <li><code>FATAL</code> — gelecekte: ekosistem güvenlik açığı
     *       seviyesinde, derhal blokla.</li>
     * </ul>
     */
    private String severity;

    /**
     * DSS'in <em>orijinal</em> indication'ı. Audit için: bizim rejection
     * kodumuzun hangi DSS verdict'i üzerine eklendiğini gösterir.
     */
    private String originalIndication;

    /** DSS'in orijinal subIndication'ı. */
    private String originalSubIndication;

    /**
     * Rejection'ı tetikleyen somut delil. Free-form key/value; her
     * <code>code</code>'a göre içeriği değişir. Örnek (missing SP
     * reference için):
     * <pre>
     *   {
     *     "signedPropertiesId": "SignedProperties_Signature_2B1660F5-...",
     *     "dssBbbConstraint": "BBB_SAV_ISQPMDOSPP",
     *     "missingProtection": "SigningTime, SigningCertificateV2"
     *   }
     * </pre>
     */
    private Map<String, Object> evidence;

    /**
     * Bu code için Mersel docs URL'i. Operatör tek tıkla rejection
     * gerekçesini, yapısal patolojiyi ve giderme yönergesini görür.
     */
    private String docsUrl;

    public AppliedRejection() {}

    public AppliedRejection(String code, String title, String reason,
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
