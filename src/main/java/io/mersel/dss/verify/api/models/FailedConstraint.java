package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * DSS DetailedReport içindeki <code>&lt;Constraint Status="NOT_OK"&gt;</code>
 * elementinin yapısal (structured) sunumu. ETSI EN 319 102-1 spec dilinde
 * bu objeler "<em>failed constraints</em>" olarak adlandırılır — DSS
 * Basic Building Blocks (BBB) içinde {@link
 * eu.europa.esig.dss.detailedreport.jaxb.XmlStatus#NOT_OK NOT_OK} statüsünde
 * sonuçlanan kontroller.
 *
 * <h2>DSS XML modeline eşleme</h2>
 * <pre>
 *   &lt;XmlBasicBuildingBlocks&gt;
 *     &lt;XCV&gt;
 *       &lt;Constraint Status="NOT_OK"&gt;
 *         &lt;Name Key="BBB_XCV_ISCGKU"&gt;Does the certificate have an expected key-usage?&lt;/Name&gt;
 *         &lt;Error Key="BBB_XCV_ISCGKU_ANS"&gt;{0}, beklenen anahtar kullanım alanına ...&lt;/Error&gt;
 *         &lt;AdditionalInfo&gt;Anahtar kullanımı : [KEY_ENCIPHERMENT, ...]&lt;/AdditionalInfo&gt;
 *       &lt;/Constraint&gt;
 *     &lt;/XCV&gt;
 *   &lt;/XmlBasicBuildingBlocks&gt;
 * </pre>
 * Üretim sırasında:
 * <ul>
 *   <li>{@code key} ← {@code XmlConstraint.name.key} (DSS i18n bundle anahtarı,
 *       locale'den bağımsız stabil makine kontratı).</li>
 *   <li>{@code message} ← {@code XmlConstraint.error.value} (locale'e göre
 *       çevrilmiş insan mesajı; {@code XmlConstraint.additionalInfo} doluysa
 *       " — " ile birleştirilir).</li>
 *   <li>{@code category} ← {@link FailureCategory} (constraint'in pipeline'daki
 *       rolü; aşağıda detaylı).</li>
 * </ul>
 *
 * <h2>Üç-aşamalı kontrat: rootCause vs failedConstraints</h2>
 * <p>DSS validation pipeline'ı sıkı hiyerarşik bir akış izler: bir alt-blok
 * (örn. SubXCV) içinde constraint FAIL olursa, üst-bloktaki summary
 * constraint'leri ({@code BBB_XCV_SUB}, {@code BBB_XCV_ICTIVRSC}) <em>otomatik
 * NOT_OK</em> olur ve bu durum SAV/CV gibi sonraki bloklara da cascade eder.
 * Sonuç: tek bir kök neden (örn. KeyUsage uygunsuz) <em>her zaman</em>
 * birden fazla NOT_OK constraint üretir.</p>
 *
 * <p>API kontratı bu hiyerarşiyi iki farklı görünüm ile yansıtır:</p>
 * <ul>
 *   <li><strong>{@link SignatureInfo#getRootCause() rootCause}</strong> (default,
 *       her zaman dolu): {@code category=ROOT_CAUSE} olan ilk satır. Frontend
 *       dispatch ve operatör eylem mesajı için kullanılır. Tek nesne =
 *       operatör tek somut sorun görür.</li>
 *   <li><strong>{@link SignatureInfo#getFailedConstraints() failedConstraints}</strong>
 *       (opt-in, {@code ?includeFailedConstraints=true}): Tüm BBB FAIL
 *       constraint'leri — {@code ROOT_CAUSE}, {@code DERIVED}, {@code CASCADE}
 *       kategorileriyle birlikte. Audit, forensic ve "neden bu satır
 *       seçildi?" sorusunun cevabı için.</li>
 * </ul>
 *
 * <h2>İlgili akış</h2>
 * <p>Üretim yolu:
 * {@code AdvancedSignatureVerificationService#collectFailingBbbConstraintDetails(...)}
 * — DSS DetailedReport'undaki tüm BBB bloklarını (FC, ISC, VCI, CV, SAV,
 * XCV + her SubXCV katmanı, PSV) gezer; {@code XmlStatus.NOT_OK} olan
 * constraint'leri {@link FailureCategory} ile etiketler; aynı (key,message)
 * çiftini tekrar etmez (ilk görüldüğü yer korunur, sıra deterministik).</p>
 *
 * <h2>Örnek JSON</h2>
 * <pre>
 * "rootCause": {
 *   "key": "BBB_XCV_ISCGKU",
 *   "message": "İmzacı sertifikası, beklenen anahtar kullanım alanına ..."
 * },
 * "failedConstraints": [
 *   {
 *     "key": "BBB_XCV_ISCGKU",
 *     "message": "İmzacı sertifikası, beklenen anahtar kullanım alanına ...",
 *     "category": "ROOT_CAUSE"
 *   },
 *   {
 *     "key": "BBB_XCV_SUB",
 *     "message": "Is the SubXCV conclusion valid?",
 *     "category": "DERIVED"
 *   },
 *   {
 *     "key": "BBB_SAV_ISQPMDOSPP",
 *     "message": "Is the signed qualifying property: 'message-digest' ...",
 *     "category": "CASCADE"
 *   }
 * ]
 * </pre>
 *
 * <p>{@code message} alanındaki <code>http://uri.etsi.org/...</code> gibi
 * statik kodlar DSS i18n tarafından çevrilmez; orijinal değer korunur —
 * frontend bu değerleri kendi lookup table'ı ile zenginleştirebilir.</p>
 *
 * @see SignatureInfo#getRootCause()
 * @see SignatureInfo#getFailedConstraints()
 * @see TimestampInfo#getRootCause()
 * @see TimestampInfo#getFailedConstraints()
 * @see FailureCategory
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class FailedConstraint {

    /**
     * DSS i18n bundle anahtarı (örn. {@code BBB_XCV_ISCGKU}). Locale'den
     * bağımsız; makine kontratının stabil tarafı. DSS DetailedReport'taki
     * {@code XmlConstraint.name.key} alanından gelir.
     */
    private String key;

    /**
     * Configured locale'de (default <code>tr</code>) doldurulmuş insan
     * mesajı. {@code additionalInfo} varsa " — " ile eklenir. DSS
     * DetailedReport'taki {@code XmlConstraint.error.value} alanından gelir
     * (yoksa {@code name.value}'ya fallback eder).
     */
    private String message;

    /**
     * Constraint'in DSS validation pipeline'ındaki rolü:
     * {@link FailureCategory#ROOT_CAUSE}, {@link FailureCategory#DERIVED},
     * veya {@link FailureCategory#CASCADE}.
     *
     * <p>{@link SignatureInfo#getRootCause() rootCause} alanında dönen
     * tek nesne için her zaman {@code ROOT_CAUSE} (alan null olabilir —
     * Jackson NON_NULL ile JSON'da görünmez). {@code failedConstraints}
     * listesinde her satırın gerçek kategorisi taşınır.</p>
     */
    private FailureCategory category;

    public FailedConstraint() {
        // Jackson deserialization desteği için no-arg constructor.
    }

    /**
     * İki-argümanlı constructor — {@code category} alanı null kalır.
     * {@link SignatureInfo#getRootCause() rootCause} alanı için kullanılır
     * (zaten her zaman ROOT_CAUSE olduğu için kategoriyi taşımaya gerek yok;
     * NON_NULL ile JSON'da görünmez).
     */
    public FailedConstraint(String key, String message) {
        this.key = key;
        this.message = message;
    }

    /**
     * Üç-argümanlı constructor — {@code failedConstraints} listesindeki
     * satırlar için kullanılır; her satır kendi kategorisini taşır.
     */
    public FailedConstraint(String key, String message, FailureCategory category) {
        this.key = key;
        this.message = message;
        this.category = category;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public FailureCategory getCategory() {
        return category;
    }

    public void setCategory(FailureCategory category) {
        this.category = category;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FailedConstraint)) {
            return false;
        }
        FailedConstraint other = (FailedConstraint) o;
        return java.util.Objects.equals(key, other.key)
                && java.util.Objects.equals(message, other.message)
                && category == other.category;
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(key, message, category);
    }

    @Override
    public String toString() {
        return "FailedConstraint{key='" + key + "', message='" + message
                + "', category=" + category + "}";
    }
}
