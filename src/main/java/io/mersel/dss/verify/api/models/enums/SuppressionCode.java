package io.mersel.dss.verify.api.models.enums;

/**
 * Mersel DSS Verifier'ın DSS kararını override ettiği tüm durumlar için
 * <strong>kararlı, public API kontratı</strong> olan kod kümesi.
 *
 * <h3>Naming convention</h3>
 * <p><code>MDSS-{LAYER}-{DESCRIPTIVE-SLUG}</code></p>
 * <ul>
 *   <li><code>MDSS</code>   — Mersel DSS prefix'i.</li>
 *   <li><code>{LAYER}</code> — XADES / CADES / PADES / CHAIN / CRYPTO / TIMESTAMP /
 *       REVOCATION. İmza formatı veya kontrol katmanı.</li>
 *   <li><code>{DESCRIPTIVE-SLUG}</code> — kısa ama self-documenting özellik adı,
 *       UPPER-KEBAB-CASE.</li>
 * </ul>
 *
 * <h3>Kararlılık (stability) kuralları</h3>
 * <ol>
 *   <li>Yeni değer <em>eklenebilir</em>.</li>
 *   <li>Mevcut değer <em>renaming</em> edilmez. Davranış değişiyorsa yeni kod
 *       eklenir, eskisi <code>@Deprecated</code> işaretlenir.</li>
 *   <li>Her kod için <code>title</code>, <code>defaultReason</code>,
 *       <code>severity</code> ve <code>docsUrl</code> sabittir; metin
 *       genişleyebilir ama anlam değişmez.</li>
 *   <li><code>docsUrl</code> her zaman çözümlenebilir bir Mersel dokümanına
 *       işaret eder. Şu an docs Mersel'in resmi sitesi yerine GitHub repo'su
 *       altında (<code>docs/suppressions/&lt;CODE&gt;.md</code>) tutuluyor;
 *       URL'ler <code>main</code> branch'inin blob link'leridir.</li>
 * </ol>
 *
 * <h3>Kod ↔ tetikleme noktası eşlemesi</h3>
 * <p>Her enum değerinin nerede tetiklendiği, javadoc içinde
 * <code>@see</code> ile bağlanır — IDE üzerinde tek tıkla "bu kod hangi
 * koşullarda set ediliyor?" sorusuna cevap.</p>
 */
public enum SuppressionCode {

    /**
     * KamuSM / GİB ekosistemindeki bazı imzalama araçları XAdES
     * <code>Reference Type</code> URI'sini standart dışı yazıyor. Bizim
     * verifier kriptografik bütünlük doğrulanmışsa bu yazım hatasına
     * tolerans veriyor.
     *
     * @see io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService#applyTrLegacyXadesToleranceIfApplicable
     */
    MDSS_XADES_LEGACY_TR_TYPE_URI(
            "MDSS-XADES-LEGACY-TR-TYPE-URI",
            "TR-legacy XAdES SignedProperties Type URI toleransı",
            "İmza, KamuSM/GİB ekosistemine özgü XAdES SignedProperties "
                    + "Type URI yazım hatası içeriyor. Kriptografik bütünlük "
                    + "doğrulandı; tolerans uygulandı.",
            "INFO",
            "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md");

    private final String code;
    private final String title;
    private final String defaultReason;
    private final String severity;
    private final String docsUrl;

    SuppressionCode(String code, String title, String defaultReason,
                    String severity, String docsUrl) {
        this.code = code;
        this.title = title;
        this.defaultReason = defaultReason;
        this.severity = severity;
        this.docsUrl = docsUrl;
    }

    /** API'de görünen kararlı string kod (örn. <code>MDSS-XADES-LEGACY-TR-TYPE-URI</code>). */
    public String getCode() {
        return code;
    }

    public String getTitle() {
        return title;
    }

    public String getDefaultReason() {
        return defaultReason;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDocsUrl() {
        return docsUrl;
    }
}
