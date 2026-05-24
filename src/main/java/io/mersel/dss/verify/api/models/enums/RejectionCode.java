package io.mersel.dss.verify.api.models.enums;

/**
 * Mersel DSS Verifier'ın bir imzayı reddederken DSS'in soyut
 * <code>SubIndication</code>'ından öte <strong>Mersel'e özgü, kararlı,
 * makine-okunaklı bir gerekçe kodu</strong> raporladığı durumlar için
 * kod kümesi.
 *
 * <h3>{@link SuppressionCode} ile farkı</h3>
 * <ul>
 *   <li><b>SuppressionCode</b> — DSS verdict'ini <em>override</em>
 *       ediyoruz: DSS INVALID dedi, biz VALID diyoruz. Gerekçe + kanıt
 *       audit için raporlanır.</li>
 *   <li><b>RejectionCode</b> — DSS verdict'ini <em>destekliyoruz</em>:
 *       DSS INVALID dedi, biz de INVALID diyoruz, AMA neden invalid
 *       olduğunu Türkiye ekosistemine spesifik bir tanı koduyla
 *       açıklıyoruz. Operatör DSS'in jenerik
 *       <code>SIG_CONSTRAINTS_FAILURE</code>'ından öte, hangi
 *       Türkiye-pratiği patolojinin tetiklediğini görür.</li>
 * </ul>
 *
 * <h3>Naming convention</h3>
 * <p><code>MDSS-{LAYER}-{DESCRIPTIVE-SLUG}</code> — aynı şema
 * {@link SuppressionCode} ile paylaşılır. Aynı kod hem suppression hem
 * rejection olarak görünmez; eklerken çakışma kontrol edilmelidir.</p>
 *
 * <h3>Kararlılık (stability) kuralları</h3>
 * <ol>
 *   <li>Yeni değer <em>eklenebilir</em>.</li>
 *   <li>Mevcut değer renaming edilmez; davranış değişiyorsa yeni kod
 *       eklenir, eskisi <code>@Deprecated</code> işaretlenir.</li>
 *   <li>Her kod için <code>title</code>, <code>defaultReason</code>,
 *       <code>severity</code> ve <code>docsUrl</code> sabittir.</li>
 * </ol>
 */
public enum RejectionCode {

    /**
     * XAdES imza yalnızca <strong>bir</strong> <code>&lt;ds:Reference&gt;</code>
     * taşıyor; <code>&lt;xades:SignedProperties&gt;</code> elementi XML
     * içinde mevcut fakat hiçbir Reference ona pointing değil. ETSI EN
     * 319 132-1 (XAdES-BES) iki referans (biri belge body'si, biri
     * SignedProperties) zorunluluğuna aykırı.
     *
     * <h4>Güvenlik etkisi ve yapısal sorun</h4>
     * <ul>
     *   <li>İkinci referans olmadığı için <code>SigningTime</code>,
     *       <code>SigningCertificate</code>, <code>SignaturePolicyIdentifier</code>,
     *       <code>SignerRole</code>, <code>CommitmentTypeIndication</code>
     *       gibi imzanın anlamını taşıyan alanlar <em>imza kapsamı
     *       dışında</em>dır — post-signing modifiye edilebilir ve imza
     *       yine matematik olarak doğrulanır. Doğrulayıcı bu tahrifatı
     *       yakalayamaz.</li>
     *   <li>Bu yapı eIDAS ve 5070 sayılı kanunun atıfta bulunduğu ETSI
     *       standartları açısından geçerli bir advanced electronic
     *       signature değildir.</li>
     *   <li>Çözüm doğrulayıcı tarafında değil, imzayı üreten yazılım
     *       tarafındadır: iki referans (biri body, biri SignedProperties)
     *       üretilmelidir.</li>
     * </ul>
     *
     * @see io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService#evaluateTrLegacyXadesRejection
     */
    MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE(
            "MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
            "XAdES SignedProperties referansı eksik (tek referanslı imza)",
            "XAdES imza yalnızca bir ds:Reference taşıyor; SignedProperties "
                    + "imza kapsamına alınmamış. SigningTime ve SigningCertificate "
                    + "gibi alanlar kriptografik olarak korunmadığı için "
                    + "post-signing tahrifata açık. ETSI EN 319 132-1 (XAdES-BES) "
                    + "iki referans zorunluluğuna aykırı; imza reddedildi.",
            "ERROR",
            "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md");

    private final String code;
    private final String title;
    private final String defaultReason;
    private final String severity;
    private final String docsUrl;

    RejectionCode(String code, String title, String defaultReason,
                  String severity, String docsUrl) {
        this.code = code;
        this.title = title;
        this.defaultReason = defaultReason;
        this.severity = severity;
        this.docsUrl = docsUrl;
    }

    /** API'de görünen kararlı string kod (örn. <code>MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE</code>). */
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
