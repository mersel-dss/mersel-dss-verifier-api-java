package io.mersel.dss.verify.api.models;

/**
 * Bir {@link FailedConstraint} satırının DSS validation pipeline'ındaki
 * <em>rolünü</em> sınıflandırır. Frontend/audit kontratı için kritik:
 * DSS pipeline'ı sıkı hiyerarşik akış izler — tek bir kök neden (örn.
 * KeyUsage uygunsuz) her zaman birden fazla NOT_OK constraint üretir
 * (alt-bloktaki failure üst-blokta summary roll-up tetikler, XCV
 * INDETERMINATE durumu da SAV/CV bloklarına cascade eder).
 *
 * <p>Bu kategorilendirme operatörün üç ayrı sorun var sanmasını
 * engeller; frontend dispatch için yalnız {@link #ROOT_CAUSE} satırlarını
 * kullanır, {@link #DERIVED} ve {@link #CASCADE} yalnız "neden bu
 * seçildi?" sorusunu cevaplayan audit kanıtıdır.</p>
 *
 * <p>Default API kontratında her imza için tek bir
 * {@link SignatureInfo#getRootCause() rootCause} alanı döner — kategori
 * her zaman <strong>ROOT_CAUSE</strong>. {@code ?includeFailedConstraints=true}
 * opt-in ile dönen {@link SignatureInfo#getFailedConstraints()
 * failedConstraints} listesinde üç kategori de görünür; operatör
 * frontend'inde isteğe göre filtreler.</p>
 *
 * <h3>Karar tablosu</h3>
 * <pre>
 * Blok          | Kategori     | Koşul
 * --------------+--------------+----------------------------------------------
 * SubXCV[*]     | ROOT_CAUSE   | Her zaman (sertifika düzleminde gerçek check)
 * FC/ISC/VCI/   | ROOT_CAUSE   | Her zaman (bağımsız blok failure'ları)
 *   PSV         |              |
 * XCV-top       | DERIVED      | Key ∈ {BBB_XCV_SUB, BBB_XCV_ICTIVRSC}
 *               |              | + en az bir SubXCV NOT_OK ise
 * XCV-top       | ROOT_CAUSE   | Aksi halde (whitelist dışı key)
 * SAV/CV        | CASCADE      | XCV.Conclusion.Indication ∈
 *               |              | {INDETERMINATE, FAILED, TOTAL_FAILED}
 * SAV/CV        | ROOT_CAUSE   | XCV temizken bağımsız failure
 * </pre>
 *
 * <p><strong>JSON kontratı:</strong> Jackson tarafından default davranışla
 * enum sabit adı UPPER_CASE string olarak serialize edilir:
 * {@code "ROOT_CAUSE"}, {@code "DERIVED"}, {@code "CASCADE"}. Tüm diğer
 * API enum'ları (örn. {@link io.mersel.dss.verify.api.models.enums.SignatureType
 * SignatureType}, {@link io.mersel.dss.verify.api.models.enums.SignaturePackaging
 * SignaturePackaging}, {@link io.mersel.dss.verify.api.models.enums.ChainRevocationStatus
 * ChainRevocationStatus}) aynı UPPER_CASE convention'unu kullanır — kontrat
 * tek bir noktada tutarlıdır, istemci SDK'lar tek code-path ile çözer.</p>
 */
public enum FailureCategory {

    /**
     * Pipeline'ın <strong>gerçek başarısızlık sebebi</strong> — diğer
     * NOT_OK constraint'ler bunun yansımasıdır. Frontend dispatch ve
     * operatör eylem mesajı için kullanılması gereken kategori.
     *
     * <p>Örnek: {@code BBB_XCV_ISCGKU} (KeyUsage uygunsuz) — SubXCV
     * katmanında, üst-blok XCV summary'sini ve SAV cascade'ini tetikler;
     * ama esas sorun bu satırdır.</p>
     *
     * <p>Wire format: {@code "ROOT_CAUSE"}.</p>
     */
    ROOT_CAUSE,

    /**
     * Üst-blokta <em>summary roll-up</em> rolü oynayan constraint —
     * alt-bloktaki bir failure'ı yukarı yansıtır, yeni bilgi taşımaz.
     *
     * <p>Yalnız XCV-top bloğundaki whitelist'lenmiş key'ler için (örn.
     * {@code BBB_XCV_SUB} = "Is the SubXCV conclusion valid?",
     * {@code BBB_XCV_ICTIVRSC} = "Is cert chain trusted in validation
     * root system cert?"). SubXCV'lerden biri zaten NOT_OK ise bu üst-blok
     * constraint'i deterministik olarak NOT_OK olur.</p>
     *
     * <p>Wire format: {@code "DERIVED"}.</p>
     */
    DERIVED,

    /**
     * Sertifika context'i kullanılamadığı için tetiklenen <em>downstream
     * yan ürün</em>. XCV bloğu INDETERMINATE/FAILED olduğunda SAV
     * (signature acceptance) ve CV (cryptographic verification)
     * bloklarının constraint'leri kontrol edilemeden NOT_OK düşer.
     *
     * <p>Örnek: KeyUsage failure XCV bloğunu INDETERMINATE'e çekince
     * SAV bloğunda {@code BBB_SAV_ISQPMDOSPP} ("Is the signed qualifying
     * property: 'message-digest' or 'SignedProperties' present?") da
     * NOT_OK görünür — esas sebep KeyUsage'dır, SAV cascade onun
     * sonucudur.</p>
     *
     * <p>Wire format: {@code "CASCADE"}.</p>
     */
    CASCADE
}
