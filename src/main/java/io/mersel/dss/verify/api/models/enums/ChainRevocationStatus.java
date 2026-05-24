package io.mersel.dss.verify.api.models.enums;

/**
 * Bir imzanın sertifika zincirinin (leaf + intermediate CA'lar) revocation
 * durumunu özetleyen kompakt enum.
 *
 * <p>{@code SIMPLE} mod response'unda da görünür olsun diye eklenmiştir.
 * Önceden, SIMPLE mod yalnız {@code signerCertificate.revocation}'i ifşa
 * ediyordu; ara CA seviyesindeki revocation durumu sadece COMPREHENSIVE
 * modda {@code certificateChain[].revocation} alt nesneleriyle görünürdü.
 * Bu alan tüketicinin SIMPLE modda da zincirin geneline dair tek bakışta
 * doğru karar vermesini sağlar — payload boyu maliyeti tek bir string.
 *
 * <p><b>Önemli kavramsal not:</b> Bu alan <em>doğrulama kararını</em>
 * etkilemez. DSS policy zaten zincirin tamamını kendi kuralları
 * çerçevesinde kontrol eder (bkz. {@code SigningCertificate} ve
 * {@code CACertificate} policy blokları). Bu enum yalnız operatöre /
 * UI'a sade bir özet sinyali sunar.
 *
 * <p><b>Seçim mantığı</b> (önceliğe göre):
 * <ol>
 *   <li>Hiç revocation verisi yoksa (çevrimdışı mod, B-level imza, vb.) →
 *       {@link #NOT_CHECKED}.</li>
 *   <li>Leaf {@code REVOKED} ise → {@link #LEAF_REVOKED}. Bu en kritik
 *       sinyal — CA durumuna bakılmaz çünkü imzacı zaten iptalli.</li>
 *   <li>Leaf {@code UNKNOWN} ise → {@link #UNKNOWN}. Imzacı için karar
 *       verilemiyor; CA durumu ne olursa olsun bu öncelikli.</li>
 *   <li>Leaf {@code GOOD} ve ara CA'lardan biri {@code REVOKED} ise →
 *       {@link #LEAF_GOOD_CA_REVOKED}. Imzacı OK görünüyor ama
 *       sertifikalandırma otoritesinin yetkisi iptal — politika
 *       seviyesinde değerlendirilmeli.</li>
 *   <li>Leaf {@code GOOD} ve bir veya daha fazla CA için {@code UNKNOWN}
 *       (ama REVOKED yok) → {@link #UNKNOWN}.</li>
 *   <li>Tüm zincir {@code GOOD} → {@link #ALL_GOOD}.</li>
 * </ol>
 */
public enum ChainRevocationStatus {

    /**
     * Zincirdeki tüm sertifikalar (leaf + intermediate CA'lar) revocation
     * kontrolünden {@code GOOD} geçti. En arzu edilen durum.
     */
    ALL_GOOD,

    /**
     * İmzacı (leaf) sertifika {@code REVOKED}. CA seviyesinin durumuna
     * bakılmaksızın en kritik sinyal. Hiçbir politika altında imza
     * üzerinde güvenle iş yapılmamalı.
     */
    LEAF_REVOKED,

    /**
     * İmzacı sertifika {@code GOOD}, fakat zincirde bir veya daha fazla
     * ara CA {@code REVOKED}. {@code signer-strict} policy'sinde imza
     * yine de geçerli sayılır (CA için {@code NotRevoked=WARN});
     * {@code strict} policy'sinde imza geçersiz olur (CA için
     * {@code NotRevoked=FAIL}). Operatörün politika tercihine göre
     * davranış değişir — bu alan o tercihi explicit hale getirir.
     */
    LEAF_GOOD_CA_REVOKED,

    /**
     * Zincirde bir veya daha fazla sertifika için durum {@code UNKNOWN}
     * — responder cevap verdi ama "iptal mi bilmiyorum" dedi.
     * Politika seviyesinde değerlendirme yapılmalı.
     */
    UNKNOWN,

    /**
     * Hiçbir sertifika için revocation kontrolü yapılamadı veya
     * yapılmadı. Çevrimdışı mod ({@code online-validation-enabled=false}),
     * B-level imza ve gömülü revocation yok, ya da responder erişilemez
     * durumlarında ortaya çıkar.
     */
    NOT_CHECKED
}
