package io.mersel.dss.verify.api.services.util;

import java.util.Objects;

/**
 * KamuSM / GİB / Mali Mühür ekosistemindeki üreticilerin XAdES imzalarda
 * ürettiği <strong>standart-dışı yapısal patolojilerin</strong> tipini
 * ve somut delilini taşıyan immutable kayıt.
 *
 * <p>{@link LegacyTurkishXadesTypeUriDetector} bu kaydı döndürür. Verifier
 * akışı (özellikle
 * {@link io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService})
 * <em>tipini</em> ({@link #getKind()}) baz alarak doğru politikayı uygular:</p>
 * <ul>
 *   <li>{@link Kind#TYPE_URI_VARIANT} → <strong>suppression</strong> yolu
 *       (DSS INVALID, biz VALID;
 *       {@link io.mersel.dss.verify.api.models.AppliedSuppression}).</li>
 *   <li>{@link Kind#MISSING_SP_REFERENCE} → <strong>rejection</strong> yolu
 *       (DSS INVALID, biz de INVALID; sadece Mersel tanı koduyla zenginleştir;
 *       {@link io.mersel.dss.verify.api.models.AppliedRejection}).</li>
 * </ul>
 */
public final class LegacyTurkishXadesAnomaly {

    /**
     * Patolojinin tipi. Verifier her tip için ayrı bir kod kümesinden
     * (SuppressionCode veya RejectionCode) kayıt tutar.
     */
    public enum Kind {
        /**
         * Üretici XAdES <code>Reference Type</code> attribute'unu standart
         * dışı yazmış: ya <code>…/01903/…XAdES.xsd…#SignedProperties</code>
         * formatında ya da <code>v1.3.2/v1.4.1#SignedProperties</code>
         * versiyon-prefix'iyle. Referans VAR ve kriptografi sağlam.
         * {@code evidence} alanı yakalanan Type URI'sini taşır.
         *
         * <p><b>Verifier davranışı</b>: suppression — DSS INVERSE'i
         * tolere ederek VALID'e elevate edilir
         * ({@link io.mersel.dss.verify.api.models.enums.SuppressionCode#MDSS_XADES_LEGACY_TR_TYPE_URI}).</p>
         */
        TYPE_URI_VARIANT,

        /**
         * XAdES imza yalnızca <strong>bir</strong>
         * <code>&lt;ds:Reference&gt;</code> taşıyor; XML'de
         * <code>&lt;xades:SignedProperties&gt;</code> elementi mevcut
         * fakat hiçbir Reference ona pointing değil — ne
         * <code>URI="#SignedProperties_X"</code> ile ne de
         * <code>Type=".../#SignedProperties"</code> ile. ETSI EN 319
         * 132-1 (XAdES-BES) iki referans zorunluluğuna aykırı.
         *
         * <p><b>Verifier davranışı</b>: rejection — bu varyantta
         * SignedProperties (içindeki SigningTime, SigningCertificate digest,
         * SignaturePolicyIdentifier vs.) imzayla cryptographic olarak bağlı
         * değil; ilgili metadata post-signing modifiye edilebilir ve imza
         * yine doğrulanır. İmza standart davranışla <strong>INVALID</strong>
         * raporlanır; yalnızca DSS'in soyut SubIndication'ı yerine Mersel'e özel
         * tanı kodu ({@link io.mersel.dss.verify.api.models.enums.RejectionCode#MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE})
         * ile zenginleştirilir.</p>
         *
         * <p>{@code evidence} alanı yakalanan SignedProperties <code>Id</code>
         * değerini taşır (audit için).</p>
         */
        MISSING_SP_REFERENCE
    }

    private final Kind kind;
    private final String evidence;

    public LegacyTurkishXadesAnomaly(Kind kind, String evidence) {
        this.kind = Objects.requireNonNull(kind, "kind cannot be null");
        this.evidence = Objects.requireNonNull(evidence, "evidence cannot be null");
    }

    public Kind getKind() {
        return kind;
    }

    /**
     * Tespiti tetikleyen somut delil. {@link Kind#TYPE_URI_VARIANT} için
     * yakalanan Type URI string'i; {@link Kind#MISSING_SP_REFERENCE} için
     * yakalanan SignedProperties <code>Id</code> attribute'u.
     */
    public String getEvidence() {
        return evidence;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof LegacyTurkishXadesAnomaly)) return false;
        LegacyTurkishXadesAnomaly that = (LegacyTurkishXadesAnomaly) o;
        return kind == that.kind && evidence.equals(that.evidence);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, evidence);
    }

    @Override
    public String toString() {
        return "LegacyTurkishXadesAnomaly{kind=" + kind + ", evidence='" + evidence + "'}";
    }
}
