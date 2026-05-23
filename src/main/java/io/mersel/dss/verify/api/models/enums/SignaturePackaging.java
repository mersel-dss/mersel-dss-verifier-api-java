package io.mersel.dss.verify.api.models.enums;

/**
 * XAdES imzasının paketleme (packaging) tipini W3C XMLDSig terminolojisiyle
 * temsil eder.
 *
 * <p>Tanımlar W3C XML Signature Syntax and Processing
 * (<a href="https://www.w3.org/TR/xmldsig-core/#sec-Signature">§4</a>) ve ETSI
 * EN 319 132-1 §4.2'nin XAdES baseline tarifinden gelir. Enum sabitleri DSS
 * upstream
 * <a href="https://github.com/esig/dss/blob/master/dss-enumerations/src/main/java/eu/europa/esig/dss/enumerations/SignaturePackaging.java">{@code eu.europa.esig.dss.enumerations.SignaturePackaging}</a>
 * ile birebir aynı isim ve semantiktedir — uluslararası entegratörler ve
 * statik tipli SDK üreticileri için tek code-path.</p>
 *
 * <h3>JSON serileştirme</h3>
 * <p>Jackson default davranışı ile {@code .name()} basılır
 * ({@code "ENVELOPED"} vb.). API yanıtında {@code signaturePackaging}
 * alanında raporlanır.</p>
 */
public enum SignaturePackaging {

    /**
     * İmza, imzaladığı XML belgenin <em>içinde</em> yer alır.
     *
     * <p>Pratik kalıp: en az bir {@code ds:Reference} ya boş URI'ye
     * ({@code URI=""}) sahiptir ya da {@code Transforms} listesinde
     * <a href="https://www.w3.org/TR/xmldsig-core/#sec-EnvelopedSignature">{@code …#enveloped-signature}</a>
     * algoritmasını barındırır. Türkiye'deki tüm e-Fatura, e-Arşiv,
     * e-İrsaliye UBL imzaları ve ApplicationResponse'lar bu kategoridedir.</p>
     */
    ENVELOPED,

    /**
     * İmzalanan içerik, {@code ds:Signature}'ın <em>içindeki</em>
     * {@code ds:Object} elementinin payload'udur.
     *
     * <p>Pratik kalıp: data {@code ds:Reference}'ı
     * {@code Type="http://www.w3.org/2000/09/xmldsig#Object"} ile aynı
     * {@code ds:Signature} altındaki {@code ds:Object[@Id]}'ye işaret eder
     * ({@code URI="#objId"}). Token-based imzalama akışlarında ve bazı
     * XAdES-EPES policy belgelerinde görülür.</p>
     */
    ENVELOPING,

    /**
     * İmzalanan içerik {@code ds:Signature}'ın <em>dışındadır</em>; ya ayrı
     * bir dosyada (external URL/file) ya da aynı XML konteyner içinde
     * sibling bir elemandadır (internally-detached).
     *
     * <p>Pratik kalıp: data {@code ds:Reference}'ın URI'si external bir
     * kaynağa, içeride bulunmayan bir {@code #id}'ye veya manifest
     * yapısına işaret eder; {@code enveloped-signature} transform'u
     * yoktur. ASiC konteynerlerinin XAdES manifest'leri de bu kategoride
     * raporlanır.</p>
     */
    DETACHED
}
