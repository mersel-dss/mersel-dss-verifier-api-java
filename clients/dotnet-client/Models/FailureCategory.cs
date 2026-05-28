using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Bir <see cref="FailedConstraint"/> satırının DSS validation pipeline'ındaki
/// <em>rolünü</em> sınıflandırır.
/// </summary>
/// <remarks>
/// <para>
/// DSS pipeline'ı sıkı hiyerarşik akış izler — tek bir kök neden (örn. KeyUsage
/// uygunsuz) her zaman birden fazla NOT_OK constraint üretir (alt-bloktaki failure
/// üst-blokta summary roll-up tetikler, XCV INDETERMINATE durumu da SAV/CV
/// bloklarına cascade eder). Bu kategorilendirme operatörün "üç ayrı sorun var"
/// sanmasını engeller; frontend dispatch için yalnız <see cref="ROOT_CAUSE"/>
/// satırlarını kullanır, <see cref="DERIVED"/> ve <see cref="CASCADE"/> yalnız
/// "neden bu seçildi?" sorusunu cevaplayan audit kanıtıdır.
/// </para>
/// <para>
/// <b>JSON wire format</b>: enum sabit adı UPPER_CASE string olarak serialize
/// edilir (<c>"ROOT_CAUSE"</c>, <c>"DERIVED"</c>, <c>"CASCADE"</c>) — diğer tüm
/// API enum'larıyla (örn. <see cref="Enums.SignatureType"/>,
/// <see cref="Enums.VerificationLevel"/>, <see cref="Enums.ChainRevocationStatus"/>,
/// <see cref="Enums.SignaturePackaging"/>) aynı convention. Java sunucusu Jackson
/// default davranışıyla enum constant adını JSON'a aynen yazar; C# sabit adları
/// da zaten aynı isimleri taşıdığı için standart <see cref="JsonStringEnumConverter"/>
/// yeterli, custom converter gerekmez.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum FailureCategory
{
    /// <summary>
    /// Pipeline'ın <strong>gerçek başarısızlık sebebi</strong> — diğer NOT_OK
    /// constraint'ler bunun yansımasıdır. Frontend dispatch ve operatör eylem
    /// mesajı için kullanılması gereken kategori.
    /// <para>Wire format: <c>"ROOT_CAUSE"</c>.</para>
    /// </summary>
    ROOT_CAUSE,

    /// <summary>
    /// Üst-blokta <em>summary roll-up</em> rolü oynayan constraint — alt-bloktaki
    /// bir failure'ı yukarı yansıtır, yeni bilgi taşımaz. Yalnız XCV-top
    /// bloğundaki whitelist'lenmiş key'ler için (örn. <c>BBB_XCV_SUB</c>,
    /// <c>BBB_XCV_ICTIVRSC</c>).
    /// <para>Wire format: <c>"DERIVED"</c>.</para>
    /// </summary>
    DERIVED,

    /// <summary>
    /// Sertifika context'i kullanılamadığı için tetiklenen <em>downstream yan ürün</em>.
    /// XCV bloğu INDETERMINATE/FAILED olduğunda SAV (signature acceptance) ve CV
    /// (cryptographic verification) bloklarının constraint'leri kontrol edilemeden
    /// NOT_OK düşer.
    /// <para>Wire format: <c>"CASCADE"</c>.</para>
    /// </summary>
    CASCADE
}
