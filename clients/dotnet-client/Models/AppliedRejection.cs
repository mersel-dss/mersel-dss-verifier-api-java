using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Mersel DSS Verifier'ın bir imzayı reddederken, DSS'in jenerik
/// <c>SubIndication</c>'ından öte <strong>Türkiye ekosistemine özgü bir tanı
/// kodu</strong> raporladığı kayıt.
/// </summary>
/// <remarks>
/// <para>
/// İlke: DSS "SIG_CONSTRAINTS_FAILURE" diyor; bu, eIDAS terminolojisinde doğru
/// ama operatör için belirsiz. Biz örneğin "XAdES imza yalnızca bir
/// <c>ds:Reference</c> taşıyor; SignedProperties imza kapsamına alınmamış"
/// gibi <em>somut, aksiyon alınabilir</em> bir gerekçeyle yanıtı zenginleştiririz.
/// </para>
/// <para>
/// <b><see cref="AppliedSuppression"/> ile farkı</b>:
/// <list type="bullet">
///   <item><b>AppliedSuppression</b> — DSS INVALID dedi, biz VALID dedik (override).
///         Verdict elevate edildi.</item>
///   <item><b>AppliedRejection</b> — DSS INVALID dedi, biz de INVALID diyoruz (destek).
///         <see cref="SignatureInfo.Valid"/> = <c>false</c> kalıyor; sadece
///         Türkiye-spesifik gerekçe kodu ekleniyor.</item>
/// </list>
/// </para>
/// </remarks>
/// <seealso cref="Enums.RejectionCode"/>
public sealed class AppliedRejection
{
    /// <summary>
    /// Kararlı, makine-okunaklı kod
    /// (örn. <c>MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE</c>).
    /// Bilinen değerler için bkz. <see cref="Enums.RejectionCode"/>.
    /// </summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    /// <summary>İnsan-okunaklı kısa başlık.</summary>
    [JsonPropertyName("title")]
    public string? Title { get; set; }

    /// <summary>Türkçe, son kullanıcıya / operatöre yönelik açıklayıcı metin. "Niye reddedildi?" cevabı.</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    /// <summary>
    /// Tanının ağırlığı:
    /// <list type="bullet">
    ///   <item><c>ERROR</c> — imza reddedildi, kullanıcı eylemi gerekli.</item>
    ///   <item><c>FATAL</c> — ekosistem güvenlik açığı seviyesinde (gelecekte).</item>
    /// </list>
    /// </summary>
    [JsonPropertyName("severity")]
    public string? Severity { get; set; }

    /// <summary>DSS'in <em>orijinal</em> indication'ı.</summary>
    [JsonPropertyName("originalIndication")]
    public string? OriginalIndication { get; set; }

    /// <summary>DSS'in orijinal subIndication'ı.</summary>
    [JsonPropertyName("originalSubIndication")]
    public string? OriginalSubIndication { get; set; }

    /// <summary>
    /// Rejection'ı tetikleyen somut delil. Free-form key/value; her
    /// <see cref="Code"/>'a göre içeriği değişir.
    /// </summary>
    [JsonPropertyName("evidence")]
    public Dictionary<string, object>? Evidence { get; set; }

    /// <summary>
    /// Bu kod için Mersel docs URL'i. Operatör tek tıkla rejection gerekçesini,
    /// yapısal patolojiyi ve giderme yönergesini görür.
    /// </summary>
    [JsonPropertyName("docsUrl")]
    public string? DocsUrl { get; set; }
}
