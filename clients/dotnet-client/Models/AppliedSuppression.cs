using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Mersel DSS Verifier'ın bir imza üzerinde DSS'in kararını <strong>bilinçli olarak
/// override ettiği</strong> (INVALID → VALID elevate) her durum için yapılandırılmış kayıt.
/// </summary>
/// <remarks>
/// <para>
/// İlke: bizim verifier "DSS dedi ki invalid, biz diyoruz ki valid" tarzı her kararı
/// <em>açık ve makine-okunaklı</em> şekilde raporlar. Audit, compliance ve
/// operasyonel görünürlük için kritik:
/// </para>
/// <list type="bullet">
///   <item><b>Audit</b>: regülatör veya kurumsal müşteri "bu imza neden VALID gösterildi?"
///         diye sorduğunda response içinde kanıt + sebep var.</item>
///   <item><b>Observability</b>: <see cref="Code"/> alanı Prometheus metric label'ı
///         ya da log filter olarak kullanılabilir.</item>
///   <item><b>Support</b>: kullanıcı support ticket'ında kod referans verir,
///         dökümentasyon URL'si tek tıkla erişilebilir.</item>
/// </list>
/// <para>
/// <b>SignatureInfo.Valid</b>: bu liste dolu olsa bile imzanın
/// <see cref="SignatureInfo.Valid"/> alanı <c>true</c> kalır — suppression'lar
/// verdict'i elevate eder.
/// </para>
/// </remarks>
/// <seealso cref="Enums.SuppressionCode"/>
public sealed class AppliedSuppression
{
    /// <summary>
    /// Kararlı, makine-okunaklı kod
    /// (örn. <c>MDSS-XADES-LEGACY-TR-TYPE-URI</c>).
    /// Bilinen değerler için bkz. <see cref="Enums.SuppressionCode"/>.
    /// </summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    /// <summary>İnsan-okunaklı kısa başlık (operatör dashboard'larında listelenebilir).</summary>
    [JsonPropertyName("title")]
    public string? Title { get; set; }

    /// <summary>Türkçe, son kullanıcıya / operatöre yönelik açıklayıcı metin. "Niye geçti?" cevabı.</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    /// <summary>
    /// Override'ın güvenlik etkisi:
    /// <list type="bullet">
    ///   <item><c>INFO</c>     — tasarımdan sapma ama güvenlik etkisi yok.</item>
    ///   <item><c>WARN</c>     — operatörün dikkat etmesi önerilir.</item>
    ///   <item><c>CRITICAL</c> — operatör eylem almalı (gelecekte).</item>
    /// </list>
    /// </summary>
    [JsonPropertyName("severity")]
    public string? Severity { get; set; }

    /// <summary>
    /// DSS'in <em>orijinal</em> indication'ı (override öncesi). Audit için:
    /// "DSS aslında ne demişti, biz ne yaptık" sorusuna kesin cevap.
    /// </summary>
    [JsonPropertyName("originalIndication")]
    public string? OriginalIndication { get; set; }

    /// <summary>DSS'in orijinal subIndication'ı (override öncesi).</summary>
    [JsonPropertyName("originalSubIndication")]
    public string? OriginalSubIndication { get; set; }

    /// <summary>
    /// Override'ı tetikleyen somut delil. Free-form key/value; her
    /// <see cref="Code"/>'a göre içeriği değişir.
    /// İstemcinin bu içeriği parse'lerken koda göre branch etmesi beklenir.
    /// </summary>
    [JsonPropertyName("evidence")]
    public Dictionary<string, object>? Evidence { get; set; }

    /// <summary>
    /// Bu kod için Mersel docs URL'i. Operatör tek tıkla detaylı sebebi + tolerans
    /// kuralını + kapatma yönergesini görür.
    /// </summary>
    [JsonPropertyName("docsUrl")]
    public string? DocsUrl { get; set; }
}
