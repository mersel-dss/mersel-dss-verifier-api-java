using System.Text.Json.Serialization;
using MERSEL.Services.DssVerifier.Client.Models.Enums;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// İmza doğrulama yanıt modeli. <c>POST /api/v1/verify/signature</c> ve
/// legacy alias endpoint'leri (<c>/xades</c>, <c>/pades</c>, <c>/cades</c>)
/// bu modeli döner.
/// </summary>
/// <remarks>
/// <para>
/// <b>Önemli</b>: Sunucu doğrulamayı başarıyla <em>icra</em> ettiği sürece
/// HTTP 200 ile bu modeli döner — imzanın geçersiz çıkması bir HTTP hatası
/// değildir. Karar için <see cref="Valid"/> alanını ve
/// <see cref="Signatures"/> içindeki her bir <see cref="SignatureInfo.Valid"/>
/// alanını birlikte inceleyin (birden çok imza varsa).
/// </para>
/// </remarks>
public sealed class VerificationResult
{
    /// <summary>
    /// Bütünsel verdict. Doküman tek imza taşıyorsa o imzanın geçerlilik
    /// kararı; çoklu imza varsa <em>tüm imzaların</em> AND'i.
    /// </summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    /// <summary>
    /// Verdict'in insan-okur özet metni (örn. <c>VALID</c>, <c>INVALID</c>,
    /// <c>INDETERMINATE</c>).
    /// </summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    /// <summary>İmza formatı (XAdES / PAdES / CAdES / …).</summary>
    [JsonPropertyName("signatureType")]
    public SignatureType? SignatureType { get; set; }

    /// <summary>Sunucunun doğrulamayı icra ettiği an.</summary>
    [JsonPropertyName("verificationTime")]
    public DateTimeOffset? VerificationTime { get; set; }

    /// <summary>Belgedeki imza sayısı.</summary>
    [JsonPropertyName("signatureCount")]
    public int? SignatureCount { get; set; }

    /// <summary>Tüm imzaların detayları.</summary>
    [JsonPropertyName("signatures")]
    public List<SignatureInfo> Signatures { get; set; } = new();

    /// <summary>Doküman-seviyesi hata kayıtları (örn. parse hatası).</summary>
    [JsonPropertyName("errors")]
    public List<string> Errors { get; set; } = new();

    /// <summary>Doküman-seviyesi uyarı kayıtları.</summary>
    [JsonPropertyName("warnings")]
    public List<string> Warnings { get; set; } = new();

    /// <summary>
    /// Doküman-seviyesi validation alt-bileşenleri özet özeti
    /// (per-signature detaylar <see cref="SignatureInfo.ValidationDetails"/> altında).
    /// </summary>
    [JsonPropertyName("validationDetails")]
    public ValidationDetails? ValidationDetails { get; set; }
}
