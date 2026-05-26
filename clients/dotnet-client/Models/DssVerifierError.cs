using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Sunucudan dönen yapılandırılmış hata yanıtı.
/// API'nin <c>ErrorResponse</c> tipine birebir karşılık gelir.
/// </summary>
public sealed class DssVerifierError
{
    /// <summary>Hata kodu / kısa etiket (örn. <c>INVALID_DOCUMENT</c>, <c>VERIFICATION_FAILED</c>).</summary>
    [JsonPropertyName("error")]
    public string? Error { get; set; }

    /// <summary>İnsan-okur formatında hata açıklaması.</summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }

    /// <summary>Opsiyonel teknik detay (stack trace / iç hata mesajı).</summary>
    [JsonPropertyName("details")]
    public string? Details { get; set; }

    /// <summary>Sunucunun hata yanıtını oluşturduğu zaman.</summary>
    [JsonPropertyName("timestamp")]
    public DateTimeOffset? Timestamp { get; set; }

    /// <summary>İstek atılan endpoint yolu (sunucu tarafından raporlanır).</summary>
    [JsonPropertyName("path")]
    public string? Path { get; set; }
}
