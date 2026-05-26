using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// <c>GET /api/v1/health</c> yanıtı.
/// </summary>
public sealed class HealthInfo
{
    /// <summary>Servis durumu (örn. <c>UP</c>, <c>DOWN</c>).</summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    /// <summary>Uygulama adı (<c>spring.application.name</c>).</summary>
    [JsonPropertyName("application")]
    public string? Application { get; set; }

    /// <summary>Uygulama versiyonu (Maven <c>project.version</c>).</summary>
    [JsonPropertyName("version")]
    public string? Version { get; set; }

    /// <summary>Yanıtın oluşturulduğu UNIX epoch millis.</summary>
    [JsonPropertyName("timestamp")]
    public long? Timestamp { get; set; }
}
