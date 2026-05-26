using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// <c>GET /api/v1/info</c> yanıtı.
/// </summary>
public sealed class ServiceInfo
{
    /// <summary>Uygulama adı.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }

    /// <summary>Uygulama versiyonu.</summary>
    [JsonPropertyName("version")]
    public string? Version { get; set; }

    /// <summary>Servis açıklaması.</summary>
    [JsonPropertyName("description")]
    public string? Description { get; set; }

    /// <summary>
    /// Desteklenen özelliklerin (insan-okur) listesi
    /// (örn. <c>"XAdES Verification"</c>, <c>"OCSP/CRL Revocation Check"</c>).
    /// </summary>
    [JsonPropertyName("features")]
    public List<string>? Features { get; set; }
}
