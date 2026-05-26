using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Bir imzaya bağlı zaman damgası (signature timestamp / archive timestamp)
/// bilgisi. Detached timestamp doğrulama için bkz.
/// <see cref="TimestampVerificationResult"/>.
/// </summary>
public sealed class TimestampInfo
{
    /// <summary>Token kriptografik olarak geçerli mi ve TSA sertifikası doğrulandı mı?</summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    /// <summary>TSA tarafından üretilen zaman damgası anı (genTime).</summary>
    [JsonPropertyName("timestampTime")]
    public DateTimeOffset? TimestampTime { get; set; }

    /// <summary>Timestamp türü (örn. <c>SIGNATURE_TIMESTAMP</c>, <c>ARCHIVE_TIMESTAMP</c>).</summary>
    [JsonPropertyName("timestampType")]
    public string? TimestampType { get; set; }

    /// <summary>Token'ı düzenleyen TSA sertifikası.</summary>
    [JsonPropertyName("tsaCertificate")]
    public CertificateInfo? TsaCertificate { get; set; }

    /// <summary>Message imprint hash algoritması (örn. <c>SHA-256</c>).</summary>
    [JsonPropertyName("digestAlgorithm")]
    public string? DigestAlgorithm { get; set; }

    /// <summary>Imzalı veriye ait hesaplanan message imprint (hex).</summary>
    [JsonPropertyName("messageImprint")]
    public string? MessageImprint { get; set; }

    /// <summary>TSA tarafından atanan seri numarası.</summary>
    [JsonPropertyName("serialNumber")]
    public string? SerialNumber { get; set; }

    /// <summary>TSA'nın insan-okur kimliği (Subject DN'inin CN veya tam adı).</summary>
    [JsonPropertyName("tsaName")]
    public string? TsaName { get; set; }

    /// <summary>Token doğrulanırken üretilen hata kayıtları.</summary>
    [JsonPropertyName("validationErrors")]
    public List<string>? ValidationErrors { get; set; }
}
