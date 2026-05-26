using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Tek başına (detached) bir RFC 3161 zaman damgası token'ının doğrulama sonucu.
/// <c>POST /api/v1/verify/timestamp</c> endpoint'i bu modeli döner.
/// </summary>
/// <remarks>
/// İmza içinde gömülü zaman damgaları için bkz.
/// <see cref="SignatureInfo.TimestampInfo"/> — bu model yalnız standalone
/// <c>.tsr</c> dosyalarının validasyonu için kullanılır.
/// </remarks>
public sealed class TimestampVerificationResult
{
    /// <summary>Token kriptografik olarak geçerli mi, TSA sertifikası doğrulandı mı (varsa orijinal veri ile message imprint eşleşti mi)?</summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    /// <summary>Verdict'in insan-okur özeti (örn. <c>VALID</c>, <c>INVALID</c>).</summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    /// <summary>TSA'nın token'ı ürettiği zaman (genTime).</summary>
    [JsonPropertyName("timestampTime")]
    public DateTimeOffset? TimestampTime { get; set; }

    /// <summary>TSA'nın insan-okur adı.</summary>
    [JsonPropertyName("tsaName")]
    public string? TsaName { get; set; }

    /// <summary>Message imprint hash algoritması (örn. <c>SHA-256</c>).</summary>
    [JsonPropertyName("digestAlgorithm")]
    public string? DigestAlgorithm { get; set; }

    /// <summary>Message imprint hex (token içindeki <c>messageImprint</c>).</summary>
    [JsonPropertyName("messageImprint")]
    public string? MessageImprint { get; set; }

    /// <summary>
    /// TSA sertifikası (yalnız istekte <c>validateCertificate=true</c> ise doludur).
    /// </summary>
    [JsonPropertyName("tsaCertificate")]
    public CertificateInfo? TsaCertificate { get; set; }

    /// <summary>Doğrulama sırasında oluşan hata kayıtları.</summary>
    [JsonPropertyName("errors")]
    public List<string>? Errors { get; set; }

    /// <summary>Doğrulama sırasında oluşan uyarı kayıtları.</summary>
    [JsonPropertyName("warnings")]
    public List<string>? Warnings { get; set; }

    /// <summary>Sunucunun doğrulamayı icra ettiği an.</summary>
    [JsonPropertyName("verificationTime")]
    public DateTimeOffset? VerificationTime { get; set; }
}
