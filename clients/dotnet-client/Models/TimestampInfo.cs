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

    /// <summary>
    /// Bu zaman damgasının DSS validation pipeline'ında <em>tek bir kök neden</em>
    /// (root cause) BBB FAIL constraint'i.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="SignatureInfo.RootCause"/> ile aynı sözleşmeyi taşır:
    /// pipeline-side-effect satırları (XCV-top roll-up + SAV/CV cascade) sessizce
    /// filtrelenir, yalnız gerçek kök neden döner. Birden fazla kök neden varsa
    /// DSS gezme sırasına göre ilki seçilir; defansif fallback ile hiç kök neden
    /// tespit edilemezse ham FAIL listesinden ilk satır seçilir.
    /// </para>
    /// <para>
    /// <c>null</c> → bu zaman damgasında FAIL constraint yok (geçerli).
    /// Eksiksiz audit için <see cref="FailedConstraints"/> alanı opt-in olarak
    /// doldurulabilir.
    /// </para>
    /// </remarks>
    /// <seealso cref="FailedConstraint"/>
    /// <seealso cref="FailedConstraints"/>
    [JsonPropertyName("rootCause")]
    public FailedConstraint? RootCause { get; set; }

    /// <summary>
    /// Bu zaman damgasının DSS validation pipeline'ındaki <em>tüm</em> BBB FAIL
    /// constraint'leri, <see cref="FailureCategory"/> ile kategorize edilmiş halde —
    /// opt-in alan.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Yalnız istekte <see cref="VerifySignatureRequest.IncludeFailedConstraints"/> =
    /// <c>true</c> verildiğinde doldurulur; default <c>null</c> kalır.
    /// Bkz. <see cref="SignatureInfo.FailedConstraints"/> — aynı sözleşmeyi taşır
    /// (ROOT_CAUSE + DERIVED + CASCADE kategorileri).
    /// </para>
    /// </remarks>
    /// <seealso cref="FailureCategory"/>
    /// <seealso cref="FailedConstraint"/>
    /// <seealso cref="VerifySignatureRequest.IncludeFailedConstraints"/>
    [JsonPropertyName("failedConstraints")]
    public List<FailedConstraint>? FailedConstraints { get; set; }
}
