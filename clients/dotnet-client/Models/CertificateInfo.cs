using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Bir X.509 sertifikasına dair detay bilgi. <c>signerCertificate</c>,
/// <c>certificateChain[*]</c> ve TSA sertifika alanlarında kullanılır.
/// API'nin <c>CertificateInfo</c> tipine birebir karşılık gelir.
/// </summary>
public sealed class CertificateInfo
{
    /// <summary>Subject DN (tam ayrıştırılmış RFC 4514 formatı).</summary>
    [JsonPropertyName("subject")]
    public string? Subject { get; set; }

    /// <summary>Subject'in Common Name (CN) alanı.</summary>
    [JsonPropertyName("commonName")]
    public string? CommonName { get; set; }

    /// <summary>Issuer (düzenleyici) Distinguished Name.</summary>
    [JsonPropertyName("issuerDN")]
    public string? IssuerDN { get; set; }

    /// <summary>Sertifika seri numarası (decimal veya hex string).</summary>
    [JsonPropertyName("serialNumber")]
    public string? SerialNumber { get; set; }

    /// <summary>
    /// Subject DN içindeki <c>serialNumber</c> attribute'u
    /// (TR'de TCKN / VKN). Sertifika seri numarası ile karıştırılmamalıdır.
    /// </summary>
    [JsonPropertyName("subjectSerialNumber")]
    public string? SubjectSerialNumber { get; set; }

    /// <summary>Geçerlilik başlangıç tarihi (notBefore).</summary>
    [JsonPropertyName("notBefore")]
    public DateTimeOffset? NotBefore { get; set; }

    /// <summary>Geçerlilik bitiş tarihi (notAfter).</summary>
    [JsonPropertyName("notAfter")]
    public DateTimeOffset? NotAfter { get; set; }

    /// <summary>Key Usage extension'ın insan-okur özeti.</summary>
    [JsonPropertyName("keyUsage")]
    public string? KeyUsage { get; set; }

    /// <summary>Public key algoritması (örn. <c>RSA</c>, <c>EC</c>).</summary>
    [JsonPropertyName("publicKeyAlgorithm")]
    public string? PublicKeyAlgorithm { get; set; }

    /// <summary>Public key uzunluğu (bit; örn. RSA için 2048, EC için eğri bit boyu).</summary>
    [JsonPropertyName("publicKeySize")]
    public int? PublicKeySize { get; set; }

    /// <summary>
    /// Sertifikanın kendi imza algoritması (örn. <c>SHA256withRSA</c>).
    /// İmza belgesinin algoritması ile karıştırılmamalıdır.
    /// </summary>
    [JsonPropertyName("signatureAlgorithm")]
    public string? SignatureAlgorithm { get; set; }

    /// <summary>Trust anchor'a kadar zincirlenebiliyor mu?</summary>
    [JsonPropertyName("trusted")]
    public bool Trusted { get; set; }

    /// <summary>Sertifikanın geçerlilik süresi (notAfter) doğrulama anında geçmiş mi?</summary>
    [JsonPropertyName("expired")]
    public bool Expired { get; set; }

    /// <summary>Tüm kriterler (zincir + revocation + süre) bir arada geçtiyse <c>true</c>.</summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    /// <summary>Revocation kontrolünden iptal olduğu tespit edildi mi?</summary>
    [JsonPropertyName("revoked")]
    public bool Revoked { get; set; }

    /// <summary>RFC 5280 revocation nedeni metni (varsa).</summary>
    [JsonPropertyName("revocationReason")]
    public string? RevocationReason { get; set; }

    /// <summary>İptal anı (varsa).</summary>
    [JsonPropertyName("revocationTime")]
    public DateTimeOffset? RevocationTime { get; set; }

    /// <summary>İptal tarihi (geriye dönük uyumluluk; <see cref="RevocationTime"/> tercih edilir).</summary>
    [JsonPropertyName("revocationDate")]
    public DateTimeOffset? RevocationDate { get; set; }

    /// <summary>
    /// OCSP/CRL kaynaklı zengin iptal detayı. Online doğrulama kapalıysa veya
    /// sertifika için DSS revocation data üretemediyse <c>null</c> kalır.
    /// </summary>
    [JsonPropertyName("revocation")]
    public RevocationInfo? Revocation { get; set; }
}
