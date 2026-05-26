using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Bir sertifikanın iptal (revocation) durumuna dair zengin bilgi modeli.
/// OCSP veya CRL kaynağından elde edilen iptal verisinin operasyonel ve
/// audit gereksinimleri için response'a yansıtılan ayrıntılı kesitidir.
/// </summary>
/// <remarks>
/// Eğer ilgili sertifika için revocation verisi yoksa (örn. çevrimdışı mod
/// veya hiç sorgulanmadıysa) <see cref="CertificateInfo.Revocation"/>
/// alanı <c>null</c> kalır — JSON'da görünmez.
/// </remarks>
public sealed class RevocationInfo
{
    /// <summary>İptal verisinin türü: <c>OCSP</c> veya <c>CRL</c>.</summary>
    [JsonPropertyName("source")]
    public string? Source { get; set; }

    /// <summary>Sertifika durumu: <c>GOOD</c>, <c>REVOKED</c>, <c>UNKNOWN</c>.</summary>
    [JsonPropertyName("status")]
    public string? Status { get; set; }

    /// <summary>Sertifikanın iptal edildiği an (yalnız <c>REVOKED</c> ise).</summary>
    [JsonPropertyName("revocationDate")]
    public DateTimeOffset? RevocationDate { get; set; }

    /// <summary>RFC 5280 iptal nedeni metni (örn. <c>keyCompromise</c>).</summary>
    [JsonPropertyName("revocationReason")]
    public string? RevocationReason { get; set; }

    /// <summary>İptal token'ının (OCSP response veya CRL) üretilme zamanı.</summary>
    [JsonPropertyName("producedAt")]
    public DateTimeOffset? ProducedAt { get; set; }

    /// <summary>Token'ın temsil ettiği bilginin geçerli olduğu başlangıç anı.</summary>
    [JsonPropertyName("thisUpdate")]
    public DateTimeOffset? ThisUpdate { get; set; }

    /// <summary>Bir sonraki güncellemenin beklendiği an (cache TTL ile uyumlu).</summary>
    [JsonPropertyName("nextUpdate")]
    public DateTimeOffset? NextUpdate { get; set; }

    /// <summary>Bilginin elde edildiği responder / dağıtım noktası adresi (audit).</summary>
    [JsonPropertyName("responderUrl")]
    public string? ResponderUrl { get; set; }

    /// <summary>
    /// Kaynak menşei: <c>EXTERNAL</c> (canlı sorgu), <c>CACHED</c>,
    /// <c>CMS_SIGNED_DATA</c>, <c>REVOCATION_VALUES</c>,
    /// <c>TIMESTAMP_VALIDATION_DATA</c>, vb.
    /// LT-level imzalarda token genellikle imzanın içinde gömülü gelir
    /// (örn. <c>REVOCATION_VALUES</c>); bu durumda canlı bir OCSP/CRL çağrısı
    /// yapılmamış demektir.
    /// </summary>
    [JsonPropertyName("origin")]
    public string? Origin { get; set; }
}
