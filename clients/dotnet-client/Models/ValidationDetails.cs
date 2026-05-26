using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// İmzaya ait kriptografik ve PKI doğrulamasının her bir alt-bileşeninin
/// tek-bakışta görülebileceği detay özeti. UI'da checklist olarak gösterilebilir.
/// </summary>
public sealed class ValidationDetails
{
    /// <summary>İmzanın kriptografik bütünlüğü (hash + signature value) doğrulandı mı?</summary>
    [JsonPropertyName("signatureIntact")]
    public bool SignatureIntact { get; set; }

    /// <summary>Sertifika zinciri trust anchor'a kadar başarılı şekilde kuruldu mu?</summary>
    [JsonPropertyName("certificateChainValid")]
    public bool CertificateChainValid { get; set; }

    /// <summary>İmzacı sertifika doğrulama anında <em>henüz</em> süresinde mi?</summary>
    [JsonPropertyName("certificateNotExpired")]
    public bool CertificateNotExpired { get; set; }

    /// <summary>İmzacı sertifika revocation kontrolünden GOOD geçti mi?</summary>
    [JsonPropertyName("certificateNotRevoked")]
    public bool CertificateNotRevoked { get; set; }

    /// <summary>Zincirin tepesindeki trust anchor (root CA) Mersel trust store'una ulaşıldı mı?</summary>
    [JsonPropertyName("trustAnchorReached")]
    public bool TrustAnchorReached { get; set; }

    /// <summary>İmzaya bağlı zaman damgaları (signature/archive timestamp) doğrulandı mı?</summary>
    [JsonPropertyName("timestampValid")]
    public bool TimestampValid { get; set; }

    /// <summary>Düşük seviyeli kriptografik doğrulama (hash karşılaştırma + RSA/EC verify) başarılı mı?</summary>
    [JsonPropertyName("cryptographicVerificationSuccessful")]
    public bool CryptographicVerificationSuccessful { get; set; }

    /// <summary>Bu doğrulama akışında en az bir OCSP/CRL kontrolü fiilen icra edildi mi?</summary>
    [JsonPropertyName("revocationCheckPerformed")]
    public bool RevocationCheckPerformed { get; set; }

    /// <summary>
    /// Serbest şemalı ek detay anahtar/değer çiftleri (örn. policy id, DSS reportXml id).
    /// </summary>
    [JsonPropertyName("additionalDetails")]
    public Dictionary<string, string>? AdditionalDetails { get; set; }
}
