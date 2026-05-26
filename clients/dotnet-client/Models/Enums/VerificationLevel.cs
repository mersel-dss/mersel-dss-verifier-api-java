using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models.Enums;

/// <summary>
/// Doğrulama seviyesi. <c>/api/v1/verify/signature</c> isteğinde <c>level</c>
/// parametresine yansır.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum VerificationLevel
{
    /// <summary>
    /// <b>Basit doğrulama</b> — Yalnızca imzanın temel geçerlilik kararı +
    /// zincir / revocation özet sinyalleri döner. Sertifika zinciri detayları
    /// (her bir CA için <see cref="CertificateInfo"/>) yanıta dahil edilmez.
    /// Yüksek hacimli akışlarda (örn. ApplicationResponse doğrulaması) tercih edilir.
    /// </summary>
    SIMPLE,

    /// <summary>
    /// <b>Kapsamlı doğrulama</b> — Zincirin tamamı, her sertifika için OCSP/CRL
    /// detayları, qualification (QES / AdES/QC / AdES) hesaplaması ve DSS validation
    /// blokları dahil tüm audit-grade detaylar yanıta dahil edilir.
    /// </summary>
    COMPREHENSIVE
}
