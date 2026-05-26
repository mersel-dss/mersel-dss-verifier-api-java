using MERSEL.Services.DssVerifier.Client.Models.Enums;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// İmza doğrulama isteği parametreleri.
/// <c>POST /api/v1/verify/signature</c> endpoint'ine eşlenir.
/// </summary>
public sealed class VerifySignatureRequest
{
    /// <summary>
    /// İmzalı doküman içeriği (binary). XAdES için XML, PAdES için PDF,
    /// CAdES için CMS / .p7s / .p7m vb.
    /// </summary>
    public byte[] SignedDocument { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// <c>SignedDocument</c> için multipart filename (sadece sunucu loglarına yansır;
    /// imza tipini sunucu içeriğe bakarak tespit eder).
    /// </summary>
    public string SignedDocumentFileName { get; set; } = "signed-document";

    /// <summary>
    /// Detached imza akışlarında orijinal (imzalanmamış) doküman. CAdES detached
    /// veya external XAdES senaryolarında zorunlu; enveloped XAdES ve PAdES için
    /// <c>null</c> bırakın.
    /// </summary>
    public byte[]? OriginalDocument { get; set; }

    /// <summary>
    /// <see cref="OriginalDocument"/> için multipart filename.
    /// </summary>
    public string OriginalDocumentFileName { get; set; } = "original-document";

    /// <summary>
    /// Doğrulama seviyesi. <see cref="Enums.VerificationLevel.SIMPLE"/> sadece
    /// imza geçerliliği + özet sinyalleri verirken,
    /// <see cref="Enums.VerificationLevel.COMPREHENSIVE"/> tam sertifika zinciri,
    /// her CA için OCSP/CRL detayları ve DSS validation blokları döndürür.
    /// Varsayılan: <see cref="Enums.VerificationLevel.SIMPLE"/>.
    /// </summary>
    public VerificationLevel Level { get; set; } = VerificationLevel.SIMPLE;
}
