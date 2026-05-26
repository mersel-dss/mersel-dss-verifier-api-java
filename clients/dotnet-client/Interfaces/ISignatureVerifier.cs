using MERSEL.Services.DssVerifier.Client.Models;
using MERSEL.Services.DssVerifier.Client.Models.Enums;

namespace MERSEL.Services.DssVerifier.Client.Interfaces;

/// <summary>
/// İmza doğrulama operasyonları. Sunucu tarafında
/// <c>POST /api/v1/verify/signature</c> (ve geri-uyumlu
/// <c>/xades</c>, <c>/pades</c>, <c>/cades</c>) endpoint'lerine eşlenir.
/// </summary>
/// <remarks>
/// <para>
/// XAdES (BES, EPES, T, C, X, XL, A), PAdES (B-B, B-T, B-LT, B-LTA) ve CAdES
/// (BES, EPES, T, C, X, XL, A) formatlarının tamamı tek bir
/// <see cref="VerifyAsync(VerifySignatureRequest, CancellationToken)"/>
/// çağrısı ile doğrulanabilir; sunucu içeriği inceleyerek format kararını
/// kendisi verir.
/// </para>
/// </remarks>
public interface ISignatureVerifier
{
    /// <summary>
    /// Verilen imzalı dokümanı doğrular ve yapılandırılmış
    /// <see cref="VerificationResult"/> döndürür.
    /// </summary>
    /// <remarks>
    /// <para>
    /// İmzanın geçersiz çıkması <em>hata değildir</em>; çağıran kod
    /// <see cref="VerificationResult.Valid"/> alanını ve
    /// <see cref="VerificationResult.Signatures"/> içindeki her bir
    /// <see cref="SignatureInfo.Valid"/> alanını birlikte incelemelidir.
    /// </para>
    /// <para>
    /// Sunucu hatası (4xx/5xx) durumunda <see cref="Exceptions.DssVerifierApiException"/>
    /// fırlatılır.
    /// </para>
    /// </remarks>
    /// <param name="request">Doğrulama isteği parametreleri (doküman, seviye, vb.).</param>
    /// <param name="ct">İptal belirteci.</param>
    /// <returns>Yapılandırılmış doğrulama sonucu.</returns>
    Task<VerificationResult> VerifyAsync(VerifySignatureRequest request, CancellationToken ct = default);

    /// <summary>
    /// Self-contained imzaları (enveloped XAdES, PAdES) varsayılan SIMPLE modda
    /// doğrulamak için kısa yol overload'ı.
    /// </summary>
    /// <param name="signedDocument">İmzalı doküman içeriği.</param>
    /// <param name="level">Doğrulama seviyesi. Varsayılan SIMPLE.</param>
    /// <param name="ct">İptal belirteci.</param>
    Task<VerificationResult> VerifyAsync(
        byte[] signedDocument,
        VerificationLevel level = VerificationLevel.SIMPLE,
        CancellationToken ct = default);

    /// <summary>
    /// Detached imza (CAdES detached, external XAdES) doğrulamak için kısa yol overload'ı.
    /// </summary>
    /// <param name="signedDocument">İmza içeriği (CMS / detached XAdES).</param>
    /// <param name="originalDocument">İmzanın hesaplandığı orijinal veri.</param>
    /// <param name="level">Doğrulama seviyesi. Varsayılan SIMPLE.</param>
    /// <param name="ct">İptal belirteci.</param>
    Task<VerificationResult> VerifyDetachedAsync(
        byte[] signedDocument,
        byte[] originalDocument,
        VerificationLevel level = VerificationLevel.SIMPLE,
        CancellationToken ct = default);
}
