using MERSEL.Services.DssVerifier.Client.Models;

namespace MERSEL.Services.DssVerifier.Client.Interfaces;

/// <summary>
/// Standalone RFC 3161 zaman damgası doğrulama operasyonları. Sunucu tarafında
/// <c>POST /api/v1/verify/timestamp</c> endpoint'ine eşlenir.
/// </summary>
/// <remarks>
/// İmzanın <em>içine gömülü</em> zaman damgaları otomatik olarak
/// <see cref="ISignatureVerifier"/> akışında doğrulanır ve sonuçları
/// <see cref="SignatureInfo.TimestampInfo"/> alanında raporlanır. Bu interface
/// yalnız tek başına gelen <c>.tsr</c> dosyalarının doğrulanması için kullanılır.
/// </remarks>
public interface ITimestampVerifier
{
    /// <summary>
    /// Bir RFC 3161 zaman damgası token'ını doğrular.
    /// </summary>
    /// <param name="request">Token, opsiyonel orijinal veri ve TSA sertifika doğrulama bayrağı.</param>
    /// <param name="ct">İptal belirteci.</param>
    Task<TimestampVerificationResult> VerifyAsync(VerifyTimestampRequest request, CancellationToken ct = default);

    /// <summary>
    /// Yalnız token doğrulamak için kısa yol overload'ı (orijinal veri yok,
    /// TSA sertifikası doğrulanır).
    /// </summary>
    /// <param name="timestampToken">RFC 3161 token içeriği (binary).</param>
    /// <param name="ct">İptal belirteci.</param>
    Task<TimestampVerificationResult> VerifyAsync(byte[] timestampToken, CancellationToken ct = default);

    /// <summary>
    /// Token ile orijinal veri arasında message imprint hash karşılaştırması
    /// yapmak için kısa yol overload'ı (TSA sertifikası doğrulanır).
    /// </summary>
    /// <param name="timestampToken">RFC 3161 token içeriği.</param>
    /// <param name="originalData">Token'ın hesaplandığı orijinal veri.</param>
    /// <param name="ct">İptal belirteci.</param>
    Task<TimestampVerificationResult> VerifyAsync(
        byte[] timestampToken,
        byte[] originalData,
        CancellationToken ct = default);
}
