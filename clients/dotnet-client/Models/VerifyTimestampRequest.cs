namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Zaman damgası doğrulama isteği parametreleri.
/// <c>POST /api/v1/verify/timestamp</c> endpoint'ine eşlenir.
/// </summary>
public sealed class VerifyTimestampRequest
{
    /// <summary>
    /// RFC 3161 zaman damgası token içeriği (binary; tipik olarak <c>.tsr</c> dosyası).
    /// </summary>
    public byte[] TimestampToken { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// <see cref="TimestampToken"/> için multipart filename (sunucu loglarına yansır).
    /// </summary>
    public string TimestampFileName { get; set; } = "timestamp.tsr";

    /// <summary>
    /// Token'ın hesaplandığı orijinal veri. Sağlanırsa sunucu hesaplanan hash
    /// ile token içindeki <c>messageImprint</c> alanını karşılaştırır
    /// (manipulation tespiti). <c>null</c> bırakılırsa yalnız token'ın
    /// kriptografik bütünlüğü kontrol edilir.
    /// </summary>
    public byte[]? OriginalData { get; set; }

    /// <summary>
    /// <see cref="OriginalData"/> için multipart filename.
    /// </summary>
    public string OriginalDataFileName { get; set; } = "original-data";

    /// <summary>
    /// <c>true</c> ise TSA sertifika zinciri ve revocation kontrolü icra edilir.
    /// <c>false</c> ise sadece token'ın kriptografik bütünlüğü kontrol edilir
    /// (hızlı ama trust kararı vermez). Varsayılan: <c>true</c>.
    /// </summary>
    public bool ValidateCertificate { get; set; } = true;
}
