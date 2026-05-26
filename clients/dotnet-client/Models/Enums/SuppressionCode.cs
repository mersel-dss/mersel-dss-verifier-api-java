namespace MERSEL.Services.DssVerifier.Client.Models.Enums;

/// <summary>
/// Mersel DSS Verifier'ın DSS kararını <strong>override ettiği</strong>
/// (INVALID → VALID elevate) durumlar için kararlı, public API kontratı
/// olan kod kümesi.
/// </summary>
/// <remarks>
/// <para>
/// <b>Hangi durumlar burada raporlanır?</b> Yalnızca DSS kararının
/// <em>geçersiz → geçerli</em> yönüne çevrildiği veya ek validasyon uyguladığımız
/// durumlar. Sıradan validation warning'leri (DSS'in zaten uyardığı şeyler)
/// buraya yazılmaz; onlar <see cref="SignatureInfo.ValidationWarnings"/> altında kalır.
/// </para>
/// <para>
/// <b>Schema kararlılığı</b>: <c>Code</c> alanı kararlı bir API kontratıdır;
/// bir kez yayınlandığında değiştirilmez. Yeni değerler eklenebilir, mevcut
/// değerler renaming yapılmaz.
/// </para>
/// <para>
/// <b>JSON serileştirme</b>: Bu enum doğrudan JSON'a düşmez — sunucu
/// <see cref="AppliedSuppression.Code"/> alanını <c>string</c> olarak gönderir
/// (örn. <c>"MDSS-XADES-LEGACY-TR-TYPE-URI"</c>). Enum ↔ kanonik kod dönüşümü
/// için <see cref="SuppressionCodeExtensions"/> yardımcılarını kullanın.
/// </para>
/// </remarks>
public enum SuppressionCode
{
    /// <summary>
    /// KamuSM / GİB ekosistemindeki bazı imzalama araçları XAdES
    /// <c>Reference Type</c> URI'sini standart dışı yazıyor. Verifier
    /// kriptografik bütünlük doğrulanmışsa bu yazım hatasına tolerans veriyor.
    /// <para>Kanonik kod: <c>MDSS-XADES-LEGACY-TR-TYPE-URI</c></para>
    /// </summary>
    MDSS_XADES_LEGACY_TR_TYPE_URI
}

/// <summary>
/// <see cref="SuppressionCode"/> enum değerini sunucu yanıtındaki kanonik
/// string koda (<c>MDSS-XADES-LEGACY-TR-TYPE-URI</c>) çeviren yardımcı.
/// </summary>
public static class SuppressionCodeExtensions
{
    /// <summary>
    /// Enum sabit adını sunucu kontratındaki dash-separated koda dönüştürür
    /// (örn. <c>MDSS_XADES_LEGACY_TR_TYPE_URI</c> → <c>MDSS-XADES-LEGACY-TR-TYPE-URI</c>).
    /// </summary>
    public static string GetCode(this SuppressionCode code) => code.ToString().Replace('_', '-');

    /// <summary>
    /// Sunucudan gelen kanonik string kodu enum değerine eşler. Bilinmeyen kodlar
    /// için <c>null</c> döner.
    /// </summary>
    public static SuppressionCode? TryParse(string? code)
    {
        if (string.IsNullOrEmpty(code)) return null;
        return Enum.TryParse<SuppressionCode>(code!.Replace('-', '_'), ignoreCase: true, out var parsed)
            ? parsed
            : null;
    }
}
