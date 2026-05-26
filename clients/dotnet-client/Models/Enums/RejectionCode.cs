namespace MERSEL.Services.DssVerifier.Client.Models.Enums;

/// <summary>
/// Mersel DSS Verifier'ın bir imzayı reddederken DSS'in soyut
/// <c>SubIndication</c>'ından öte Türkiye ekosistemine özgü bir
/// tanı kodu raporladığı durumlar.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="SuppressionCode"/> ile farkı</b>:
/// <list type="bullet">
///   <item><b>SuppressionCode</b> — DSS verdict'ini <em>override</em> ediyoruz:
///         DSS INVALID dedi, biz VALID diyoruz.</item>
///   <item><b>RejectionCode</b> — DSS verdict'ini <em>destekliyoruz</em>:
///         DSS INVALID dedi, biz de INVALID diyoruz, AMA neden invalid
///         olduğunu Türkiye-spesifik bir tanı koduyla açıklıyoruz.
///         <see cref="SignatureInfo.Valid"/> alanı <c>false</c> kalır.</item>
/// </list>
/// </para>
/// <para>
/// <b>Schema kararlılığı</b>: <c>Code</c> alanı kararlı bir API kontratıdır;
/// bir kez yayınlandığında değiştirilmez. Yeni değerler eklenebilir, mevcut
/// değerler renaming yapılmaz.
/// </para>
/// </remarks>
public enum RejectionCode
{
    /// <summary>
    /// XAdES imza yalnızca bir <c>ds:Reference</c> taşıyor;
    /// <c>xades:SignedProperties</c> elementi XML içinde mevcut fakat hiçbir
    /// Reference ona pointing değil. ETSI EN 319 132-1 (XAdES-BES) iki referans
    /// zorunluluğuna aykırı; <c>SigningTime</c>, <c>SigningCertificate</c> gibi
    /// alanlar kriptografik olarak korunmadığı için post-signing tahrifata açık.
    /// <para>Kanonik kod: <c>MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE</c></para>
    /// </summary>
    MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE
}

/// <summary>
/// <see cref="RejectionCode"/> enum değerini sunucu yanıtındaki kanonik
/// string koda çeviren yardımcı.
/// </summary>
public static class RejectionCodeExtensions
{
    /// <summary>
    /// Enum sabit adını sunucu kontratındaki dash-separated koda dönüştürür.
    /// </summary>
    public static string GetCode(this RejectionCode code) => code.ToString().Replace('_', '-');

    /// <summary>
    /// Sunucudan gelen kanonik string kodu enum değerine eşler. Bilinmeyen kodlar
    /// için <c>null</c> döner.
    /// </summary>
    public static RejectionCode? TryParse(string? code)
    {
        if (string.IsNullOrEmpty(code)) return null;
        return Enum.TryParse<RejectionCode>(code!.Replace('-', '_'), ignoreCase: true, out var parsed)
            ? parsed
            : null;
    }
}
