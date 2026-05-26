using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models.Enums;

/// <summary>
/// XAdES imzasının paketleme (packaging) tipini W3C XMLDSig terminolojisiyle
/// temsil eder.
/// </summary>
/// <remarks>
/// <para>
/// Tanımlar W3C XML Signature Syntax and Processing (§4) ve ETSI EN 319 132-1
/// §4.2'nin XAdES baseline tarifinden gelir. Sabit isim ve semantik DSS upstream
/// <c>eu.europa.esig.dss.enumerations.SignaturePackaging</c> ile birebir aynıdır —
/// uluslararası entegratörler için tek code-path.
/// </para>
/// <para>
/// XAdES dışı (CAdES/PAdES) imzalar için <c>null</c> kalır
/// (<see cref="SignatureInfo.SignaturePackaging"/> alanı doldurulmaz, JSON çıktısına
/// da düşmez).
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SignaturePackaging
{
    /// <summary>
    /// İmza, imzaladığı XML belgenin <em>içinde</em> yer alır.
    /// Türkiye'deki tüm e-Fatura, e-Arşiv, e-İrsaliye UBL imzaları ve
    /// ApplicationResponse'lar bu kategoridedir.
    /// </summary>
    ENVELOPED,

    /// <summary>
    /// İmzalanan içerik, <c>ds:Signature</c>'ın <em>içindeki</em>
    /// <c>ds:Object</c> elementinin payload'udur. Token-based imzalama akışlarında
    /// ve bazı XAdES-EPES policy belgelerinde görülür.
    /// </summary>
    ENVELOPING,

    /// <summary>
    /// İmzalanan içerik <c>ds:Signature</c>'ın <em>dışındadır</em>; ya ayrı bir
    /// dosyada (external URL/file) ya da aynı XML konteyner içinde sibling bir
    /// elemandadır (internally-detached). ASiC konteynerlerinin XAdES manifest'leri
    /// de bu kategoride raporlanır.
    /// </summary>
    DETACHED
}
