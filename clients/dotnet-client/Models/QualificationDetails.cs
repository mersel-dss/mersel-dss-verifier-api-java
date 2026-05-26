using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// İmzanın eIDAS qualification (yasal seviye) sonucu.
/// </summary>
/// <remarks>
/// <para>
/// <b>Olası seviye değerleri</b> (<see cref="QualificationLevel"/>):
/// <list type="bullet">
///   <item><c>QES</c>          — Qualified Electronic Signature (en güçlü; ıslak imza eşdeğeri).</item>
///   <item><c>AdES/QC</c>      — Advanced Electronic Signature with Qualified Certificate.</item>
///   <item><c>AdES</c>         — Advanced Electronic Signature (qualified certificate'sız).</item>
///   <item><c>NA</c>           — Qualification hesaplanamadı veya uygulanamadı.</item>
/// </list>
/// </para>
/// </remarks>
public sealed class QualificationDetails
{
    /// <summary>Qualification seviyesi (QES, AdES/QC, AdES, NA).</summary>
    [JsonPropertyName("qualificationLevel")]
    public string? QualificationLevel { get; set; }

    /// <summary>Qualification hesaplaması sırasında oluşan FAIL kayıtları.</summary>
    [JsonPropertyName("errors")]
    public List<string>? Errors { get; set; }

    /// <summary>Qualification hesaplaması sırasında oluşan WARN kayıtları.</summary>
    [JsonPropertyName("warnings")]
    public List<string>? Warnings { get; set; }

    /// <summary>Qualification hesaplaması sırasında oluşan INFO kayıtları.</summary>
    [JsonPropertyName("info")]
    public List<string>? Info { get; set; }
}
