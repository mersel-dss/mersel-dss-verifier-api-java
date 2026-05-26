using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models.Enums;

/// <summary>
/// İmza tipi enum. Sunucu tarafında imzalı belge incelenir ve baş-prefix'e göre
/// karar verilir (XAdES → XML/UBL, PAdES → PDF, CAdES → CMS, vb.).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SignatureType
{
    /// <summary>PDF Advanced Electronic Signatures (ETSI EN 319 142).</summary>
    PADES,

    /// <summary>XML Advanced Electronic Signatures (ETSI EN 319 132).</summary>
    XADES,

    /// <summary>CMS Advanced Electronic Signatures (ETSI EN 319 122).</summary>
    CADES,

    /// <summary>ASiC-S (Associated Signature Container - Simple).</summary>
    ASIC_S,

    /// <summary>ASiC-E (Associated Signature Container - Extended).</summary>
    ASIC_E,

    /// <summary>Tanımlanamayan / desteklenmeyen format.</summary>
    UNKNOWN
}
