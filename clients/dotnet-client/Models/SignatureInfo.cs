using System.Text.Json.Serialization;
using MERSEL.Services.DssVerifier.Client.Models.Enums;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Tek bir imzanın detay bilgisi. Bir doküman birden çok imza içerebilir
/// (örn. multi-signed UBL, multi-signed PDF); her biri ayrı bir
/// <see cref="SignatureInfo"/> olarak <see cref="VerificationResult.Signatures"/>
/// listesinde döner.
/// </summary>
public sealed class SignatureInfo
{
    /// <summary>İmzanın benzersiz id'si (XAdES için <c>ds:Signature/@Id</c>, CAdES için SignerInfo SID).</summary>
    [JsonPropertyName("signatureId")]
    public string? SignatureId { get; set; }

    /// <summary>İmzanın bütünsel geçerlilik kararı (kriptografi + zincir + revocation + policy).</summary>
    [JsonPropertyName("valid")]
    public bool Valid { get; set; }

    /// <summary>İmza formatı (örn. <c>XAdES</c>, <c>PAdES</c>, <c>CAdES</c>).</summary>
    [JsonPropertyName("signatureFormat")]
    public string? SignatureFormat { get; set; }

    /// <summary>
    /// İmza seviyesi (örn. <c>XAdES-BASELINE-B</c>, <c>XAdES-BASELINE-LTA</c>,
    /// <c>PAdES-BASELINE-LTA</c>). DSS upstream isimlendirmesi.
    /// </summary>
    [JsonPropertyName("signatureLevel")]
    public string? SignatureLevel { get; set; }

    /// <summary>
    /// XAdES paketleme tipi — W3C XMLDSig terminolojisi. XAdES dışı (CAdES/PAdES)
    /// imzalar için <c>null</c>.
    /// </summary>
    [JsonPropertyName("signaturePackaging")]
    public SignaturePackaging? SignaturePackaging { get; set; }

    /// <summary>İmza atılırken kullanılan zaman (TSA timestamp varsa onun aksi halde claimed).</summary>
    [JsonPropertyName("signingTime")]
    public DateTimeOffset? SigningTime { get; set; }

    /// <summary>İmzacının iddia ettiği imzalama anı (<c>xades:SigningTime</c>).</summary>
    [JsonPropertyName("claimedSigningTime")]
    public DateTimeOffset? ClaimedSigningTime { get; set; }

    /// <summary>İmzacı (leaf) sertifika.</summary>
    [JsonPropertyName("signerCertificate")]
    public CertificateInfo? SignerCertificate { get; set; }

    /// <summary>
    /// Tam sertifika zinciri (leaf'ten root'a). Yalnız
    /// <see cref="Enums.VerificationLevel.COMPREHENSIVE"/> modda doldurulur.
    /// </summary>
    [JsonPropertyName("certificateChain")]
    public List<CertificateInfo>? CertificateChain { get; set; }

    /// <summary>
    /// İmzanın sertifika zinciri (leaf + intermediate CA'lar) için revocation
    /// durumunun kompakt özeti. SIMPLE mod response'unda da görünür.
    /// </summary>
    [JsonPropertyName("chainRevocationStatus")]
    public ChainRevocationStatus? ChainRevocationStatus { get; set; }

    /// <summary>İmzaya bağlı (varsa) ilk zaman damgası bilgisi.</summary>
    [JsonPropertyName("timestampInfo")]
    public TimestampInfo? TimestampInfo { get; set; }

    /// <summary>İmza algoritması (örn. <c>SHA256withRSA</c>, <c>ecdsa-with-SHA384</c>).</summary>
    [JsonPropertyName("signatureAlgorithm")]
    public string? SignatureAlgorithm { get; set; }

    /// <summary>Digest algoritması (örn. <c>SHA-256</c>).</summary>
    [JsonPropertyName("digestAlgorithm")]
    public string? DigestAlgorithm { get; set; }

    /// <summary>Bu imzaya özgü hata kayıtları.</summary>
    [JsonPropertyName("validationErrors")]
    public List<string>? ValidationErrors { get; set; }

    /// <summary>Bu imzaya özgü uyarı kayıtları.</summary>
    [JsonPropertyName("validationWarnings")]
    public List<string>? ValidationWarnings { get; set; }

    /// <summary>
    /// DSS indication (örn. <c>TOTAL_PASSED</c>, <c>INDETERMINATE</c>,
    /// <c>TOTAL_FAILED</c>). eIDAS terminolojisi.
    /// </summary>
    [JsonPropertyName("indication")]
    public string? Indication { get; set; }

    /// <summary>DSS sub-indication (örn. <c>HASH_FAILURE</c>, <c>SIG_CONSTRAINTS_FAILURE</c>).</summary>
    [JsonPropertyName("subIndication")]
    public string? SubIndication { get; set; }

    /// <summary>eIDAS qualification (QES / AdES/QC / AdES) sonucu.</summary>
    [JsonPropertyName("qualificationDetails")]
    public QualificationDetails? QualificationDetails { get; set; }

    /// <summary>Bu imzaya bağlı zaman damgası sayısı.</summary>
    [JsonPropertyName("timestampCount")]
    public int? TimestampCount { get; set; }

    /// <summary>XAdES-EPES için imza policy id (OID veya URI).</summary>
    [JsonPropertyName("policyIdentifier")]
    public string? PolicyIdentifier { get; set; }

    /// <summary>İmza-spesifik detaylı validation alt-bileşenleri.</summary>
    [JsonPropertyName("validationDetails")]
    public ValidationDetails? ValidationDetails { get; set; }

    /// <summary>
    /// Mersel DSS Verifier'ın bu imza için DSS kararını <em>override ettiği</em>
    /// tüm durumlar. Boş veya null ise: DSS'in kararı aynen kullanıldı.
    /// </summary>
    [JsonPropertyName("appliedSuppressions")]
    public List<AppliedSuppression>? AppliedSuppressions { get; set; }

    /// <summary>
    /// Mersel DSS Verifier'ın bu imzayı reddederken DSS'in soyut subIndication'ına
    /// ek olarak Türkiye ekosistemine özgü tanı kodlarıyla zenginleştirdiği gerekçeler.
    /// İmzanın <see cref="Valid"/> alanı bu liste dolu olsa bile <c>false</c> kalır.
    /// </summary>
    [JsonPropertyName("appliedRejections")]
    public List<AppliedRejection>? AppliedRejections { get; set; }
}
