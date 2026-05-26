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

    /// <summary>
    /// İsteğe ek custom HTTP request header'ları. Sunucu tarafındaki
    /// <c>LogHeadersFilter</c> <c>x-log-*</c> prefix'li tüm header'ları
    /// otomatik olarak MDC'ye taşır; doğrulama log satırlarına bunları
    /// JSON olarak iliştirir ve <strong>INVALID imza webhook/Slack
    /// bildirimlerine</strong> hem JSON payload (<c>logHeaders</c> alanı)
    /// hem de pass-through HTTP header olarak forward eder.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Tipik kullanım:</b> upstream akıştan gelen korelasyon kimliklerini
    /// (request ID, tenant, kullanıcı, trace) DSS Verifier log/alarm
    /// akışına geçirmek. Sunucu kontratı yalnız <c>x-log-*</c> prefix'li
    /// header'ları işler — diğer custom header'lar (örn. <c>X-API-Key</c>)
    /// için <see cref="DssVerifierClientOptions"/> ya da
    /// <c>IHttpClientBuilder</c> üzerinden DefaultRequestHeaders eklemek
    /// daha doğru bir yer.
    /// </para>
    /// <para>
    /// <b>Header ismi ve değer kuralları:</b> isimler küçük harfle eşleşir
    /// (HTTP semantik); değerler max 512 char'a sunucuda kırpılır ve
    /// CR/LF/control karakterler boşlukla değiştirilir (log injection
    /// koruması). Request başına en fazla 20 header sunucu tarafında
    /// işlenir; üstündekiler sessizce drop edilir.
    /// </para>
    /// <para>
    /// <b>Çok-değerli header:</b> Aynı header birden fazla kez eklenmek
    /// isteniyorsa standart pratik virgülle birleştirilmiş tek değer
    /// kullanmaktır (HTTP/1.1 izin verir). Dictionary tek değer tutar.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var sonuc = await verifier.Signatures.VerifyAsync(new VerifySignatureRequest
    /// {
    ///     SignedDocument = imzaliPdf,
    ///     Headers = new Dictionary&lt;string, string&gt;
    ///     {
    ///         ["x-log-id"]      = Activity.Current?.Id ?? Guid.NewGuid().ToString("N"),
    ///         ["x-log-tenant"]  = currentTenantId,
    ///         ["x-log-user"]    = currentUserId
    ///     }
    /// });
    /// </code>
    /// </example>
    public IDictionary<string, string>? Headers { get; set; }
}
