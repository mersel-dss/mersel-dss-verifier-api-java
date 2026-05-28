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
    /// Her imza ve zaman damgası için tüm BBB FAIL constraint'leri
    /// (<see cref="FailureCategory.ROOT_CAUSE"/> + <see cref="FailureCategory.DERIVED"/> +
    /// <see cref="FailureCategory.CASCADE"/>) <see cref="SignatureInfo.FailedConstraints"/>
    /// ve <see cref="TimestampInfo.FailedConstraints"/> alanlarına eklensin mi?
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Varsayılan: <c>false</c></b> — alan response'ta hiç görünmez; operatör
    /// yalnız tek bir <see cref="SignatureInfo.RootCause"/> görür (frontend
    /// dispatch için yeterli, kontrat dar). Bu kontratın varsayılan davranışı
    /// %99 senaryoda doğrudur.
    /// </para>
    /// <para>
    /// <b><c>true</c> verildiğinde</b>: her imza ve zaman damgasına kategorize
    /// tam liste eklenir — audit/forensic akışları, "neden bu satır
    /// <see cref="FailureCategory.ROOT_CAUSE"/> seçildi?" incelemesi veya
    /// gelişmiş detay paneli için.
    /// <see cref="SignatureInfo.RootCause"/> alanı zaten her zaman dolu olduğundan,
    /// opt-in işlemi <em>ek</em> detay sağlar; mevcut response alanlarının
    /// semantiğini değiştirmez.
    /// </para>
    /// <para>
    /// Sunucu tarafında <c>?includeFailedConstraints=true</c> query parameter
    /// (multipart için form field) olarak iletilir.
    /// </para>
    /// </remarks>
    /// <seealso cref="SignatureInfo.FailedConstraints"/>
    /// <seealso cref="TimestampInfo.FailedConstraints"/>
    /// <seealso cref="FailureCategory"/>
    public bool IncludeFailedConstraints { get; set; } = false;

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
