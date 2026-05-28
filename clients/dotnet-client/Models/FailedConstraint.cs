using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// DSS DetailedReport içindeki <c>&lt;Constraint Status="NOT_OK"&gt;</c>
/// elementinin yapısal sunumu. ETSI EN 319 102-1 spec dilinde bu objeler
/// <em>failed constraints</em> olarak adlandırılır — DSS Basic Building Blocks
/// (BBB) içinde NOT_OK statüsünde sonuçlanan kontroller.
/// </summary>
/// <remarks>
/// <para>
/// <b>İki farklı görünüm</b>:
/// </para>
/// <list type="bullet">
///   <item>
///     <b><see cref="SignatureInfo.RootCause"/></b> (default, her zaman dolu —
///     varsa): kategori = <see cref="FailureCategory.ROOT_CAUSE"/> olan ilk satır.
///     Frontend dispatch ve operatör eylem mesajı için kullanılır. Tek nesne →
///     operatör tek somut sorun görür. Burada <see cref="Category"/> alanı
///     genellikle <c>null</c> kalır (Jackson NON_NULL ile sunucudan JSON'a
///     da düşmez) — zaten anlam olarak hep ROOT_CAUSE'tur.
///   </item>
///   <item>
///     <b><see cref="SignatureInfo.FailedConstraints"/></b> (opt-in,
///     <c>includeFailedConstraints=true</c>): tüm BBB FAIL constraint'leri —
///     ROOT_CAUSE, DERIVED, CASCADE kategorileriyle birlikte. Audit, forensic
///     ve "neden bu satır seçildi?" sorusunun cevabı için. Burada her satır
///     kendi <see cref="Category"/> bilgisini taşır.
///   </item>
/// </list>
/// <para>
/// <b>Örnek JSON</b>:
/// <code>
/// "rootCause": {
///   "key": "BBB_XCV_ISCGKU",
///   "message": "İmzacı sertifikası, beklenen anahtar kullanım alanına ..."
/// },
/// "failedConstraints": [
///   {
///     "key": "BBB_XCV_ISCGKU",
///     "message": "İmzacı sertifikası, beklenen anahtar kullanım alanına ...",
///     "category": "ROOT_CAUSE"
///   },
///   {
///     "key": "BBB_XCV_SUB",
///     "message": "Is the SubXCV conclusion valid?",
///     "category": "DERIVED"
///   },
///   {
///     "key": "BBB_SAV_ISQPMDOSPP",
///     "message": "Is the signed qualifying property: 'message-digest' ...",
///     "category": "CASCADE"
///   }
/// ]
/// </code>
/// </para>
/// </remarks>
/// <seealso cref="FailureCategory"/>
/// <seealso cref="SignatureInfo.RootCause"/>
/// <seealso cref="SignatureInfo.FailedConstraints"/>
/// <seealso cref="TimestampInfo.RootCause"/>
/// <seealso cref="TimestampInfo.FailedConstraints"/>
public sealed class FailedConstraint
{
    /// <summary>
    /// DSS i18n bundle anahtarı (örn. <c>BBB_XCV_ISCGKU</c>). Locale'den bağımsız;
    /// makine kontratının stabil tarafı. Frontend bu kodu doğrudan dispatch ederek
    /// özel yönlendirme/UI yapabilir (regex ile parse etmek gerekmez).
    /// </summary>
    [JsonPropertyName("key")]
    public string? Key { get; set; }

    /// <summary>
    /// Sunucu locale'inde (default <c>tr</c>) doldurulmuş insan mesajı.
    /// <c>additionalInfo</c> varsa " — " ile eklenir.
    /// </summary>
    [JsonPropertyName("message")]
    public string? Message { get; set; }

    /// <summary>
    /// Constraint'in DSS validation pipeline'ındaki rolü
    /// (<see cref="FailureCategory.ROOT_CAUSE"/>, <see cref="FailureCategory.DERIVED"/>
    /// veya <see cref="FailureCategory.CASCADE"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="SignatureInfo.RootCause"/> / <see cref="TimestampInfo.RootCause"/>
    /// alanlarında dönen tek nesne için sunucu bu alanı doldurmaz (zaten hep
    /// ROOT_CAUSE) — Jackson NON_NULL ile JSON'da görünmez, deserialize sonrası
    /// <c>null</c> kalır.
    /// </para>
    /// <para>
    /// <see cref="SignatureInfo.FailedConstraints"/> /
    /// <see cref="TimestampInfo.FailedConstraints"/> listelerinde her satırın
    /// gerçek kategorisi taşınır.
    /// </para>
    /// </remarks>
    [JsonPropertyName("category")]
    public FailureCategory? Category { get; set; }
}
