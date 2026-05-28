using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// Mersel DSS Verifier'ın bir imza üzerinde DSS'in kararını <strong>bilinçli olarak
/// override ettiği</strong> (INVALID → VALID elevate) her durum için yapılandırılmış kayıt.
/// </summary>
/// <remarks>
/// <para>
/// İlke: bizim verifier "DSS dedi ki invalid, biz diyoruz ki valid" tarzı her kararı
/// <em>açık ve makine-okunaklı</em> şekilde raporlar. Audit, compliance ve
/// operasyonel görünürlük için kritik:
/// </para>
/// <list type="bullet">
///   <item><b>Audit</b>: regülatör veya kurumsal müşteri "bu imza neden VALID gösterildi?"
///         diye sorduğunda response içinde kanıt + sebep var.</item>
///   <item><b>Observability</b>: <see cref="Code"/> alanı Prometheus metric label'ı
///         ya da log filter olarak kullanılabilir.</item>
///   <item><b>Support</b>: kullanıcı support ticket'ında kod referans verir,
///         dökümentasyon URL'si tek tıkla erişilebilir.</item>
/// </list>
/// <para>
/// <b>SignatureInfo.Valid</b>: bu liste dolu olsa bile imzanın
/// <see cref="SignatureInfo.Valid"/> alanı <c>true</c> kalır — suppression'lar
/// verdict'i elevate eder.
/// </para>
/// </remarks>
/// <seealso cref="Enums.SuppressionCode"/>
public sealed class AppliedSuppression
{
    /// <summary>
    /// Kararlı, makine-okunaklı kod
    /// (örn. <c>MDSS-XADES-LEGACY-TR-TYPE-URI</c>).
    /// Bilinen değerler için bkz. <see cref="Enums.SuppressionCode"/>.
    /// </summary>
    [JsonPropertyName("code")]
    public string? Code { get; set; }

    /// <summary>İnsan-okunaklı kısa başlık (operatör dashboard'larında listelenebilir).</summary>
    [JsonPropertyName("title")]
    public string? Title { get; set; }

    /// <summary>Türkçe, son kullanıcıya / operatöre yönelik açıklayıcı metin. "Niye geçti?" cevabı.</summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    /// <summary>
    /// Override'ın güvenlik etkisi:
    /// <list type="bullet">
    ///   <item><c>INFO</c>     — tasarımdan sapma ama güvenlik etkisi yok.</item>
    ///   <item><c>WARN</c>     — operatörün dikkat etmesi önerilir.</item>
    ///   <item><c>CRITICAL</c> — operatör eylem almalı (gelecekte).</item>
    /// </list>
    /// </summary>
    [JsonPropertyName("severity")]
    public string? Severity { get; set; }

    /// <summary>
    /// DSS'in <em>orijinal</em> indication'ı (override öncesi). Audit için:
    /// "DSS aslında ne demişti, biz ne yaptık" sorusuna kesin cevap.
    /// </summary>
    [JsonPropertyName("originalIndication")]
    public string? OriginalIndication { get; set; }

    /// <summary>DSS'in orijinal subIndication'ı (override öncesi).</summary>
    [JsonPropertyName("originalSubIndication")]
    public string? OriginalSubIndication { get; set; }

    /// <summary>
    /// Override'ı tetikleyen somut delil. Free-form key/value; her
    /// <see cref="Code"/>'a göre içeriği değişir.
    /// İstemcinin bu içeriği parse'lerken koda göre branch etmesi beklenir.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Deserialize davranışı</b>: <c>System.Text.Json</c> her değeri
    /// <see cref="System.Text.Json.JsonElement"/> olarak deserialize eder
    /// (target tip <c>object</c> olduğu için). Primitive erişim için
    /// <c>elem.GetString()</c>, <c>elem.GetInt64()</c>, <c>elem.GetBoolean()</c>
    /// vb. çağırın. Nesne/dizi erişimi için <c>elem.EnumerateObject()</c>
    /// veya <c>elem.EnumerateArray()</c> kullanın.
    /// </para>
    /// <example>
    /// <code>
    /// // MDSS-XADES-LEGACY-TR-TYPE-URI için tipik delil:
    /// var uri = supp.Evidence?.TryGetValue("detectedTypeUri", out var v) == true
    ///     ? ((JsonElement)v).GetString()
    ///     : null;
    /// </code>
    /// </example>
    /// </remarks>
    [JsonPropertyName("evidence")]
    public Dictionary<string, object>? Evidence { get; set; }

    /// <summary>
    /// Bu kod için Mersel docs URL'i. Operatör tek tıkla detaylı sebebi + tolerans
    /// kuralını + kapatma yönergesini görür.
    /// </summary>
    [JsonPropertyName("docsUrl")]
    public string? DocsUrl { get; set; }

    // ─────────────────────────────────────────────────────────────────────────
    // Audit metadata (tolerance gate v2.0+). Forensic-grade kayıt için her
    // override kararına eklenir. Sunucu Jackson NON_NULL ile null alanları
    // gizler — eski sürümlerle deserialize uyumluluğu korunur.
    // ─────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Tolerance gate'inin <em>sürüm</em> kodu. Pipeline mantığı değiştikçe
    /// artar (örn. <c>"v2.0"</c>); audit reviewer'ı geriye dönük olarak
    /// "bu kayıt hangi gate sıkılığıyla üretildi?" sorusuna cevap verebilir.
    /// </summary>
    /// <remarks>
    /// Bir sonraki gate sürümünde sabit artırılırsa, eski kayıtlardaki versiyon
    /// string'i dokunulmaz kalır — tarihsel forensic için.
    /// </remarks>
    [JsonPropertyName("gateVersion")]
    public string? GateVersion { get; set; }

    /// <summary>
    /// Tolerance gate'inin pozitif tarafta beklediği <strong>tek izinli FAIL
    /// constraint key</strong> set'i (örn. <c>["BBB_SAV_ISQPMDOSPP"]</c>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Bu set <em>dışında</em> herhangi bir BBB bloğunda NOT_OK constraint
    /// varsa gate kapanır. Audit için kritik: yarın gate sıkılığı azalırsa
    /// (set genişlerse) eski kayıtlarda hangi izin verilenler varmış kanıtı
    /// kalır.
    /// </para>
    /// <para>
    /// Sunucuda <c>Set&lt;String&gt;</c> olarak modellenmiştir; .NET tarafında
    /// JSON array <see cref="List{T}"/> olarak deserialize edilir (uniqueness
    /// kontratı sunucu tarafında korunur, istemci yalnız okur).
    /// </para>
    /// </remarks>
    [JsonPropertyName("allowedFailureKeys")]
    public List<string>? AllowedFailureKeys { get; set; }

    /// <summary>
    /// Gate inceleme sırasında <strong>fiilen gözlenen</strong> tüm BBB FAIL
    /// constraint key'lerinin set'i (FC/ISC/VCI/CV/SAV/XCV-top/SubXCV/PSV
    /// bloklarının birleşimi).
    /// </summary>
    /// <remarks>
    /// Tolerance uygulandığı için bu set <see cref="AllowedFailureKeys"/>'in
    /// alt-kümesidir. Saldırı ya da regresyon tespiti için: operatör bu set'i
    /// incelediğinde "DSS hangi constraint'lerle INVALID dedi?" sorusuna
    /// birebir cevap alır.
    /// </remarks>
    [JsonPropertyName("observedFailureKeys")]
    public List<string>? ObservedFailureKeys { get; set; }

    /// <summary>
    /// Doğrulamaya giren <em>imzalı doküman</em> byte'larının SHA-256 hash'i
    /// (hex). Forensic dispute'ta "tam olarak hangi byte dizisi tolere edildi?"
    /// sorusunun cevabı; receiver başka kaynaktan aldığı kopyayla hash
    /// karşılaştırabilir.
    /// </summary>
    /// <remarks>
    /// ECDSA preprocessor sonrası halini ifade eder (gate tam o byte dizisi
    /// üzerinde karar verdiği için).
    /// </remarks>
    [JsonPropertyName("documentSha256")]
    public string? DocumentSha256 { get; set; }

    /// <summary>
    /// Doğrulamaya giren imzalı doküman byte uzunluğu (preprocess sonrası).
    /// Pratik dispute ve sızdırma tespitinde hash ile birlikte ikincil sinyal —
    /// aynı hash farklı uzunluk teorik olarak imkânsız ama forensic format/encoding
    /// ipucu sağlar.
    /// </summary>
    [JsonPropertyName("documentSizeBytes")]
    public long? DocumentSizeBytes { get; set; }
}
