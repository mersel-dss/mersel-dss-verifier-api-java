using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models.Enums;

/// <summary>
/// Bir imzanın sertifika zincirinin (leaf + intermediate CA'lar) revocation
/// durumunu özetleyen kompakt enum.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="VerificationLevel.SIMPLE"/> mod response'unda da görünür — tüketici
/// COMPREHENSIVE moda geçmek zorunda kalmadan zincirin geneline dair tek bakışta
/// doğru karar verebilsin diye eklenmiştir. Payload boyu maliyeti tek bir string.
/// </para>
/// <para>
/// <b>Önemli kavramsal not</b>: Bu alan <em>doğrulama kararını</em> etkilemez.
/// DSS policy zaten zincirin tamamını kendi kuralları çerçevesinde kontrol eder.
/// Bu enum yalnız operatöre / UI'a sade bir özet sinyali sunar.
/// </para>
/// <para>
/// <b>Seçim mantığı</b> (önceliğe göre):
/// <list type="number">
///   <item>Hiç revocation verisi yoksa (çevrimdışı mod, B-level imza, vb.) → <see cref="NOT_CHECKED"/>.</item>
///   <item>Leaf REVOKED ise → <see cref="LEAF_REVOKED"/>.</item>
///   <item>Leaf UNKNOWN ise → <see cref="UNKNOWN"/>.</item>
///   <item>Leaf GOOD ve ara CA'lardan biri REVOKED ise → <see cref="LEAF_GOOD_CA_REVOKED"/>.</item>
///   <item>Leaf GOOD ve bir veya daha fazla CA için UNKNOWN (REVOKED yok) → <see cref="UNKNOWN"/>.</item>
///   <item>Tüm zincir GOOD → <see cref="ALL_GOOD"/>.</item>
/// </list>
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ChainRevocationStatus
{
    /// <summary>
    /// Zincirdeki tüm sertifikalar revocation kontrolünden GOOD geçti.
    /// En arzu edilen durum.
    /// </summary>
    ALL_GOOD,

    /// <summary>
    /// İmzacı (leaf) sertifika REVOKED. CA seviyesinin durumuna bakılmaksızın
    /// en kritik sinyal — imza üzerinde güvenle iş yapılmamalı.
    /// </summary>
    LEAF_REVOKED,

    /// <summary>
    /// İmzacı sertifika GOOD, fakat zincirde bir veya daha fazla ara CA REVOKED.
    /// <c>signer-strict</c> policy'sinde imza yine de geçerli sayılır
    /// (CA için <c>NotRevoked=WARN</c>); <c>strict</c> policy'sinde imza
    /// geçersiz olur (CA için <c>NotRevoked=FAIL</c>). Operatör politika tercihini
    /// bu sinyale göre değerlendirmelidir.
    /// </summary>
    LEAF_GOOD_CA_REVOKED,

    /// <summary>
    /// Zincirde bir veya daha fazla sertifika için durum UNKNOWN — responder cevap
    /// verdi ama "iptal mi bilmiyorum" dedi. Politika seviyesinde değerlendirme yapılmalı.
    /// </summary>
    UNKNOWN,

    /// <summary>
    /// Hiçbir sertifika için revocation kontrolü yapılamadı veya yapılmadı.
    /// Çevrimdışı mod, B-level imza ve gömülü revocation yok, ya da responder
    /// erişilemez durumlarında ortaya çıkar.
    /// </summary>
    NOT_CHECKED
}
