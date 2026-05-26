namespace MERSEL.Services.DssVerifier.Client.Models;

/// <summary>
/// İstemci yapılandırma seçenekleri. <c>appsettings.json</c> ya da kod ile bağlanır.
/// </summary>
public sealed class DssVerifierClientOptions
{
    /// <summary>Yapılandırma kök bölümü (default <c>Services:DssVerifier</c>).</summary>
    public const string DefaultConfigurationSection = "Services:DssVerifier";

    /// <summary>HTTP istemcisinin kullanacağı isimli client adı.</summary>
    public const string HttpClientName = "MERSEL.Services.DssVerifier";

    /// <summary>
    /// DSS Verifier mikroservisinin temel URL'i. Sonunda <c>/</c> olmasına gerek yok.
    /// Örn. <c>http://dss-verifier:8086</c>.
    /// </summary>
    public string BaseUrl { get; set; } = "http://localhost:8086";

    /// <summary>
    /// İstek zaman aşımı. COMPREHENSIVE doğrulama, büyük imzalı PDF / multi-MB
    /// XAdES belgeleri veya yavaş OCSP/CRL kaynakları olan ortamlarda 2-5 dakikaya
    /// çekilmesi önerilir. Varsayılan: 2 dakika.
    /// </summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Custom <c>User-Agent</c> başlığı. Varsayılan paket adı + sürümünden üretilir.
    /// </summary>
    /// <remarks>
    /// Sunucu authentication uygulamaz (internal/gateway arkası mimari); herhangi bir
    /// ek header (API gateway anahtarı, korelasyon kimliği vb.) eklemek için
    /// <c>AddDssVerifierClient(...)</c> sonrası
    /// <see cref="Microsoft.Extensions.DependencyInjection.IHttpClientBuilder"/>
    /// üzerinden <c>ConfigureHttpClient</c> ya da <c>AddHttpMessageHandler</c> kullanın.
    /// </remarks>
    public string? UserAgent { get; set; }
}
