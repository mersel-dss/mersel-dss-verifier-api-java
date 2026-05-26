using System.Net.Http.Headers;
using System.Reflection;
using MERSEL.Services.DssVerifier.Client.Clients;
using MERSEL.Services.DssVerifier.Client.Interfaces;
using MERSEL.Services.DssVerifier.Client.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace MERSEL.Services.DssVerifier.Client;

/// <summary>
/// MERSEL DSS Verifier API istemci SDK'sı için DI uzantı metotları.
/// Tek satırlık <c>AddDssVerifierClient</c> çağrısıyla tüm sub-client'lar
/// (<see cref="ISignatureVerifier"/>, <see cref="ITimestampVerifier"/>,
/// <see cref="IHealthClient"/>) ve aggregator <see cref="IDssVerifierClient"/>
/// servis koleksiyonuna kaydedilir.
/// </summary>
public static class DependencyInjection
{
    /// <summary>
    /// İstemci SDK'sını <c>IConfiguration</c> üzerinden okuyarak DI'ye kaydeder.
    /// </summary>
    /// <param name="services">Servis koleksiyonu.</param>
    /// <param name="configuration">Konfigürasyon kaynağı.</param>
    /// <param name="sectionName">
    /// Bağlanılacak konfigürasyon bölümü.
    /// Varsayılan: <see cref="DssVerifierClientOptions.DefaultConfigurationSection"/> (<c>Services:DssVerifier</c>).
    /// </param>
    /// <example>
    /// <code>
    /// // appsettings.json
    /// {
    ///   "Services": {
    ///     "DssVerifier": {
    ///       "BaseUrl": "http://dss-verifier:8086",
    ///       "Timeout": "00:02:00"
    ///     }
    ///   }
    /// }
    ///
    /// // Program.cs
    /// builder.Services.AddDssVerifierClient(builder.Configuration);
    /// </code>
    /// </example>
    public static IServiceCollection AddDssVerifierClient(
        this IServiceCollection services,
        IConfiguration configuration,
        string sectionName = DssVerifierClientOptions.DefaultConfigurationSection)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        services.AddOptions<DssVerifierClientOptions>()
            .Bind(configuration.GetSection(sectionName))
            .Validate(o => !string.IsNullOrWhiteSpace(o.BaseUrl),
                $"DssVerifierClientOptions.BaseUrl '{sectionName}:BaseUrl' anahtarı zorunludur.");

        return AddDssVerifierClientCore(services);
    }

    /// <summary>
    /// İstemci SDK'sını doğrudan kod ile yapılandırarak DI'ye kaydeder.
    /// </summary>
    /// <param name="services">Servis koleksiyonu.</param>
    /// <param name="configure">Seçenekleri yapılandıran delegate.</param>
    /// <example>
    /// <code>
    /// builder.Services.AddDssVerifierClient(o =>
    /// {
    ///     o.BaseUrl = "http://dss-verifier:8086";
    ///     o.Timeout = TimeSpan.FromMinutes(5);
    /// });
    /// </code>
    /// </example>
    public static IServiceCollection AddDssVerifierClient(
        this IServiceCollection services,
        Action<DssVerifierClientOptions> configure)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configure is null) throw new ArgumentNullException(nameof(configure));

        services.AddOptions<DssVerifierClientOptions>()
            .Configure(configure)
            .Validate(o => !string.IsNullOrWhiteSpace(o.BaseUrl),
                "DssVerifierClientOptions.BaseUrl zorunludur.");

        return AddDssVerifierClientCore(services);
    }

    /// <summary>
    /// Sadece taban URL belirterek hızlıca DI'ye kayıt yapan kısa yol overload'ı.
    /// </summary>
    public static IServiceCollection AddDssVerifierClient(
        this IServiceCollection services,
        string baseUrl)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
            throw new ArgumentException("BaseUrl boş olamaz.", nameof(baseUrl));

        return services.AddDssVerifierClient(o => o.BaseUrl = baseUrl);
    }

    // ── Çekirdek kayıt: tüm typed-client'ların ortak HTTP client'ı paylaşmasını sağlar ──

    private static IServiceCollection AddDssVerifierClientCore(IServiceCollection services)
    {
        services.AddHttpClient(DssVerifierClientOptions.HttpClientName, ConfigureHttpClient);

        // Sub-client'lar; hepsi aynı HttpClient'ı (HttpClientFactory üzerinden) kullanır.
        services.TryAddTransient<ISignatureVerifier>(sp => CreateClient<SignatureVerifier>(sp));
        services.TryAddTransient<ITimestampVerifier>(sp => CreateClient<TimestampVerifier>(sp));
        services.TryAddTransient<IHealthClient>(sp => CreateClient<HealthClient>(sp));

        services.TryAddTransient<IDssVerifierClient, DssVerifierClient>();

        return services;
    }

    private static T CreateClient<T>(IServiceProvider sp) where T : class
    {
        var factory = sp.GetRequiredService<IHttpClientFactory>();
        var http = factory.CreateClient(DssVerifierClientOptions.HttpClientName);
        var loggerFactory = sp.GetRequiredService<ILoggerFactory>();
        var logger = loggerFactory.CreateLogger<T>();

        // İki argüman alan ctor'ı (HttpClient, ILogger<T>) bul ve çağır.
        return (T)Activator.CreateInstance(typeof(T), http, logger)!;
    }

    private static void ConfigureHttpClient(IServiceProvider sp, HttpClient http)
    {
        var options = sp.GetRequiredService<IOptions<DssVerifierClientOptions>>().Value;

        var baseUrl = options.BaseUrl?.TrimEnd('/') ?? string.Empty;
        if (string.IsNullOrEmpty(baseUrl))
        {
            throw new InvalidOperationException(
                "DssVerifierClientOptions.BaseUrl yapılandırılmamış. " +
                $"'{DssVerifierClientOptions.DefaultConfigurationSection}:BaseUrl' anahtarını ayarlayın " +
                "veya AddDssVerifierClient(...) çağrısında belirtin.");
        }

        http.BaseAddress = new Uri(baseUrl + "/");
        http.Timeout = options.Timeout > TimeSpan.Zero
            ? options.Timeout
            : TimeSpan.FromMinutes(2);

        // Authentication: Sunucu kendisi auth yapmaz (internal/gateway arkası mimari).
        // Kullanıcı API gateway arkasına koyduğunda ekstra header'ları kendi
        // ConfigureHttpClient / AddHttpMessageHandler zincirinde ekler.

        // User-Agent: paket adı + sürüm.
        var userAgent = options.UserAgent ?? BuildDefaultUserAgent();
        if (!string.IsNullOrEmpty(userAgent))
        {
            http.DefaultRequestHeaders.UserAgent.Clear();
            // Tek parça olarak ekleriz; karmaşık formatlama gerekmez.
            http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", userAgent);
        }

        // application/json tercihen okunsun.
        http.DefaultRequestHeaders.Accept.Clear();
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json", 0.9));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*", 0.1));
    }

    private static string BuildDefaultUserAgent()
    {
        var asm = typeof(DependencyInjection).Assembly;
        var name = asm.GetName().Name ?? "MERSEL.Services.DssVerifier.Client";
        var version = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
                      ?? asm.GetName().Version?.ToString()
                      ?? "0.0.0";
        // SourceLink commit suffix'lerini temizle.
        var plus = version.IndexOf('+');
        if (plus > 0) version = version.Substring(0, plus);
        return $"{name}/{version}";
    }
}
