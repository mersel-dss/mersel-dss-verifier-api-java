using MERSEL.Services.DssVerifier.Client.Interfaces;

namespace MERSEL.Services.DssVerifier.Client;

/// <summary>
/// MERSEL DSS Verifier API mikroservisinin tüm domain'lerini tek bir cephe arkasından
/// erişilebilir kılan birleşik istemci. <see cref="IDssVerifierClient"/>'ı uygular.
/// </summary>
/// <remarks>
/// Genellikle
/// <see cref="DependencyInjection.AddDssVerifierClient(Microsoft.Extensions.DependencyInjection.IServiceCollection, Microsoft.Extensions.Configuration.IConfiguration, string)"/>
/// ile DI'ye kaydedilir; tüketici kodda doğrudan <see cref="IDssVerifierClient"/>
/// olarak inject edilir.
/// </remarks>
public sealed class DssVerifierClient : IDssVerifierClient
{
    /// <inheritdoc />
    public ISignatureVerifier Signatures { get; }

    /// <inheritdoc />
    public ITimestampVerifier Timestamps { get; }

    /// <inheritdoc />
    public IHealthClient Health { get; }

    public DssVerifierClient(
        ISignatureVerifier signatures,
        ITimestampVerifier timestamps,
        IHealthClient health)
    {
        Signatures = signatures ?? throw new ArgumentNullException(nameof(signatures));
        Timestamps = timestamps ?? throw new ArgumentNullException(nameof(timestamps));
        Health = health ?? throw new ArgumentNullException(nameof(health));
    }
}
