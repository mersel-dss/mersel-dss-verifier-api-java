using MERSEL.Services.DssVerifier.Client.Interfaces;
using MERSEL.Services.DssVerifier.Client.Internal;
using MERSEL.Services.DssVerifier.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssVerifier.Client.Clients;

/// <summary>
/// Sağlık kontrolü ve servis meta-bilgisi sorgulama operasyonları.
/// </summary>
internal sealed class HealthClient : DssVerifierHttpBase, IHealthClient
{
    public HealthClient(HttpClient httpClient, ILogger<HealthClient> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<HealthInfo> GetHealthAsync(CancellationToken ct = default)
        => GetJsonAsync<HealthInfo>("api/v1/health", ct);

    /// <inheritdoc />
    public Task<ServiceInfo> GetInfoAsync(CancellationToken ct = default)
        => GetJsonAsync<ServiceInfo>("api/v1/info", ct);
}
