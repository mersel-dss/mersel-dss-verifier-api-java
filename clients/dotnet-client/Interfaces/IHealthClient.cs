using MERSEL.Services.DssVerifier.Client.Models;

namespace MERSEL.Services.DssVerifier.Client.Interfaces;

/// <summary>
/// Sağlık kontrolü ve servis meta-bilgisi operasyonları.
/// <c>GET /api/v1/health</c> ve <c>GET /api/v1/info</c> endpoint'lerine eşlenir.
/// </summary>
/// <remarks>
/// Production'da Kubernetes liveness/readiness probe'larında genellikle Spring
/// Boot Actuator'ın <c>/actuator/health</c> ucu (port 8086 +
/// <c>management.endpoints.web.exposure.include=health</c>) kullanılır;
/// burada exposed olan <c>/api/v1/health</c> kullanıcı tarafına dönük
/// hafif, açıklayıcı bir sağlık özetidir.
/// </remarks>
public interface IHealthClient
{
    /// <summary>
    /// Servisin canlı olup olmadığını ve versiyonunu döndürür.
    /// </summary>
    Task<HealthInfo> GetHealthAsync(CancellationToken ct = default);

    /// <summary>
    /// Servis adı, versiyonu, açıklaması ve desteklenen özelliklerin listesini döndürür.
    /// </summary>
    Task<ServiceInfo> GetInfoAsync(CancellationToken ct = default);
}
