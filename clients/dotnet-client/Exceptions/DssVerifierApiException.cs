using System.Net;
using MERSEL.Services.DssVerifier.Client.Models;

namespace MERSEL.Services.DssVerifier.Client.Exceptions;

/// <summary>
/// DSS Verifier API'sinden başarısız bir HTTP yanıtı geldiğinde fırlatılır.
/// Sunucunun döndürdüğü yapılandırılmış <see cref="DssVerifierError"/>
/// (varsa) <see cref="ApiError"/> üzerinden erişilebilir.
/// </summary>
/// <remarks>
/// <para>
/// <b>Önemli</b>: Bu exception yalnız taşıma katmanı / sunucu hatalarında atılır.
/// İmza doğrulamasının "imza geçersiz" sonucu vermesi <em>hata değildir</em> — bu
/// durumda HTTP 200 + <see cref="VerificationResult.Valid"/> = <c>false</c> döner;
/// çağıran kod <see cref="VerificationResult.Errors"/>, <see cref="SignatureInfo.AppliedRejections"/>
/// vb. alanları inceleyerek karar verir.
/// </para>
/// </remarks>
public sealed class DssVerifierApiException : Exception
{
    /// <summary>HTTP durum kodu.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Sunucu yanıtının deserialize edilmiş hata gövdesi (varsa).</summary>
    public DssVerifierError? ApiError { get; }

    /// <summary>Sunucu yanıtının ham gövdesi (yapılandırılmış parse başarısız olduysa loglama için).</summary>
    public string? RawBody { get; }

    /// <summary>İstek atılan endpoint yolu (debug/log amaçlı).</summary>
    public string? RequestPath { get; }

    public DssVerifierApiException(
        HttpStatusCode statusCode,
        string message,
        DssVerifierError? apiError = null,
        string? rawBody = null,
        string? requestPath = null,
        Exception? innerException = null)
        : base(message, innerException)
    {
        StatusCode = statusCode;
        ApiError = apiError;
        RawBody = rawBody;
        RequestPath = requestPath;
    }
}
