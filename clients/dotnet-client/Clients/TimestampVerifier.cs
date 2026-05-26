using MERSEL.Services.DssVerifier.Client.Interfaces;
using MERSEL.Services.DssVerifier.Client.Internal;
using MERSEL.Services.DssVerifier.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssVerifier.Client.Clients;

/// <summary>
/// Standalone RFC 3161 zaman damgası doğrulama operasyonlarını DSS Verifier
/// mikroservisi üzerinden gerçekleştiren HTTP istemcisi.
/// </summary>
internal sealed class TimestampVerifier : DssVerifierHttpBase, ITimestampVerifier
{
    public TimestampVerifier(HttpClient httpClient, ILogger<TimestampVerifier> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<TimestampVerificationResult> VerifyAsync(byte[] timestampToken, CancellationToken ct = default)
        => VerifyAsync(new VerifyTimestampRequest { TimestampToken = timestampToken }, ct);

    /// <inheritdoc />
    public Task<TimestampVerificationResult> VerifyAsync(
        byte[] timestampToken,
        byte[] originalData,
        CancellationToken ct = default)
        => VerifyAsync(new VerifyTimestampRequest
        {
            TimestampToken = timestampToken,
            OriginalData = originalData
        }, ct);

    /// <inheritdoc />
    public async Task<TimestampVerificationResult> VerifyAsync(
        VerifyTimestampRequest request,
        CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (request.TimestampToken is null || request.TimestampToken.Length == 0)
            throw new ArgumentException("Zaman damgası token içeriği boş olamaz.", nameof(request));

        Logger.LogDebug(
            "DSS Verifier timestamp isteği — token: {Token} bayt, originalData: {HasData}, validateCert: {ValidateCert}",
            request.TimestampToken.Length,
            request.OriginalData is not null,
            request.ValidateCertificate);

        using var form = new MultipartFormDataContent();
        AddFilePart(form, "timestampFile", request.TimestampToken, request.TimestampFileName);
        if (request.OriginalData is { Length: > 0 })
        {
            AddFilePart(form, "originalData", request.OriginalData, request.OriginalDataFileName);
        }
        AddStringPart(form, "validateCertificate", request.ValidateCertificate ? "true" : "false");

        return await PostMultipartJsonAsync<TimestampVerificationResult>(
            "api/v1/verify/timestamp", form, ct).ConfigureAwait(false);
    }
}
