using MERSEL.Services.DssVerifier.Client.Interfaces;
using MERSEL.Services.DssVerifier.Client.Internal;
using MERSEL.Services.DssVerifier.Client.Models;
using MERSEL.Services.DssVerifier.Client.Models.Enums;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssVerifier.Client.Clients;

/// <summary>
/// XAdES, PAdES ve CAdES imza doğrulama operasyonlarını DSS Verifier
/// mikroservisi üzerinden gerçekleştiren HTTP istemcisi.
/// </summary>
internal sealed class SignatureVerifier : DssVerifierHttpBase, ISignatureVerifier
{
    public SignatureVerifier(HttpClient httpClient, ILogger<SignatureVerifier> logger)
        : base(httpClient, logger)
    {
    }

    /// <inheritdoc />
    public Task<VerificationResult> VerifyAsync(
        byte[] signedDocument,
        VerificationLevel level = VerificationLevel.SIMPLE,
        CancellationToken ct = default)
        => VerifyAsync(new VerifySignatureRequest
        {
            SignedDocument = signedDocument,
            Level = level
        }, ct);

    /// <inheritdoc />
    public Task<VerificationResult> VerifyDetachedAsync(
        byte[] signedDocument,
        byte[] originalDocument,
        VerificationLevel level = VerificationLevel.SIMPLE,
        CancellationToken ct = default)
        => VerifyAsync(new VerifySignatureRequest
        {
            SignedDocument = signedDocument,
            OriginalDocument = originalDocument,
            Level = level
        }, ct);

    /// <inheritdoc />
    public async Task<VerificationResult> VerifyAsync(VerifySignatureRequest request, CancellationToken ct = default)
    {
        if (request is null) throw new ArgumentNullException(nameof(request));
        if (request.SignedDocument is null || request.SignedDocument.Length == 0)
            throw new ArgumentException("İmzalı doküman içeriği boş olamaz.", nameof(request));

        Logger.LogDebug(
            "DSS Verifier signature isteği — boyut: {Boyut} bayt, detached: {Detached}, seviye: {Seviye}, includeFailedConstraints: {IncludeFC}",
            request.SignedDocument.Length,
            request.OriginalDocument is not null,
            request.Level,
            request.IncludeFailedConstraints);

        using var form = new MultipartFormDataContent();
        AddFilePart(form, "signedDocument", request.SignedDocument, request.SignedDocumentFileName);
        if (request.OriginalDocument is { Length: > 0 })
        {
            AddFilePart(form, "originalDocument", request.OriginalDocument, request.OriginalDocumentFileName);
        }
        AddStringPart(form, "level", request.Level.ToString());
        // includeFailedConstraints: sunucu tarafında @RequestParam(defaultValue="false")
        // — sadece true verildiğinde gönderiyoruz; default akış multipart payload'ı
        // gereksiz yere şişmesin (sunucu varsayılan davranışı zaten false).
        if (request.IncludeFailedConstraints)
        {
            AddStringPart(form, "includeFailedConstraints", "true");
        }

        return await PostMultipartJsonAsync<VerificationResult>(
            "api/v1/verify/signature", form, ct, request.Headers).ConfigureAwait(false);
    }
}
