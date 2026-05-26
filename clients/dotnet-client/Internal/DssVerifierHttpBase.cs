using System.Text.Json;
using MERSEL.Services.DssVerifier.Client.Exceptions;
using MERSEL.Services.DssVerifier.Client.Models;
using Microsoft.Extensions.Logging;

namespace MERSEL.Services.DssVerifier.Client.Internal;

/// <summary>
/// Tüm sub-client'ların paylaştığı HTTP/multipart yardımcı tabanı.
/// Hata gövdesi parse, multipart inşa ve JSON deserialize işlemleri burada toplandı.
/// </summary>
internal abstract class DssVerifierHttpBase
{
    /// <summary>Tüm yanıtlarda kullanılan ortak JSON ayarları.</summary>
    protected static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    protected readonly HttpClient HttpClient;
    protected readonly ILogger Logger;

    protected DssVerifierHttpBase(HttpClient httpClient, ILogger logger)
    {
        HttpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    // ── Multipart yardımcıları ──────────────────────────────────────

    /// <summary>
    /// Verilen byte içeriği için form alanı (file part) inşa eder.
    /// API tarafında <c>MultipartFile</c> olarak okunan alanlarda kullanılır.
    /// </summary>
    protected static void AddFilePart(
        MultipartFormDataContent form,
        string name,
        byte[] content,
        string fileName,
        string mediaType = "application/octet-stream")
    {
        var part = new ByteArrayContent(content);
        part.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue(mediaType);
        form.Add(part, name, fileName);
    }

    /// <summary>
    /// Verilen string için düz form alanı ekler.
    /// API tarafında <c>@RequestParam</c> tek değer alanlarına bağlanır.
    /// </summary>
    protected static void AddStringPart(
        MultipartFormDataContent form,
        string name,
        string? value)
    {
        if (value is null) return;
        form.Add(new StringContent(value), name);
    }

    // ── İstek/yanıt çağrıları ───────────────────────────────────────

    /// <summary>
    /// JSON yanıtı bekleyen GET istekleri için yardımcı.
    /// </summary>
    protected async Task<T> GetJsonAsync<T>(string path, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        using var response = await HttpClient.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

        await EnsureSuccessAsync(response, path, ct).ConfigureAwait(false);
        return await ReadJsonAsync<T>(response, path, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// JSON yanıtı bekleyen POST(multipart) istekleri için yardımcı.
    /// </summary>
    protected async Task<T> PostMultipartJsonAsync<T>(
        string path,
        MultipartFormDataContent content,
        CancellationToken ct)
    {
        using var response = await HttpClient.PostAsync(path, content, ct).ConfigureAwait(false);
        await EnsureSuccessAsync(response, path, ct).ConfigureAwait(false);
        return await ReadJsonAsync<T>(response, path, ct).ConfigureAwait(false);
    }

    // ── Hata/Yanıt parse ────────────────────────────────────────────

    /// <summary>
    /// Başarısız HTTP yanıtlarında, eğer mümkünse <see cref="DssVerifierError"/>
    /// gövdesini parse edip <see cref="DssVerifierApiException"/> fırlatır.
    /// </summary>
    protected async Task EnsureSuccessAsync(HttpResponseMessage response, string path, CancellationToken ct)
    {
        if (response.IsSuccessStatusCode) return;

        string? rawBody = null;
        DssVerifierError? structuredError = null;

        try
        {
            rawBody = await ReadStringAsync(response.Content, ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(rawBody) &&
                (BodyLooksLikeJson(rawBody) ||
                 MediaTypeIsJson(response.Content.Headers.ContentType?.MediaType)))
            {
                structuredError = JsonSerializer.Deserialize<DssVerifierError>(rawBody, JsonOptions);
            }
        }
        catch (Exception ex)
        {
            Logger.LogDebug(ex, "DssVerifier hata gövdesi parse edilemedi (path: {Path})", path);
        }

        var msg = structuredError?.Message
                  ?? structuredError?.Error
                  ?? rawBody
                  ?? response.ReasonPhrase
                  ?? $"DSS Verifier API HTTP {(int)response.StatusCode}";

        throw new DssVerifierApiException(
            response.StatusCode,
            $"DSS Verifier API '{path}' başarısız (HTTP {(int)response.StatusCode}): {msg}",
            structuredError,
            rawBody,
            path);
    }

    private static bool MediaTypeIsJson(string? mediaType)
    {
        if (string.IsNullOrEmpty(mediaType)) return false;
        return mediaType!.IndexOf("json", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool BodyLooksLikeJson(string body)
    {
        // Cheap heuristic — used as fallback when Content-Type missing/wildcard.
        var trimmed = body.TrimStart();
        return trimmed.StartsWith("{", StringComparison.Ordinal)
               || trimmed.StartsWith("[", StringComparison.Ordinal);
    }

    private static async Task<string> ReadStringAsync(HttpContent content, CancellationToken ct)
    {
#if NET6_0_OR_GREATER
        return await content.ReadAsStringAsync(ct).ConfigureAwait(false);
#else
        return await content.ReadAsStringAsync().ConfigureAwait(false);
#endif
    }

    /// <summary>
    /// JSON yanıtı verilen tipe deserialize eder. Boş gövde durumunda
    /// <see cref="DssVerifierApiException"/> fırlatır.
    /// </summary>
    private async Task<T> ReadJsonAsync<T>(HttpResponseMessage response, string path, CancellationToken ct)
    {
#if NET6_0_OR_GREATER
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#else
        using var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
        try
        {
            var result = await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, ct).ConfigureAwait(false);
            if (result is null)
            {
                throw new DssVerifierApiException(
                    response.StatusCode,
                    $"DSS Verifier API '{path}' boş JSON yanıtı döndürdü.",
                    requestPath: path);
            }
            return result;
        }
        catch (JsonException ex)
        {
            throw new DssVerifierApiException(
                response.StatusCode,
                $"DSS Verifier API '{path}' yanıtı deserialize edilemedi: {ex.Message}",
                requestPath: path,
                innerException: ex);
        }
    }
}
