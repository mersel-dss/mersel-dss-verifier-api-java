namespace MERSEL.Services.DssVerifier.Client.Interfaces;

/// <summary>
/// MERSEL DSS Verifier API mikroservisinin tüm domain'lerini tek bir cephe (facade)
/// arkasından erişilebilir kılan birleşik istemci sözleşmesi.
/// </summary>
/// <remarks>
/// Tek bir bağımlılık enjeksiyonu ile tüm imza doğrulama (XAdES, PAdES, CAdES),
/// zaman damgası doğrulama ve sağlık kontrolü operasyonlarına erişebilirsiniz.
/// İhtiyacınız tek bir alan ise ilgili sub-interface'i (<see cref="ISignatureVerifier"/>,
/// <see cref="ITimestampVerifier"/> vb.) doğrudan da inject edebilirsiniz.
/// </remarks>
public interface IDssVerifierClient
{
    /// <summary>XAdES, PAdES, CAdES imza doğrulama operasyonları.</summary>
    ISignatureVerifier Signatures { get; }

    /// <summary>Standalone RFC 3161 zaman damgası doğrulama operasyonları.</summary>
    ITimestampVerifier Timestamps { get; }

    /// <summary>Sağlık kontrolü ve servis meta-bilgisi.</summary>
    IHealthClient Health { get; }
}
