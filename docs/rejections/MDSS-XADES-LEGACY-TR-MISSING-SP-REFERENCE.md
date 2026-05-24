# MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE

| Alan | Değer |
|---|---|
| Kod | `MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE` |
| Başlık | XAdES SignedProperties referansı eksik (tek referanslı imza) |
| Severity | `ERROR` |
| Layer | XAdES |
| İlgili enum | [`RejectionCode.MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`AdvancedSignatureVerificationService#evaluateTrLegacyXadesRejection`](../../src/main/java/io/mersel/dss/verify/api/services/verification/AdvancedSignatureVerificationService.java) |
| Detector | [`LegacyTurkishXadesTypeUriDetector` (P3)](../../src/main/java/io/mersel/dss/verify/api/services/util/LegacyTurkishXadesTypeUriDetector.java) |

## Sorunun özeti

Bu rejection kodu, **XAdES imzanın yalnızca bir `<ds:Reference>` taşıdığı —
yani belgenin özeti dışında imzanın kendi kapsamını koruyan ikinci
referansın hiç üretilmediği** vakaları işaretler.

> Sorun şu: imza içindeki veriyi değiştiriyorum ama imza bozulmuyor.
> Çünkü imzada iki referans olması gerekirken yalnızca bir referans var.
> İki referansın biri belgenin özetiyken, diğeri imzanın kendi özeti /
> korumasıdır. Tek referanslı imzalarda örneğin `SigningTime` alanını
> rahatlıkla değiştirebilirsiniz, imza yine doğrulanır. Bu çok büyük bir
> problemdir.

## Eski doğru davranış vs. yeni regresyon

Türkiye e-imza altyapısı yıllardır XAdES imzalarını **iki `<ds:Reference>`
ile** üretiyordu. Bu, ETSI EN 319 132-1 (XAdES-BES) tarafından zorunlu
kılınan ve `xmldsig-core` ile uyumlu olan tek doğru yapıdır. İki referansın
işlevi ayrıdır ve birbirine ikame değildir:

| `ds:Reference` | URI | Koruduğu alan | Tahrifat halinde |
|---|---|---|---|
| 1. | `URI=""` | XML body — `<ds:Signature>` haricindeki tüm doküman | İmza matematik olarak bozulur, doğrulayıcı yakalar. |
| 2. | `URI="#SignedProperties_…"` `Type="…#SignedProperties"` | `<xades:SignedProperties>` — `SigningTime`, `SigningCertificate`, `SignaturePolicyIdentifier`, `SignerRole`, `CommitmentTypeIndication` | İmza matematik olarak bozulur, doğrulayıcı yakalar. |

Bu doğru yapıda XML'in **herhangi bir** alanına dokunulamaz — body'de bir
boşluğun yeri değişse ya da SignedProperties içindeki bir tarih
mikro-saniye düzeyinde modifiye edilse, `SignedInfo` hash'leri patlar
ve `SignatureValue` doğrulanmaz.

Son dönemde gözlenen sapma şudur: bazı imzalama bileşenleri yalnızca
birinci referansı (`URI=""`) üreterek `<xades:SignedProperties>`
elementini imzanın kapsamına dahil etmiyor. Yapı şu hale geliyor:

```xml
<ds:SignedInfo>
  <ds:Reference URI="">                                  <!-- yalnızca body -->
    <ds:Transforms>
      <ds:Transform Algorithm=".../xmldsig#enveloped-signature"/>
    </ds:Transforms>
    <ds:DigestValue>...</ds:DigestValue>
  </ds:Reference>
  <!-- SignedProperties için Reference YOK -->
</ds:SignedInfo>
<ds:Object>
  <xades:QualifyingProperties>
    <xades:SignedProperties Id="SignedProperties_...">
      <xades:SigningTime>...</xades:SigningTime>
      <xades:SigningCertificateV2>...</xades:SigningCertificateV2>
      <xades:SignaturePolicyIdentifier>...</xades:SignaturePolicyIdentifier>
    </xades:SignedProperties>
```

`<xades:SignedProperties>` elementi XML içinde mevcut, ama hiçbir
`<ds:Reference>` bu elemente pointing değil — ne URI fragment'ı
(`#SignedProperties_…`) ile, ne de `Type="…#SignedProperties"` attribute'u
ile. Sonuç: bu alanlar imzanın kriptografik kapsamı **dışında** kalıyor.

## Saldırı yüzeyi

`enveloped-signature` transform'u, ilk referans hash'i hesaplanırken
`<ds:Signature>` elementini hash girdisinden çıkarır. Bu, doğru
tasarımda zorunludur (özyinelemeyi engeller); fakat tek referanslı
yapıda `<ds:Signature>` *içindeki* her şeyin korunmadığı anlamına gelir.
Şu alanlar imza altına alınmadan kalır ve doğrulama aşamasında tespit
edilmeden değiştirilebilir:

| Alan | Tahrifat senaryosu | Pratik etki |
|---|---|---|
| `<xades:SigningTime>` | İmza tarihi ileri/geri alma | Sözleşme tarihi, vergi dönemi, faiz başlangıcı, zamanaşımı manipülasyonu. |
| `<xades:SigningCertificateV2>` | Cert digest'i farklı bir cert'in digest'iyle değiştirme | İmzacı kimliği üzerinde çapraz doğrulama mekanizması iptal olur. |
| `<xades:SignaturePolicyIdentifier>` | Politika OID'sini değiştirme | İmzanın bağlı olduğu yasal/teknik politika değişir. |
| `<xades:SignerRole>` | Yetkili rolü ekleme/değiştirme | İmzanın yetki kapsamı manipülasyonu. |
| `<xades:CommitmentTypeIndication>` | İmza niyeti (onayladım / oluşturdum / kabul ettim) değiştirme | İmzanın hukuki anlamı değişir. |

Bu manipülasyonların hiçbiri `SignatureValue`'yu bozmaz; imza
matematik olarak geçerli görünmeye devam eder. Body bütünlüğü korunduğu
için doğrulayıcı `signatureIntact=true` raporlar — ama imzanın kapsadığı
metadata serbestçe oynanabilir.

## Bu yapı yasal değildir

Türkiye'de elektronik imzaya yasal geçerlilik kazandıran çerçeve
(5070 sayılı kanun ve bağlı yönetmelikler) eIDAS ile uyumlu, ETSI
standartlarına atıfla yazılmıştır. ETSI EN 319 132-1 (XAdES-BES) bir
imzanın *signed signature properties* alanlarını imza kapsamına almasını
**zorunlu** kılar. Bu zorunluluk yerine getirilmediğinde:

- İmza, format açısından XAdES-BES değildir; sadece bir XMLDSig'dir.
- İmzanın taşıdığı metadata (özellikle `SigningTime`) **delil değeri
  taşımaz** — sonradan değiştirilmiş olabilir, ispat edilemez.
- Bu yapı, eIDAS terminolojisinde "advanced electronic signature"
  niteliği taşımaz; *nitelikli* imza (QES) zaten olamaz.

Mersel DSS Verifier, bu tip imzaları **INVALID** olarak raporlar. DSS'in
soyut `SIG_CONSTRAINTS_FAILURE` sub-indication'ı yerine, hangi yapısal
hatanın tetiklediğini operatöre ve denetleyiciye somut Mersel rejection
kodu ile bildirir. Verdict her zaman invalid; rejection objesi yalnızca
tanı kanalıdır.

## Çözüm — imza altyapısı sağlayıcısının sorumluluğu

Bu sorun **imzalanmış belgenin alıcı tarafında** çözülemez. Doğrulayıcı
tarafından eklenecek hiçbir tolerans, kayıp olan kriptografik bağı
geri getirmez. Çözüm tek noktada: **imzayı üreten yazılım tek referans
yerine iki referans üretmelidir.**

İmza üreten bileşeni geliştiren veya bu altyapıyı kuran ekipler:

1. XAdES imzalama akışında `<ds:SignedInfo>` blokuna iki ayrı
   `<ds:Reference>` üretildiğinden emin olun:
   - Birincisi: `URI=""` + `enveloped-signature` transform (belge body'si).
   - İkincisi: `URI="#<SignedPropertiesId>"` +
     `Type="http://uri.etsi.org/01903#SignedProperties"`
     (qualifying properties).
2. Üretim ortamında çıkan örnek imzaları XAdES validator'ı ile
   doğrulayın; `SignedProperties` reference'ının var olduğunu açıkça
   teyit edin.
3. Yıllardır sorunsuz üretilen bu yapının regresyona uğramaması için
   regresyon testlerine "iki referans var mı?" assertion'ı ekleyin.

Bu sorunu üreten yazılımı geliştiren veya bu yazılımı kullanan
ekosistem oyuncularına, konu üzerinde **acilen** çalışmaları için
güçlü tavsiyedir.

## Tetik koşulları

Mersel DSS Verifier bu rejection'ı yalnızca aşağıdaki tüm koşullar
aynı anda sağlandığında raporlar:

1. DSS `Indication = INDETERMINATE`.
2. DSS `SubIndication = SIG_CONSTRAINTS_FAILURE`.
3. DSS DiagnosticData: `signatureIntact && signatureValid`
   (kriptografi sağlam — yani body bütünlüğü korunuyor).
4. BBB SAV içinde tek FAIL constraint `BBB_SAV_ISQPMDOSPP`
   (neither message-digest nor SignedProperties present).
5. Orijinal XML'de `<xades:SignedProperties Id="...">` elementi var
   fakat hiçbir `<ds:Reference>` bu Id'ye veya
   `Type="…#SignedProperties"` attribute'una pointing değil.

Herhangi bir gate açılmazsa imza yine `INVALID` döner; ek
Mersel tanı kodu raporlanmaz, DSS'in jenerik subIndication'ı son söz
olur.

## API yanıt örneği

```jsonc
{
  "signatures": [
    {
      "signatureId": "S-...",
      "valid": false,
      "indication": "INDETERMINATE",
      "subIndication": "SIG_CONSTRAINTS_FAILURE",
      "validationErrors": [
        "İmza geçersiz: INDETERMINATE (SIG_CONSTRAINTS_FAILURE)",
        "[MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE] XAdES imza yalnızca bir ds:Reference taşıyor; SignedProperties imza kapsamına alınmamış. SigningTime ve SigningCertificate digest kriptografik olarak korunmuyor."
      ],
      "appliedRejections": [
        {
          "code": "MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
          "title": "XAdES SignedProperties referansı eksik (tek referanslı imza)",
          "severity": "ERROR",
          "originalIndication": "INDETERMINATE",
          "originalSubIndication": "SIG_CONSTRAINTS_FAILURE",
          "evidence": {
            "signedPropertiesId": "SignedProperties_Signature_...",
            "dssBbbConstraint": "BBB_SAV_ISQPMDOSPP",
            "missingProtection": "SigningTime, SigningCertificateV2",
            "standardReference": "ETSI EN 319 132-1 (XAdES-BES)"
          },
          "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md"
        }
      ]
    }
  ]
}
```

## Log örneği

```
WARN  ... AdvancedSignatureVerificationService - TR legacy XAdES rejection raporlandı (signatureId=..., code=MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE). DSS INDETERMINATE/SIG_CONSTRAINTS_FAILURE; imza kriptografik olarak sağlam fakat SignedProperties Id='SignedProperties_Signature_...' hiçbir Reference tarafından bağlanmamış. İmza reddedildi; SigningTime ve SigningCertificate kriptografik olarak korunmuyor.
```

## Konfigurasyon

Konfigurasyon flag'i **yoktur**. Rejection enrichment verdict'i
değiştirmez; kapatmak operatörden tanı bilgisini saklamak anlamına gelir.
İmzanın `valid=false` davranışı DSS standart akışından gelir ve
toleranslandırılmaz.
