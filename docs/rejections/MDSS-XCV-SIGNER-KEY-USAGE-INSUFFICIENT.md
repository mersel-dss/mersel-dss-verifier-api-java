# MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT

| Alan | Değer |
|---|---|
| Kod | `MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT` |
| Başlık | İmzacı sertifikası KeyUsage'da imza yetkisi taşımıyor |
| Severity | `ERROR` |
| Layer | XCV (X.509 Certificate Validation) |
| İlgili enum | [`RejectionCode.MDSS_XCV_SIGNER_KEY_USAGE_INSUFFICIENT`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`AdvancedSignatureVerificationService#evaluateSignerKeyUsageRejection`](../../src/main/java/io/mersel/dss/verify/api/services/verification/AdvancedSignatureVerificationService.java) |
| İlgili policy | [`kamusm-signer-strict-constraint.xml`](../../src/main/resources/policy/kamusm-signer-strict-constraint.xml) — `<KeyUsage Level="FAIL">` |

## Sorunun özeti

Bu rejection kodu, **imzayı atan sertifikanın X.509 `KeyUsage` extension'ında
imza atmaya yetkili bir bit (`digitalSignature` veya `nonRepudiation`)
bulunmadığı** vakaları işaretler. Yani:

> İmza matematik olarak doğrulansa bile, bu cert'i veren CA "bu sertifika
> ile imza atılabilir" demiyor. Cert sahibi belge imzalama yetkisinin
> dışına çıkmıştır; doğrulayıcı reddetmek zorundadır.

## X.509 KeyUsage extension nedir?

[RFC 5280 §4.2.1.3](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3),
bir sertifikadaki public key'in **hangi kriptografik operasyonlar için
kullanılabileceğini** sınırlayan zorunlu bir extension tanımlar.
9 bit'in semantiği:

| Bit | İsim | Anlamı |
|---:|---|---|
| 0 | `digitalSignature` | Sıradan imza (HMAC harici). |
| 1 | `nonRepudiation` (a.k.a. `contentCommitment`) | İnkâr edilemez imza — Mali Mühür / e-Seal için zorunlu. |
| 2 | `keyEncipherment` | Symmetric key sarmalama (örn. TLS RSA key exchange). |
| 3 | `dataEncipherment` | Veriyi doğrudan şifreleme (nadir). |
| 4 | `keyAgreement` | DH/ECDH anahtar üretimi. |
| 5 | `keyCertSign` | CA cert imzalama (yalnız CA'lar). |
| 6 | `cRLSign` | CRL imzalama. |
| 7-8 | `encipherOnly`, `decipherOnly` | `keyAgreement` ile kombineli alt-roller. |

Belge imzalayan bir cert için CA'nın **en az** `digitalSignature` veya
`nonRepudiation` bit'ini set etmesi gerekir. Bu yoksa cert imza için
yayınlanmamıştır; belge imzalama operasyonu policy ihlalidir.

Extension `critical=TRUE` ise her doğrulayıcı bu kuralı uygulamak
zorundadır (RFC 5280 §4.2: *"A certificate-using system MUST reject the
certificate if it encounters a critical extension it does not recognize
or a critical extension that contains information that it cannot process"*).
Türkiye'de KamuSM Mali Mühür CA'sı bu extension'ı `critical` olarak
yayınlar; dolayısıyla bit'lerin saygı görmesi opsiyonel değildir.

## Türkiye production gözlemi

KamuSM bir tüzel kişiye genellikle **birden fazla cert** verir:

| Cert kullanımı | KeyUsage bit'leri |
|---|---|
| Mali Mühür (e-imza / e-Seal) | `nonRepudiation` (gerekli), opsiyonel `digitalSignature` |
| TLS sunucu | `digitalSignature`, `keyEncipherment` |
| Anahtar değişimi / şifreleme | `keyEncipherment`, `keyAgreement` |

Bazı entegratör yazılımlar — özellikle çoklu cert sahibi büyük
mükelleflerde — imzalama akışında yanlış cert'i pick edebiliyor.
Yani: ekosistemde şifreleme amaçlı yayınlanmış bir cert ile XAdES imza
atılıyor. Belge body'si ve SignedProperties düzgünce imzalanmış olsa
bile, "bu cert'in sahibi imza atmaya CA tarafından yetkilendirilmemiş"
ihlali kalıyor.

**Gözlemlenen tipik bit kombinasyonu (146 production örneği):**

```
X509v3 Key Usage: critical
    Key Encipherment, Key Agreement
```

`digitalSignature` ve `nonRepudiation` bit'lerinden **hiçbiri yok**.
Extension `critical`. Dolayısıyla bu cert ile atılmış imza her
uyumlu doğrulayıcı tarafından reddedilmelidir.

## Tübitak ile uyum

Tübitak referans doğrulayıcısı bu durumu **"Sertifika anahtar kullanım
alanı hatalı"** mesajı ile reddeder. Mersel DSS Verifier de
`v0.4.3`'ten itibaren, default policy XML'lerinde
`<KeyUsage Level="FAIL">` kuralı ile aynı kararı verir; ek olarak
operatöre hangi spesifik X.509 patolojisinin tetiklediğini bu
rejection code ile kataloglu olarak bildirir.

## Güvenlik etkisi

Kriptografik olarak imza matematik açısından doğru olabilir — `SignedInfo`
hash'leri uyuyor, `SignatureValue` cert'in public key'i ile verify
oluyor. Sorun matematikte değil, **yetki ve hukuki anlamda**:

| Konu | Açıklama |
|---|---|
| Hukuki bağlayıcılık | Cert sahibi "bu key'in imza için kullanılamayacağı" hükmü altında imza atmış. eIDAS terminolojisinde advanced electronic signature niteliği taşımaz. QES (qualified electronic signature) zaten olamaz. |
| 5070 sayılı kanun | Yasa eIDAS / ETSI çerçevesine atıfla yazılmıştır. KeyUsage zorunluluğu cert profil tanımının zorunlu parçasıdır. |
| Denetim | Cert sahibinin imzayı *reddetmesi* mümkündür ("bu cert imza için verilmedi, sözleşmede taraf değilim"). Cert sahibinin nonRepudiation iddiası geçersizdir. |
| Kötü-niyet senaryosu | Çalınmış bir şifreleme cert'i imza için yeniden-kullanılabilir; CA bunu compromise olarak işaretlememiştir (zira kullanım amacı dışında). |

## Çözüm — imzayı üreten tarafın sorumluluğu

Bu sorun **alıcı tarafında** çözülemez. Doğrulayıcı tarafından eklenecek
hiçbir tolerans, CA'nın koyduğu yetki sınırını ortadan kaldırmaz.
Çözüm tek noktada: **imzayı atan kuruluş, KamuSM/CA'dan imza-amaçlı
bir cert (KeyUsage'da `digitalSignature` veya `nonRepudiation` bit'i
set) edinmeli ve onu kullanmalıdır.**

İmza üreten bileşeni geliştiren veya bu altyapıyı kuran ekiplere:

1. İmzalama akışında HSM/yumuşak token'dan cert seçilirken
   KeyUsage extension'ı kontrol edin. Şifreleme amaçlı cert (sadece
   `keyEncipherment`/`keyAgreement`) imza işlemine giremez.
2. Mali Mühür cert'i ile şifreleme cert'inin Subject DN'leri aynı
   olabilir (aynı tüzel kişi); ayırt edici özellik **KeyUsage**'dır.
3. Üretim ortamında çıkan örnek imzaları XAdES validator'ı ile
   doğrulayın; imzayı atan cert'in `keyUsage`'ı `digitalSignature`
   veya `nonRepudiation` içeriyor mu açıkça teyit edin.

## Tetik koşulları

Mersel DSS Verifier bu rejection'ı yalnızca aşağıdaki tüm koşullar
aynı anda sağlandığında raporlar:

1. DSS `Indication` ≠ `TOTAL_PASSED` (yani imza zaten valid değil —
   default policy'de KeyUsage `FAIL` olduğu için DSS doğal olarak
   INDETERMINATE/CHAIN_CONSTRAINTS_FAILURE üretir).
2. İmzacı `signingCertificate` mevcut ve DiagnosticData'ya yazılmış.
3. Cert'in `KeyUsage` extension'ı boş değil (yani extension mevcut).
4. `KeyUsage` bit listesinde ne `digitalSignature` ne de `nonRepudiation`
   bulunuyor.

Operatör custom policy ile KeyUsage seviyesini `WARN`'a indirdiyse
DSS imzayı VALID raporlar; bu durumda rejection üretilmez (operatör
explicit gevşek davranmayı seçmiştir).

## API yanıt örneği

```jsonc
{
  "signatures": [
    {
      "signatureId": "S-...",
      "valid": false,
      "indication": "INDETERMINATE",
      "subIndication": "CHAIN_CONSTRAINTS_FAILURE",
      "validationErrors": [
        "İmza geçersiz: INDETERMINATE (CHAIN_CONSTRAINTS_FAILURE)",
        "[MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT] İmzacı sertifikasının X.509 KeyUsage extension'ında imza için gerekli bit'lerden hiçbiri set değil (digitalSignature veya nonRepudiation/contentCommitment bekleniyor). CA cert'i imza amaçlı yayınlamamış; RFC 5280 §4.2.1.3 gereği reddedildi. Mevcut bit'ler: [keyEncipherment, keyAgreement].",
        "İmza uyarısı: CHAIN_CONSTRAINTS_FAILURE (Kritik hata)"
      ],
      "appliedRejections": [
        {
          "code": "MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT",
          "title": "İmzacı sertifikası KeyUsage'da imza yetkisi taşımıyor",
          "severity": "ERROR",
          "originalIndication": "INDETERMINATE",
          "originalSubIndication": "CHAIN_CONSTRAINTS_FAILURE",
          "evidence": {
            "presentKeyUsageBits": ["keyEncipherment", "keyAgreement"],
            "acceptedKeyUsageBits": ["digitalSignature", "nonRepudiation"],
            "signerCommonName": "ÖRNEK A.Ş. (Mali Mühür)",
            "signerSerialNumber": "0123456789ABCDEF",
            "standardReference": "RFC 5280 §4.2.1.3; ETSI EN 319 412-2 §4.3 (e-Seal)",
            "remediation": "İmzayı atan kuruluş, KamuSM/CA'dan imza-amaçlı (KeyUsage'da digitalSignature veya nonRepudiation bit'i set) bir cert edinmeli ve onu kullanmalıdır. Mevcut cert sadece şifreleme/anahtar değişimi için yetkilendirilmiştir."
          },
          "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT.md"
        }
      ]
    }
  ]
}
```

## Log örneği

```
WARN  ... AdvancedSignatureVerificationService - İmzacı sertifikası KeyUsage yetersiz (signatureId=..., code=MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT, cn="ÖRNEK A.Ş. (Mali Mühür)"). Mevcut bit'ler: [keyEncipherment, keyAgreement]; beklenenlerden biri: digitalSignature veya nonRepudiation.
```

## Konfigurasyon

İki ayrı katman halinde uygulanır:

1. **Policy XML** — primary enforcement. `kamusm-strict-constraint.xml` ve
   `kamusm-signer-strict-constraint.xml`'de signer cert için
   `<KeyUsage Level="FAIL">` + `digitalSignature` + `nonRepudiation`.
   Operatör custom policy yükleyebilir.
2. **Suppression gate guard** — defense in depth. `matchesTrLegacyXadesGate`
   içinde `hasAcceptableSigningKeyUsage` kontrolü; policy gevşetilse bile
   TR XAdES Type URI suppression bu durumda devreye girmez.

Rejection enrichment için ayrı bir feature flag yoktur — verdict zaten
DSS tarafından invalid raporlanır, biz yalnızca tanı koduyla zenginleştiririz.
