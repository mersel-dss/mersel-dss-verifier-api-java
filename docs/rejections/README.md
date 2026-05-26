# Applied Rejections — Mersel DSS Verifier

Mersel DSS Verifier, bir imzayı reddederken Eclipse DSS'in jenerik
`SubIndication` (örn. `SIG_CONSTRAINTS_FAILURE`) çıktısının ötesinde
**Türkiye e-imza ekosistemine özgü, kataloglu, makine-okunaklı bir tanı
kodu** raporlar. İmzanın `valid` alanı yine `false` kalır — yani DSS'in
kararını override etmiyoruz, sadece *neden invalid olduğunu* Mersel
kataloğundan kod + kanıt + dokümantasyon URL'i ile açıklıyoruz.

## Suppression vs Rejection — özet

| Kavram | DSS kararı | Mersel kararı | Verdict değişir mi? | Kullanım |
|---|---|---|---|---|
| **Suppression** | INVALID | VALID | Evet (override) | Type URI yazım hatası gibi, kriptografisi sağlam fakat formal hatası olan imzalara tolerans. |
| **Rejection** | INVALID | INVALID | Hayır (destek) | Tek referanslı XAdES imza (eksik SignedProperties reference) gibi, güvenlik trade-off'u kabul edilmeyen yapısal patolojiler. |

Suppression kataloğu: [`docs/suppressions/`](../suppressions/README.md)

---

## Naming convention

```
MDSS-{LAYER}-{DESCRIPTIVE-SLUG}
```

| Bölüm | Açıklama |
|---|---|
| `MDSS` | Mersel DSS prefix'i. |
| `{LAYER}` | İmza formatı veya kontrol katmanı: `XADES`, `CADES`, `PADES`, `CHAIN`, `CRYPTO`, `TIMESTAMP`, `REVOCATION`. |
| `{DESCRIPTIVE-SLUG}` | UPPER-KEBAB-CASE özellik adı; self-documenting. |

Aynı kod hem suppression hem rejection olamaz; kod uzayı paylaşılır.

## Kararlılık (stability)

1. Yayınlanmış bir kod **renaming** edilmez. Davranış değişiyorsa yeni kod
   eklenir, eskisi `@Deprecated` işaretlenir.
2. Her kod için `title`, `defaultReason`, `severity` ve `docsUrl` sabittir.
3. `evidence` map'inde mevcut field'lar removed/renamed yapılmaz; yeni
   field'lar eklenebilir.

## Severity seviyeleri

| Seviye | Anlam | Operatör eylemi |
|---|---|---|
| `ERROR` | İmza reddedildi, kullanıcı eylemi gerekli (yeniden imzalama veya kaynaktan düzeltme). | Kaynak entegratör/firma bilgilendirilmeli, yapısal düzeltme talep edilmeli. |
| `FATAL` | (Gelecekte) Ekosistem güvenlik açığı seviyesinde, derhal blokla. | Alert kurun, root-cause araştırın. |

## Kayıtlı kodlar

| Kod | Severity | Kategori | Açıklama |
|---|---|---|---|
| [`MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE`](./MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md) | `ERROR` | XAdES | XAdES imza yalnızca bir `ds:Reference` taşıyor; `SignedProperties` imza kapsamına alınmamış. ETSI EN 319 132-1 iki referans zorunluluğuna aykırı; SignedProperties içindeki alanlar post-signing tahrifata açık. |
| [`MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT`](./MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT.md) | `ERROR` | XCV | İmzacı sertifikasının `KeyUsage` extension'ı imza için yetkili bit (`digitalSignature` veya `nonRepudiation`) içermiyor. CA cert'i imza amaçlı yayınlamamış; RFC 5280 §4.2.1.3 ihlali. |

## Operasyonel kullanım

### Response içinde tüketim

```jsonc
{
  "signatures": [
    {
      "valid": false,
      "indication": "INDETERMINATE",
      "subIndication": "SIG_CONSTRAINTS_FAILURE",
      "validationErrors": [
        "İmza geçersiz: INDETERMINATE (SIG_CONSTRAINTS_FAILURE)",
        "[MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE] XAdES imza yalnızca bir ds:Reference taşıyor; SignedProperties imza kapsamına alınmamış. SigningTime ve SigningCertificate gibi alanlar kriptografik olarak korunmadığı için post-signing tahrifata açık. ETSI EN 319 132-1 (XAdES-BES) iki referans zorunluluğuna aykırı; imza reddedildi."
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
            "missingProtection": "SigningTime, SigningCertificateV2, SignaturePolicyIdentifier, SignerRole, CommitmentTypeIndication",
            "standardReference": "ETSI EN 319 132-1 (XAdES-BES)",
            "remediation": "İmzayı üreten yazılım iki ds:Reference üretmelidir: biri URI=\"\" (belge body'si, enveloped-signature transform), diğeri URI=\"#<SignedPropertiesId>\" Type=\"http://uri.etsi.org/01903#SignedProperties\" (qualifying properties)."
          },
          "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md"
        }
      ]
    }
  ]
}
```

`appliedRejections` boş veya `null` ise: DSS'in jenerik subIndication'ı
tek başına yeterli kabul edildi, ek Türkiye-spesifik bir patoloji tespit
edilmedi.

### Log filter

Her rejection `verification.log`'a `WARN` seviyesinde tek satır kaydeder:

```
TR legacy XAdES rejection raporlandı (signatureId=..., code=MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE). ...
```

## Yeni kod eklemek (contributors için)

1. `src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java`
   içine yeni enum değeri ekleyin (naming convention'a uyun).
2. `docs/rejections/<KOD>.md` dosyasını oluşturun.
3. Bu README'deki "Kayıtlı kodlar" tablosuna ekleyin.
4. `RejectionCode.docsUrl` field'ını yeni MD dosyasına yönlendirin
   (GitHub blob URL — `main` branch).
5. Tetik noktasının `@see` javadoc'una enum değerini bağlayın.
6. Service'te detector hit'ini `AppliedRejection`'a maple ve
   `SignatureInfo.appliedRejections` listesine ekle.
