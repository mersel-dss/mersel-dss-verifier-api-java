# Applied Suppressions — Mersel DSS Verifier

Mersel DSS Verifier, Eclipse DSS'in spec'e harfiyen uyduğu bazı durumlarda
Türkiye e-imza ekosisteminin gerçekleriyle uyumlu davranabilmek için DSS'in
kararını **bilinçli olarak override** eder. Her override:

- Kriptografik bütünlük doğrulanmış imzalar üzerinde uygulanır.
- Dar ve belgelenmiş bir tetik kuralına bağlıdır (jenerik bir bypass değildir).
- Response içinde `signatures[i].appliedSuppressions[]` altında yapılandırılmış
  olarak raporlanır — *audit trail*.
- Operatör tarafından konfigurasyon flag'i ile kapatılabilir.

Bu klasör, her bir suppression kodunun ne yaptığını, hangi koşullarda
tetiklendiğini ve nasıl kapatılabileceğini detaylı anlatır.

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

## Kararlılık (stability)

1. Yayınlanmış bir kod **renaming** edilmez. Davranış değişiyorsa yeni kod
   eklenir, eskisi `@Deprecated` işaretlenir.
2. Her kod için `title`, `defaultReason`, `severity` ve `docsUrl` sabittir.
3. `evidence` map'inde mevcut field'lar removed/renamed yapılmaz; yeni
   field'lar eklenebilir.
4. `docsUrl` her zaman çözümlenebilir bir Mersel dökümanına işaret eder; kod
   kaldırılırsa bile geçici redirect ile korunur.

## Severity seviyeleri

| Seviye | Anlam | Operatör eylemi |
|---|---|---|
| `INFO` | Tasarımdan sapma, güvenlik etkisi yok. | Genelde bir şey yapmaya gerek yok; bilgi amaçlı. |
| `WARN` | Operatörün dikkat etmesi önerilir. | Dashboard'da görünür hale getirin, periyodik gözden geçirin. |
| `CRITICAL` | Operatör eylem almalı. | Alert kurun, root-cause araştırın. |

## Kayıtlı kodlar

| Kod | Severity | Kategori | Açıklama |
|---|---|---|---|
| [`MDSS-XADES-LEGACY-TR-TYPE-URI`](./MDSS-XADES-LEGACY-TR-TYPE-URI.md) | `INFO` | XAdES | KamuSM/GİB üreticisinin XAdES `Reference` Type URI yazım hatasına tolerans. |

## Operasyonel kullanım

### Prometheus / metric label

```promql
sum by (code) (rate(mersel_dss_suppression_applied_total[5m]))
```

### Log filter (Loki / Datadog)

Her override `verification.log`'a tek satır kaydeder ve mesaj başında `code=…`
field'ı bulundurur:

```
code=MDSS-XADES-LEGACY-TR-TYPE-URI signatureId=… ...
```

### Response içinde tüketim

```jsonc
{
  "signatures": [
    {
      "valid": true,
      "indication": "TOTAL_PASSED",
      "appliedSuppressions": [
        {
          "code": "MDSS-XADES-LEGACY-TR-TYPE-URI",
          "title": "...",
          "severity": "INFO",
          "originalIndication": "INDETERMINATE",
          "originalSubIndication": "SIG_CONSTRAINTS_FAILURE",
          "evidence": { "...": "..." },
          "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md"
        }
      ]
    }
  ]
}
```

`appliedSuppressions` boş veya `null` ise: DSS'in kararı aynen kullanıldı,
hiçbir Mersel-spesifik override uygulanmadı.

## Yeni kod eklemek (contributors için)

1. `src/main/java/io/mersel/dss/verify/api/models/enums/SuppressionCode.java`
   içine yeni enum değeri ekleyin (naming convention'a uyun).
2. `docs/suppressions/<KOD>.md` dosyasını oluşturun (bu klasördeki mevcut
   dosyaları template olarak kullanabilirsiniz).
3. Bu README'deki "Kayıtlı kodlar" tablosuna ekleyin.
4. `SuppressionCode.docsUrl` field'ını yeni MD dosyasına yönlendirin
   (GitHub blob URL — `main` branch).
5. Tetik noktasının `@see` javadoc'una enum değerini bağlayın.
6. `AppliedSuppressionTest.allSuppressionCodesFollowMdssNamingConvention`
   testi otomatik olarak yeni kodu da kontrol eder.
