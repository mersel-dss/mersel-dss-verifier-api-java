# `MDSS-XADES-LEGACY-TR-TYPE-URI`

> TR-legacy XAdES SignedProperties Type URI toleransı

| Field | Değer |
|---|---|
| **Code** | `MDSS-XADES-LEGACY-TR-TYPE-URI` |
| **Severity** | `INFO` |
| **Kategori** | XAdES (Layer = `XADES`) |
| **Default** | Açık (operatör kapatabilir) |
| **Config flag** | `verification.tr-legacy-xades-tolerance-enabled` |
| **ENV var** | `TR_LEGACY_XADES_TOLERANCE` |
| **Eklendiği sürüm** | `0.3.0` |

---

## TL;DR

KamuSM / GİB ekosistemindeki bazı imzalama araçları XAdES `Reference` elemanının
`Type` URI'sini standart dışı yazıyor. Eclipse DSS spec'e harfiyen uyduğu için
bu Type URI'yi tanımıyor ve **kriptografik olarak sağlam** imzaları bile
`INDETERMINATE / SIG_CONSTRAINTS_FAILURE` ile reddediyor.

TÜBİTAK İmzager, KamuSM doğrulama servisi ve diğer Türkiye e-imza araçları bu
imzaları kabul ediyor. Bu kod ile Mersel DSS Verifier de — **kriptografik
bütünlük doğrulanmışsa** — bu üretici hatasını affediyor.

## Sorun

XAdES standardında (ETSI TS 101 903), `<ds:Reference>` elemanının `Type`
attribute'u `<xades:SignedProperties>` blok'una işaret etmek için **tek bir
URI** kullanmalıdır:

| | Type URI |
|---|---|
| ❌ Bazı TR araçlarında üretilen | `http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties` |
| ✅ ETSI TS 101 903 standardı | `http://uri.etsi.org/01903#SignedProperties` |
| ✅ DSS'in tanıdığı diğer varyantlar | `http://uri.etsi.org/01903/v1.1.1#SignedProperties` <br> `http://uri.etsi.org/01903/v1.2.2#SignedProperties` <br> `http://uri.etsi.org/01903/v1.3.2#SignedProperties` <br> `http://uri.etsi.org/01903/v1.4.1#SignedProperties` |

**Hatalı varyant**, namespace URI'sinin sonuna `XAdES.xsd` ekleyerek **schema
location**'ı **type URI** ile karıştırmış. Bu yazım hatası KamuSM yıllarca
kullandığı bazı imzalama kütüphanelerinden geliyor; üretilmiş onbinlerce
imzayı kapsıyor.

DSS bu Type URI'yi tanımayınca BBB (Basic Building Block) içinde **SAV**
(Signed Attributes Validation) bloğunda şu constraint FAIL eder:

```
BBB_SAV_ISQPMDOSPP — The signed qualifying property:
neither 'message-digest' nor 'SignedProperties' is present!
```

Sonuç: `Indication=INDETERMINATE`, `SubIndication=SIG_CONSTRAINTS_FAILURE`.

## Çözüm — Tetik koşulları

Bu kod **şu altı koşulun TAMAMI sağlandığında** otomatik olarak uygulanır
(hiçbiri eksikse DSS'in kararı aynen kullanılır):

1. **Config flag açık**: `verification.tr-legacy-xades-tolerance-enabled=true`
   (default).
2. **DSS Indication = `INDETERMINATE`**.
3. **DSS SubIndication = `SIG_CONSTRAINTS_FAILURE`**.
4. **Kriptografik bütünlük sağlam**: DSS DiagnosticData'da `signatureIntact &&
   signatureValid` true.
5. **Tek SAV failure**: BBB SAV içinde **yalnızca** `BBB_SAV_ISQPMDOSPP`
   constraint'i FAIL. Başka SAV constraint'i (örn. `BBB_SAV_ISCDC` zayıf
   algoritma, `BBB_SAV_DSCACDPHED` digest hatası) FAIL ediyorsa imza gerçekten
   kırıktır → tolerans **uygulanmaz**.
6. **Patern eşleşmesi**: Orijinal XML byte'larında detector
   (`LegacyTurkishXadesTypeUriDetector`),
   `01903 + .xsd + #SignedProperties` paternine uyan bir Type URI buluyor.

> **Bu jenerik bir SIG_CONSTRAINTS bypass değildir.** Patern eşleşmesi byte
> seviyesinde regex ile yapılır; belirtilen yazım hatası dışında hiçbir
> SIG_CONSTRAINTS_FAILURE türü affedilmez.

## Sonuç

Tolerans uygulandığında:

| Field | Değer |
|---|---|
| `signatures[i].valid` | `true` |
| `signatures[i].indication` | `TOTAL_PASSED` |
| `signatures[i].subIndication` | (kaldırılır, `null`) |
| `signatures[i].validationErrors` | (toleransa ait constraint listede yer almaz) |
| `signatures[i].validationWarnings` | `[MDSS-XADES-LEGACY-TR-TYPE-URI] İmza, KamuSM/GİB ekosistemine özgü XAdES SignedProperties Type URI yazım hatası içeriyor (...). Kriptografik bütünlük doğrulandı; tolerans uygulandı.` |
| `signatures[i].appliedSuppressions[0]` | Aşağıdaki audit kaydı |

### Audit kaydı

```json
{
  "code": "MDSS-XADES-LEGACY-TR-TYPE-URI",
  "title": "TR-legacy XAdES SignedProperties Type URI toleransı",
  "reason": "İmza, KamuSM/GİB ekosistemine özgü XAdES SignedProperties Type URI yazım hatası içeriyor. Kriptografik bütünlük doğrulandı; tolerans uygulandı. Üretici Type URI: \"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\".",
  "severity": "INFO",
  "originalIndication": "INDETERMINATE",
  "originalSubIndication": "SIG_CONSTRAINTS_FAILURE",
  "evidence": {
    "detectedTypeUri": "http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties",
    "expectedTypeUri": "http://uri.etsi.org/01903#SignedProperties",
    "dssBbbConstraint": "BBB_SAV_ISQPMDOSPP"
  },
  "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md"
}
```

### Log

`verification.log` içinde tek satır:

```
TR legacy XAdES toleransı uygulandı (signatureId=…, code=MDSS-XADES-LEGACY-TR-TYPE-URI).
DSS INDETERMINATE/SIG_CONSTRAINTS_FAILURE iken imza kriptografik olarak sağlam
ve tek hata BBB_SAV_ISQPMDOSPP. Üretici Type URI: '…'
```

## Konfigürasyon

### Açık tutmak (default — TÜBİTAK İmzager paritesi)

```bash
TR_LEGACY_XADES_TOLERANCE=true
```

veya `application.properties`:

```properties
verification.tr-legacy-xades-tolerance-enabled=true
```

### Kapatmak (eIDAS-QES strict mode)

eIDAS-QES paralelinde davranmak isteyen kurumsal operatörler kapatabilir:

```bash
TR_LEGACY_XADES_TOLERANCE=false
```

Kapatıldığında bu üretici hatasına sahip imzalar `INDETERMINATE /
SIG_CONSTRAINTS_FAILURE` olarak raporlanmaya devam eder.

## Risk değerlendirmesi (severity = `INFO`)

| Soru | Cevap |
|---|---|
| **İmzanın kriptografik bütünlüğü doğrulandı mı?** | Evet — koşul (4) gereği `signatureIntact && signatureValid` true olmalı. |
| **SignedProperties bloğu manipüle edilmiş olabilir mi?** | Hayır — SignedProperties digest'i `SignedInfo` içindeki diğer Reference üzerinden zaten doğrulanıyor. URI Type değişkliği bu digest'i etkilemez. |
| **Başka bir SAV constraint'i sessizce maskeleniyor mu?** | Hayır — koşul (5) bu olasılığı dışlar; `BBB_SAV_ISQPMDOSPP` *tek* failure olmalı. |
| **Bypass jenerik mi?** | Hayır — koşul (6) byte-level regex ile yalnızca belgelenen yazım hatasını yakalar. |

Bu nedenle severity `INFO` — operatör eylem almak zorunda değildir, kayıt
audit/raporlama amaçlıdır.

## İlgili kaynaklar

- ETSI TS 101 903 v1.4.1 — XML Advanced Electronic Signatures (XAdES)
- TÜBİTAK İmzager — Türkiye'de yaygın e-imza doğrulama aracı
- KamuSM SertifikaDeposu (resmi root chain): http://depo.kamusm.gov.tr/depo/SertifikaDeposu.xml
- Eclipse DSS BBB constraint katalogu: `BBB_SAV_ISQPMDOSPP`
- Kaynak: [`LegacyTurkishXadesTypeUriDetector`](../../src/main/java/io/mersel/dss/verify/api/services/util/LegacyTurkishXadesTypeUriDetector.java)
- Tetik mantığı: [`AdvancedSignatureVerificationService.evaluateTrLegacyXadesTolerance`](../../src/main/java/io/mersel/dss/verify/api/services/verification/AdvancedSignatureVerificationService.java)

## Geçmiş (changelog)

| Sürüm | Değişiklik |
|---|---|
| `0.3.0` | Tolerans eklendi. |
| `Unreleased` | `appliedSuppressions[]` audit trail içine `MDSS-XADES-LEGACY-TR-TYPE-URI` kodu olarak yapılandırılmış kayıt eklendi. |
