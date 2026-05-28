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

## Çözüm — Tetik koşulları (gate v2.2 — allow-list-only)

> **🛡️ Gate v2 hardening (Unreleased):** Önceki sürüm (v1) yalnızca SAV
> ve XCV bloklarını gözetiyordu — FC/ISC/VCI/CV/PSV blokları kontrol
> edilmiyordu. Bir saldırgan **hash mismatch (CV) yaratıp** üzerine
> legacy Type URI yazım hatası eklerse, gate kapanmıyor ve imza
> yanlışlıkla VALID görünebiliyordu. Gate v2 bu açığı kapatır.

> **🐞 v2.0/v2.1 → v2.2 düzeltmesi:** v2.0 ve v2.1 sürümlerine bir
> 8. koşul olarak "cryptographic re-validation" katmanı eklenmişti
> (Type URI normalize edip XML'i DSS'e yeniden vermek). **Tasarım
> hatasıydı.** `<ds:Reference Type="...">` attribute değeri SignedInfo
> bloğunda yer aldığı için imza kapsamındadır; byte stream'inde
> değiştirmek SignatureValue'yi geçersizleştirir ve gerçek P1/P2
> vakalarda re-validation her zaman `SIG_CRYPTO_FAILURE` dönerdi
> (yalnız birim testlerin mock'lu "PASSED" senaryosu çalışıyordu).
> v2.2'de katman tamamen kaldırıldı; gate aşağıdaki **7 katmanlı
> allow-list süzgecine** geri çekildi. Allow-list mantığı tek başına
> yeterince güçlü güveni sağlar — KeyUsage / chain / revocation /
> policy hash gibi tüm gerçek FAIL'leri yakalar.

Bu kod **şu yedi koşulun TAMAMI sağlandığında** otomatik olarak uygulanır
(hiçbiri eksikse DSS'in kararı aynen kullanılır):

1. **Config flag açık**: `verification.tr-legacy-xades-tolerance-enabled=true`
   (default).
2. **DSS Indication = `INDETERMINATE`**.
3. **DSS SubIndication ⊂ `{SIG_CONSTRAINTS_FAILURE}`** — explicit
   `EnumSet` allow-list (`ALLOWED_TOLERANCE_SUB_INDICATIONS`). DSS taxonomi'de
   yarın yeni SubIndication eklenirse default tolere edilmez; review
   gerektirir. Asla tolere edilmeyen örnekler: `HASH_FAILURE`,
   `FORMAT_FAILURE`, `CHAIN_CONSTRAINTS_FAILURE`,
   `CRYPTO_CONSTRAINTS_FAILURE`, `EXPIRED`, `REVOKED`, `NO_POE`.
4. **Kriptografik bütünlük sağlam**: DSS DiagnosticData'da `signatureIntact`
   true (PKI key ile SignatureValue doğrulandı).
5. **Reference digest'leri eşleşiyor**: DSS DiagnosticData'da `signatureValid`
   true (içerik body + signed properties hash kontrolü geçti).
6. **🆕 Universal Allow-List**: TÜM BBB bloklarındaki (FC/ISC/VCI/CV/SAV/
   XCV-top/SubXCV/PSV) `NOT_OK` constraint key set'i
   `ALLOWED_TOLERANCE_FAILURE_KEYS = {BBB_SAV_ISQPMDOSPP}`'nin alt-kümesi
   olmalı. Tek izinli key bu; **herhangi başka bir blokta tek bir FAIL
   bile** gate'i kapatır. Tipik blocker örnekleri:

   | Block | Constraint | Anlamı |
   |---|---|---|
   | **CV** | `BBB_CV_IRDOI` | 🔴 Reference data object intact değil — **içerik manipülasyonu**! |
   | **CV** | `BBB_CV_IRDOF` | Reference data found değil |
   | **FC** | `BBB_FC_IEFF` | Signature format beklenenden farklı (örn. PAdES bekleniyor, XAdES gelmiş) |
   | **FC** | `BBB_FC_ISD` | Duplicate signature mevcut |
   | **ICS** | `BBB_ICS_ISCI` | Signing certificate identify edilemedi |
   | **VCI** | `BBB_VCI_ISPK` | Signature policy bilinmiyor |
   | **XCV** | `BBB_XCV_ISCGKU` | KeyUsage uygunsuz (şifreleme sertifikasıyla imza vakası) |
   | **XCV** | `BBB_XCV_CCCBB` | Chain root CA'ya kadar kurulamadı |
   | **SubXCV** | `BBB_XCV_ICTIVRSC` | Imza zamanında sertifika geçerlilik dışı |
   | **SubXCV** | `BBB_XCV_IRDC` / `BBB_XCV_RFC` | Revocation data freshness ihlali (24h+ bayat CRL) — 2026 hardening |
   | **SAV** | `BBB_SAV_ASCCM` / `BBB_SAV_ACCCBB` | Kabul edilmeyen digest/key algoritması (örn. MD5/SHA1, RSA <2048) — 2026 hardening |
   | **VCI** | `BBB_VCI_ISPM` | Signature policy hash uyumsuz — 2026 hardening (`PolicyHashMatch` FAIL'e çıkarıldı) |
   | **PSV** | `PSV_IPSVC` | Past signature validation conclusive değil (LTV/LTA) |

7. **Patern eşleşmesi**: Orijinal XML byte'larında detector
   (`LegacyTurkishXadesTypeUriDetector`),
   `01903 + (.xsd veya v1.3.2/v1.4.1) + #SignedProperties` paternine uyan
   bir Type URI buluyor.

> **Bu jenerik bir SIG_CONSTRAINTS bypass değildir.** Universal allow-list
> sayesinde DSS'in BBB pipeline'ındaki TÜM blokları (FC/ISC/VCI/CV/SAV/
> XCV/PSV) tek bir whitelist mantığıyla denetlenir. Pattern eşleşmesi
> byte seviyesinde regex ile yapılır; belirtilen yazım hatası dışında
> hiçbir SIG_CONSTRAINTS_FAILURE türü affedilmez.

### Defense-in-depth: gate v1 → v2 evolution

**Gate v1** (Pre-Unreleased) iki ayrı helper'la çalışıyordu:
`isOnlyBbbSavFailureMessageDigestOrSignedProperties` (SAV white-list) +
`hasAnyBbbXcvFailure` (XCV no-failure). FC/ISC/VCI/CV/PSV blokları
*hiç* kontrol edilmiyordu — saldırgan **hash mismatch (CV blok) yaratıp**
üzerine legacy Type URI yazım hatası eklerse gate kapanmıyor ve imza
yanlışlıkla VALID görünebiliyordu. Üretimde `99967f00-…` vakası ek
olarak şifreleme sertifikasıyla imza atılması problemini ortaya çıkardı
(`KeyUsage = keyEncipherment + keyAgreement`), XCV defense-in-depth o
turda eklendi.

**Gate v2** (Unreleased — bu sürüm) tek bir **universal allow-list**'le
tüm blokları tek noktada gözetir. `collectAllBbbFailureKeys` helper'ı
FC/ISC/VCI/CV/SAV/XCV-top/SubXCV/PSV bloklarındaki tüm `NOT_OK` key'leri
toplar; bu set `ALLOWED_TOLERANCE_FAILURE_KEYS = {BBB_SAV_ISQPMDOSPP}`'nin
alt-kümesi değilse gate kapanır. Yeni güvenlik özellikleri:

- **SubIndication EnumSet**: Yarın DSS taxonomi'sine yeni SubIndication
  eklenirse default tolere edilmez (taxonomy white-list lock).
- **Forensic audit metadata**: Her tolerance kararı
  {`gateVersion`, `allowedFailureKeys`, `observedFailureKeys`,
  `documentSha256`, `documentSizeBytes`} ile zenginleştirilir —
  regülatör ve dispute süreçlerinde "DSS hangi constraint'lerle INVALID
  dedi, biz neyi affettik" sorusuna birebir cevap veriyor.
- **Prometheus telemetry**: 2 metric ailesi
  (`mdss_tolerance_applied_total`, `mdss_tolerance_rejected_total`)
  + 2 Alertmanager kuralı — operatör suppression akışını real-time
  izler, sapma görürse uyarı alır.

> **Tarihsel not — v2.0/v2.1 cryptographic re-validation katmanı:**
> Gate v2.0 ek bir 8. koşul olarak "kanıt-bazlı re-validation" eklemişti
> (Type URI'yi standart varyantla değiştirip DSS'i yeniden çalıştırma).
> Tasarım hatasıydı çünkü Type URI imza kapsamında; byte stream'inde
> değiştirmek SignatureValue'yi geçersizleştirir. v2.2'de katman
> tamamen kaldırıldı, gate yukarıdaki 7 katmanlı allow-list süzgecine
> indirgendi. Detay için [CHANGELOG](../../CHANGELOG.md).

### `validationErrors` + yapısal `rootCause` — opaque BBB key'lerine insan-okur mesaj

Tolerance uygulanmadığında (yani imza gerçekten reddedildiğinde)
`signatures[i]` iki paralel kanaldan rapor verir:

1. **`validationErrors: List<String>`** — kısa özet satırlar. İlk satır
   her zaman üst düzey verdict (örn. *"İmza geçersiz: INDETERMINATE
   (CHAIN_CONSTRAINTS_FAILURE)"*); ardından her FAIL constraint için
   `[KEY] insan-okur mesaj` satırı. Geriye uyumlu — eski client'ları
   bozmaz.
2. **`rootCause: FailedConstraint`** *(yeni — `Unreleased`, default açık)* —
   her imza için **tek bir** yapısal `{key, message}` objesi. ETSI EN
   319 102-1 terminolojisinde DSS DetailedReport'taki
   `<Constraint Status="NOT_OK">` elementleri "*failed constraints*"
   olarak adlandırılır; bu alan bunlardan tek bir kök nedeni seçer.
   Frontend/audit kontratı `key` üzerinden lookup yapar (locale değişse
   bile aynı kalır), `message` doğrudan kullanıcıya gösterilir.

   **Niçin tek nesne (default)?** DSS pipeline'ı sıkı hiyerarşik akış
   izler — tek bir kök neden (örn. KeyUsage uygunsuz) her zaman birden
   fazla NOT_OK constraint üretir (XCV-top roll-up + SAV/CV cascade).
   Frontend bu satırları liste olarak alıp eşit ağırlıkta gösterirse
   operatör "üç ayrı sorun var" sanır; oysa yalnız bir tane gerçek kök
   neden vardır. Default tek nesne kontratı UX gürültüsünü kaynağında
   keser. Audit/forensic ihtiyaç olduğunda opt-in
   `failedConstraints` listesi devreye girer (aşağıya bkz.).

Örneğin şifreleme sertifikasıyla imzalanmış bir e-Belge için DSS
pipeline'ı kanonik üç-aşamalı bir zincir üretir — KeyUsage failure
(root cause / SubXCV) → XCV-top roll-up (`BBB_XCV_SUB`) → SAV cascade
(`BBB_SAV_ISQPMDOSPP` çünkü XCV INDETERMINATE). Default response'ta
yalnız kök neden görünür:

```json
"validationErrors": [
  "İmza geçersiz: INDETERMINATE (CHAIN_CONSTRAINTS_FAILURE)",
  "[BBB_XCV_ISCGKU] İmzacı sertifikası, beklenen anahtar kullanım alanına (KeyUsage) sahip değil!"
],
"rootCause": {
  "key": "BBB_XCV_ISCGKU",
  "message": "İmzacı sertifikası, beklenen anahtar kullanım alanına (KeyUsage) sahip değil! — Anahtar kullanımı : [KEY_ENCIPHERMENT, KEY_AGREEMENT]"
}
```

Roll-up satırı (`BBB_XCV_SUB`) ve cascade satırı (`BBB_SAV_ISQPMDOSPP`)
default response'ta **görünmez** — ikisi de pipeline'ın yan ürünüdür,
operatör için aksiyon alınabilir bilgi taşımazlar. Opt-in
`failedConstraints` listesinde audit için kategorize halde görünürler.

**Birden fazla gerçek kök neden** (örn. signer + counter signer
sertifikalarında ayrı ayrı KeyUsage failure): DSS gezme sırasına göre
ilk satır seçilir (deterministik: FC → ISC → VCI → CV → SAV →
XCV-top → SubXCV[0..n] → PSV). Eksiksiz pipeline detayı isteyen
operatör opt-in `?includeFailedConstraints=true` query parameter'i ile
tüm constraint'leri kategorize halde alabilir (bkz. aşağıda).

**Defansif fallback**: Listede hiç ROOT_CAUSE satırı yoksa (DSS yeni
sürümünde whitelist eksik veya beklenmeyen blok ilişkisi oluşursa),
`selectRootCause` listenin ilk elemanına düşer. Operatör hiçbir
zaman bilgisiz kalmaz.

3. **`failedConstraints: List<FailedConstraint>`** *(yeni — `Unreleased`,
   opt-in)* — pipeline'ın ürettiği <em>tüm</em> BBB FAIL constraint'leri,
   her biri `category` alanı ile etiketlenmiş (`ROOT_CAUSE`, `DERIVED`,
   `CASCADE`). Yalnız `?includeFailedConstraints=true` query parameter
   ile istendiğinde doldurulur; default `null` (NON_NULL ile JSON'a
   yazılmaz). Audit, forensic, "neden bu satır rootCause olarak seçildi?"
   sorusu, veya frontend'de gelişmiş detay paneli için.

   **Kategori semantiği** (wire format: enum sabit adı UPPER_CASE —
   diğer API enum'larıyla aynı convention):
   - `ROOT_CAUSE` — pipeline'ın gerçek başarısızlık sebepleri
     (SubXCV içindeki spesifik check'ler, FC/ISC/VCI/PSV bağımsız
     failure'lar, XCV-top'un whitelist dışı key'leri). Operatör
     aksiyon alacaksa bunlardan birine yönelir.
   - `DERIVED` — XCV-top summary roll-up satırları
     (`BBB_XCV_SUB`, `BBB_XCV_ICTIVRSC`). SubXCV'lerden biri NOT_OK
     olduğu için tetiklenen yansıma — yeni bilgi taşımaz.
   - `CASCADE` — SAV/CV bloklarındaki downstream yan ürün satırları.
     XCV INDETERMINATE/FAILED olduğunda sertifika context'i
     kullanılamadığı için bu blokların "kontrol edilemedi" üretmesi
     doğal.

   ```bash
   # Default — yalnız rootCause döner (yukarıdaki örnek)
   curl -F signedDocument=@imza.xml https://verifier/api/v1/verify/signature

   # Audit — tüm pipeline kategorize halde dönsün
   curl -F signedDocument=@imza.xml \
        "https://verifier/api/v1/verify/signature?includeFailedConstraints=true"
   ```

   Opt-in response'ta canonical zincir:

   ```json
   "rootCause": {
     "key": "BBB_XCV_ISCGKU",
     "message": "İmzacı sertifikası, beklenen anahtar kullanım alanına ..."
   },
   "failedConstraints": [
     {
       "key": "BBB_XCV_ISCGKU",
       "message": "İmzacı sertifikası, beklenen anahtar kullanım alanına ...",
       "category": "ROOT_CAUSE"
     },
     {
       "key": "BBB_XCV_SUB",
       "message": "SubXCV sonucu geçerli mi?",
       "category": "DERIVED"
     },
     {
       "key": "BBB_SAV_ISQPMDOSPP",
       "message": "İmzalı qualifying property mevcut mu?",
       "category": "CASCADE"
     }
   ]
   ```

   Frontend tarafında dispatch + isteğe bağlı detay paneli:

   ```js
   // Default kart: tek aksiyon mesajı
   showError(result.signatures[0].rootCause.key, result.signatures[0].rootCause.message);

   // Audit paneli (opt-in fetch sonrası)
   const all = result.signatures[0].failedConstraints || [];
   const root  = all.filter(c => c.category === "ROOT_CAUSE");
   const sideE = all.filter(c => c.category !== "ROOT_CAUSE");
   ```

   **Global Jackson NON_NULL**: `application.properties`'te
   `spring.jackson.default-property-inclusion=non_null` ayarı tüm
   ObjectMapper'ları NON_NULL yapar — yeni model eklenirken
   `@JsonInclude(NON_NULL)` annotation unutulsa bile null alanlar
   JSON'a sızmaz. `rootCause` alanındaki tek nesne için `category`
   her zaman ROOT_CAUSE olduğu için null bırakılır ve JSON'a yazılmaz
   (UX: tek nesne = kategoriye gerek yok).

   **Boş liste sözleşmesi:** Opt-in açıkken alan her zaman set edilir —
   imzada FAIL constraint yoksa bile boş array (`[]`) döner. Frontend
   opt-in onayını alanın varlığından okur:

   ```js
   if ("failedConstraints" in sig) {
     // opt-in açıldı; boş bile olsa alan var
     showAuditPanel(sig.failedConstraints);
   }
   ```

   **Imza ↔ timestamp simetri:** Aynı kontrat
   [`TimestampInfo`](../../src/main/java/io/mersel/dss/verify/api/models/TimestampInfo.java)
   için de geçerli. Her timestamp için DSS DetailedReport'taki ayrı
   BBB bloğu gezilir (BBB Id = `TimestampWrapper.getId()`); aynı
   sınıflandırma kuralları (XCV roll-up DERIVED, SAV/CV cascade
   CASCADE) timestamp tarafında da geçerli. TSA sertifikası KeyUsage
   uygunsuzluğu, NotExpired ihlali, revocation problemleri imzayla
   birebir aynı yapıda raporlanır:

   ```json
   "signatures": [{
     "rootCause": { "key": "BBB_XCV_ISCGKU", ... },
     "timestamps": [{
       "rootCause": { "key": "QUAL_TL_REACH_ANS", ... },
       "failedConstraints": [
         { "key": "QUAL_TL_REACH_ANS", "category": "ROOT_CAUSE", ... }
       ]
     }]
   }]
   ```

Mesajlar DSS'in kendi `dss-i18n` paketinden (`I18nProvider`,
`dss-messages.properties`) geliyor; pipeline her FAIL constraint için
`XmlConstraint.error.value` alanına bunu zaten doldurmuş halde sağlıyor.
İki helper aynı kaynaktan okur:
- [`AdvancedSignatureVerificationService.collectFailingBbbConstraintDetails`](../../src/main/java/io/mersel/dss/verify/api/services/verification/AdvancedSignatureVerificationService.java)
  — yapısal `List<FailedConstraint>` üretir; FC, ISC, VCI, CV, SAV, XCV
  (top-level + her SubXCV katmanı), PSV bloklarını gezer.
- `collectFailingBbbConstraintMessages` — yukarıdaki helper'ı sarmalayan
  string adapter (`[KEY] message` formatında); `validationErrors`
  alanını besler.

`additionalInfo` doluysa (örn. CN, serial, expiry tarihi) " — " ile
mesajla birleştirilir; aynı `(key, message)` çifti tekrar etmez
(LinkedHashSet dedup, sıra korunur). Aynı KEY iki farklı sertifika için
geliyorsa (farklı `additionalInfo`) iki giriş de korunur — bağlam
kaybedilmez.

**Locale varsayılanı Türkçe — TAM çeviri** — `verification.i18n-locale=tr`
(default). DSS pipeline'a `validator.setLocale(Locale.forLanguageTag("tr"))`
çağrısıyla iletildiğinden mesajlar
[`dss-messages_tr.properties`](../../src/main/resources/dss-messages_tr.properties)
dosyamızdan okunur; **DSS 6.3 dss-messages.properties dosyasındaki 823
anahtarın tamamı** (BBB constraint'leri, ETSI EN 319 102-1 semantics,
QUAL, QWAC, additional info template'leri, validation süreç başlıkları)
Türkçe'ye çevrildi. İleride DSS yeni anahtar eklerse otomatik İngilizce
default'a fallback olur — boş çıktı oluşmaz.

Source dosyası UTF-8 olarak klasik Spring Boot konumunda
`src/main/resources/dss-messages_tr.properties`'de tutulur (IDE'de
temiz okunur — Türkçe karakterler doğrudan yazılır). `pom.xml`'de
`<build><resources>` bloğu bu dosyayı `maven-resources-plugin`'in
default copy'sinden **exclude eder** (UTF-8 byte'ların runtime'da
mojibake'e yol açmasını önlemek için); yerine `maven-antrun-plugin` +
Apache Ant `<native2ascii>` task'ı aynı `process-resources` phase'inde
non-ASCII karakterleri Unicode escape (`\uXXXX`) ile değiştirip
`target/classes/dss-messages_tr.properties` olarak yazar — tek kanal,
runtime'da JVM'in encoding davranışından bağımsız doğru çeviri.

Operatör İngilizce'ye dönmek için `verification.i18n-locale=en` set
edebilir. Bkz.
[`I18nProviderConfiguration`](../../src/main/java/io/mersel/dss/verify/api/config/I18nProviderConfiguration.java).

`TRUSTED_SERVICE_STATUS`, `TRUST_SERVICE_NAME`, `TRUSTED_SERVICE_TYPE`
gibi parametreli mesajlar ETSI URI / enum kodunu placeholder olarak
geçirir; bu URI/enum değerleri DSS tarafında çevrilmez ve
`rootCause.message` (ve eski `validationErrors`) çıktısında orijinal kod
(örn. `http://uri.etsi.org/TrstSvc/Svcstatus/granted`) olarak görünür —
frontend bu değerleri kendi lookup table'ı ile zenginleştirebilir.

## Sonuç

Tolerans uygulandığında:

| Field | Değer |
|---|---|
| `signatures[i].valid` | `true` |
| `signatures[i].indication` | `TOTAL_PASSED` |
| `signatures[i].subIndication` | (kaldırılır, `null`) |
| `signatures[i].validationErrors` | (toleransa ait constraint listede yer almaz) |
| `signatures[i].rootCause` | (alan görünmez — tolerans uygulandığında `null`, NON_NULL JSON ile gizli) |
| `signatures[i].validationWarnings` | `[MDSS-XADES-LEGACY-TR-TYPE-URI] İmza, KamuSM/GİB ekosistemine özgü XAdES SignedProperties Type URI yazım hatası içeriyor (...). Kriptografik bütünlük doğrulandı; tolerans uygulandı.` |
| `signatures[i].appliedSuppressions[0]` | Aşağıdaki audit kaydı |

### Audit kaydı (gate v2.2 — forensic grade)

```json
{
  "code": "MDSS-XADES-LEGACY-TR-TYPE-URI",
  "title": "TR-legacy XAdES SignedProperties Type URI toleransı",
  "reason": "İmza, KamuSM/GİB ekosistemine özgü XAdES SignedProperties Type URI yazım hatası içeriyor. Kriptografik bütünlük doğrulandı; tolerans uygulandı. Üretici Type URI: \"http://uri.etsi.org/01903/v1.3.2#SignedProperties\".",
  "severity": "INFO",
  "originalIndication": "INDETERMINATE",
  "originalSubIndication": "SIG_CONSTRAINTS_FAILURE",
  "evidence": {
    "detectedTypeUri": "http://uri.etsi.org/01903/v1.3.2#SignedProperties",
    "dssBbbConstraint": "BBB_SAV_ISQPMDOSPP"
  },
  "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md",
  "gateVersion": "v2.2",
  "allowedFailureKeys": ["BBB_SAV_ISQPMDOSPP"],
  "observedFailureKeys": ["BBB_SAV_ISQPMDOSPP"],
  "documentSha256": "61fe765f8d365c01399a965030fe4bfa2edecbf19aaa87464202b23f7f289902",
  "documentSizeBytes": 108694
}
```

Audit alanları:

| Alan | Niçin? |
|---|---|
| `gateVersion` | Bu karar hangi gate sürümüyle alındı? Geriye dönük forensic: yarın gate sıkılaşırsa eski kayıtlar dokunulmaz kalır. |
| `allowedFailureKeys` | Pozitif tarafta beklenen izinli set. Yarın allow-list genişlerse eski kayıtlarda hangi izin verilenler varmış kanıtı kalır. |
| `observedFailureKeys` | DSS'in gerçekten gözlediği FAIL key set'i. Saldırı tespiti / regresyon analizi için: bekleniyor mu, beklenmedik mi? |
| `documentSha256` + `documentSizeBytes` | Forensic dispute'ta "tam o byte dizisi mi affedildi" sorusunun cevabı. Receiver kendi kopyasıyla hash karşılaştırabilir. |

> **Tarihsel not:** v2.0/v2.1 audit kayıtlarında `evidence.expectedTypeUri`
> ve `reValidationVerdict` alanları da görülürdü; bu alanlar
> re-validation katmanına aitti ve v2.2'de katmanla birlikte kaldırıldı.
> Eski JSON kayıtlarını deserialize ederken Jackson bu alanları sessizce
> yok sayar (backward compatible).

### Log

`verification.log` içinde tek satır (gate v2.2):

```
TR legacy XAdES toleransı uygulandı (signatureId=…, code=MDSS-XADES-LEGACY-TR-TYPE-URI,
kind=TYPE_URI_VARIANT, gateVersion=v2.2).
DSS INDETERMINATE/SIG_CONSTRAINTS_FAILURE iken imza kriptografik olarak sağlam
ve tek hata BBB_SAV_ISQPMDOSPP. Üretici Type URI: '…'
```

### Prometheus telemetry

Operatör suppression akışını real-time izler:

| Metric | Tip | Label'lar | Açıklama |
|---|---|---|---|
| `mdss_tolerance_applied_total` | Counter | `code`, `gate_version` | Tolerance uygulanan vakalar. |
| `mdss_tolerance_rejected_total` | Counter | `code`, `gate_version`, `reason` | Tolerance reddedilen vakalar. `reason` label'ı: `indication_not_indeterminate`, `sub_indication_not_allowed`, `signature_not_intact`, `signature_not_valid`, `unallowed_failure_key`, `no_failure_observed`, `pattern_no_match`, `config_disabled`. |

Alertmanager kuralları (`devops/monitoring/prometheus/alerts.yml`):

- `MdssToleranceUsageSpike` — sustained >1 req/s tolerance uygulaması (10dk)
- `MdssToleranceRejectionRateHigh` — >5 req/s sustained rejection (10dk)

> **Tarihsel not:** v2.0/v2.1'de iki ek metric (`mdss_tolerance_revalidation_seconds`)
> ve iki ek alarm (`MdssToleranceReValidationErrorRate`,
> `MdssToleranceReValidationLatencyHigh`) vardı; v2.2'de re-validation
> katmanı kaldırıldığı için bu metric/alarm'lar da silindi.

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
| **İmzanın kriptografik bütünlüğü doğrulandı mı?** | Evet — koşul (4) ve (5) gereği `signatureIntact && signatureValid` true olmalı. |
| **İçerik (CV blok) manipüle edilmiş olabilir mi?** | Hayır — koşul (6) Universal Allow-List `BBB_CV_IRDOI` (reference data object intact değil) hatası varsa gate'i kapatır. Hash mismatch maskelenemez. |
| **SignedProperties bloğu manipüle edilmiş olabilir mi?** | Hayır — SignedProperties digest'i `SignedInfo` içindeki diğer Reference üzerinden zaten doğrulanıyor. URI Type değişkliği bu digest'i etkilemez. |
| **Başka bir SAV constraint'i sessizce maskeleniyor mu?** | Hayır — koşul (6) `ALLOWED_TOLERANCE_FAILURE_KEYS` tek elemanlı bir set; `BBB_SAV_ISQPMDOSPP` dışında her SAV FAIL (örn. `BBB_SAV_ISCDC` zayıf algoritma) gate'i kapatır. |
| **Sertifika düzleminde (KeyUsage, chain, expiry, revocation) bir hata maskeleniyor mu?** | Hayır — koşul (6) BBB XCV (top-level + tüm SubXCV katmanları) içinde herhangi bir `NOT_OK` varsa gate'i kapatır; şifreleme sertifikasıyla imza atma gibi vakalar tolerance ile gizlenmez. |
| **Format Check (FC), Identification of Signing Certificate (ICS), Validation Context Initialization (VCI), Past Signature Validation (PSV) bloklarındaki hatalar maskeleniyor mu?** | 🆕 Hayır — gate v2'de Universal Allow-List bu blokları da kapsar; herhangi bir blokta `BBB_SAV_ISQPMDOSPP` dışı FAIL gate'i kapatır. Gate v1'de bu bloklar atlanıyordu. |
| **Yarın DSS yeni bir SubIndication eklerse otomatik tolere edilir mi?** | 🆕 Hayır — koşul (3) `EnumSet` allow-list. Yeni SubIndication explicit eklenmedikçe default kapalı (taxonomy white-list lock). |
| **v2.0/v2.1'de bahsi geçen "cryptographic re-validation" katmanı nerede?** | 🐞 Tasarım hatası nedeniyle v2.2'de kaldırıldı. Type URI imza kapsamında (`<ds:Reference>` SignedInfo'da); byte stream'inde değiştirmek SignatureValue'yi geçersizleştirir. Gerçek P1/P2 vakalarda layer her zaman `SIG_CRYPTO_FAILURE` dönerdi. Allow-list mantığı (7 katman) tek başına yeterli güveni sağlar; yarın gerçek "kanıt-bazlı" bir kontrol gerekirse Type URI tolerant XAdES path provider (DSS internal API genişletmesi) yolu açıktır. |
| **Bypass jenerik mi?** | Hayır — koşul (7) byte-level regex ile yalnızca belgelenen yazım hatasını yakalar; jenerik SIG_CONSTRAINTS_FAILURE bypass'ı değildir. |

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
| `Unreleased` | **🐞 Gate v2.2 — Cryptographic re-validation katmanı kaldırıldı (tasarım hatası düzeltmesi)**: v2.0/v2.1'de eklenen "kanıt-bazlı" re-validation katmanı (Type URI normalize edip DSS'i yeniden çalıştırma) gerçek vakalarda her zaman patlıyordu. `<ds:Reference Type="...">` attribute değeri SignedInfo bloğunda yer aldığı için imza kapsamındadır; byte stream'inde değiştirmek canonical SignedInfo'yu değiştirir, dolayısıyla SignatureValue geçersiz olur ve DSS pipeline `SIG_CRYPTO_FAILURE` döner. Layer kaldırıldı; gate "allow-list-only" mantığa indirgendi (7 katman: config + indication + subIndication + signatureIntact + signatureValid + observedFailureKeys ⊆ allow-list + pattern eşleşmesi). `attemptCryptographicReValidation` metodu, `ReValidationContext` ve `ReValidationResult` inner class'ları, `normalizeTypeUri` + `CANONICAL_SIGNED_PROPERTIES_TYPE_URI` helper'ı, iki config flag (`verification.tr-legacy-xades-re-validation-enabled`, `…-fail-closed`), `AppliedSuppression.reValidationVerdict` alanı, `mdss_tolerance_revalidation_seconds` metric ve `MdssToleranceReValidationErrorRate` + `MdssToleranceReValidationLatencyHigh` alarm'ları silindi. Audit kanıtında `gateVersion = "v2.2"`. Backward compatible (eski env var'lar/JSON alanları Jackson tarafından sessizce yok sayılır). |
| `Unreleased` | **🛡️ Gate v2.1 — Re-validation ERROR fail-closed (safe-by-default hardening)** *(v2.2'de revert edildi — bkz. yukarıdaki entry)*: Gate v2.0'da cryptographic re-validation Java exception atarsa konservatif olarak yine tolere ediliyordu (fail-open); bu davranış `verification.tr-legacy-xades-re-validation-fail-closed=true` (default) ile **fail-closed**'a alınmıştı. |
| `Unreleased` | `appliedSuppressions[]` audit trail içine `MDSS-XADES-LEGACY-TR-TYPE-URI` kodu olarak yapılandırılmış kayıt eklendi. |
| `Unreleased` | **XCV defense-in-depth (gate v1.5)**: tetik koşullarına BBB XCV (top-level + SubXCV) bloğunda `NOT_OK` constraint olmaması zorunluluğu eklendi. Şifreleme sertifikasıyla imzalama vakası gibi sertifika düzlemindeki QC ihlalleri tolerance ile maskelenmiyor. Helper: `hasAnyBbbXcvFailure` (gate v2'de silindi — Universal Allow-List tarafından kapsandı). |
| `Unreleased` | **🛡️ Gate v2.0 — Universal Allow-List (security hardening)**: Tetik koşulları 7 → 8'e çıkarıldı *(v2.2'de tekrar 7'ye indi — re-validation kaldırıldı)*. Önceki sürümde FC/ISC/VCI/CV/PSV blokları kontrol edilmiyordu — saldırgan hash mismatch (CV) yaratıp üzerine legacy Type URI yazım hatası eklerse gate kapanmıyordu. Yeni `collectAllBbbFailureKeys` helper'ı TÜM BBB bloklarını tek noktada gezer ve `ALLOWED_TOLERANCE_FAILURE_KEYS = {BBB_SAV_ISQPMDOSPP}` set'iyle subset check yapar. Eski `isOnlyBbbSavFailureMessageDigestOrSignedProperties` ve `hasAnyBbbXcvFailure` helper'ları silindi. |
| `Unreleased` | **🆕 SubIndication EnumSet (taxonomy white-list lock)**: `ALLOWED_TOLERANCE_SUB_INDICATIONS = EnumSet.of(SIG_CONSTRAINTS_FAILURE)`. DSS yarın yeni SubIndication eklerse default tolere edilmez. HASH_FAILURE, FORMAT_FAILURE, CHAIN_CONSTRAINTS_FAILURE, CRYPTO_CONSTRAINTS_FAILURE, EXPIRED, REVOKED, NO_POE asla bypass edilmez. |
| `Unreleased` | **🆕 Forensic audit metadata**: `AppliedSuppression` model'ine 5 yeni alan: `gateVersion`, `allowedFailureKeys`, `observedFailureKeys`, `documentSha256`, `documentSizeBytes`. Backward compatible (yeni constructor; eski 8-args constructor null bırakır). Defensive copy + `UnsupportedOperationException` ile audit set'lerinin kirletilmesi engellenir. *(v2.0/v2.1'de bir 6. alan `reValidationVerdict` da vardı; v2.2'de re-validation katmanıyla birlikte kaldırıldı.)* |
| `Unreleased` | **🆕 Prometheus telemetry**: 2 metric ailesi (`mdss_tolerance_applied_total`, `mdss_tolerance_rejected_total`) MeterRegistry'e yazılır (best-effort; null güvenli). 2 Alertmanager kuralı (`MdssToleranceUsageSpike`, `MdssToleranceRejectionRateHigh`). *(v2.0/v2.1'de bir 3. metric `mdss_tolerance_revalidation_seconds` ve 2 ek alarm vardı; v2.2'de re-validation katmanıyla birlikte kaldırıldı.)* |
| `Unreleased` | **`validationErrors` BBB enrichment**: tolerans uygulanmayan akışta DSS'in opaque BBB key'leri (`BBB_XCV_ISCGKU` vb.) artık `[KEY] insan-okur mesaj` formatında listeleniyor. Mesaj kaynağı DSS `dss-i18n` paketi (`I18nProvider`, `dss-messages.properties`); ek dependency yok — pipeline `XmlConstraint.error.value` alanını zaten dolduruyor. Helper: `AdvancedSignatureVerificationService.collectFailingBbbConstraintMessages`. |
| `Unreleased` | **DSS i18n locale = `tr` (default)**: Tüm BBB constraint mesajları (`BBB_XCV_ISCGKU`, `TRUSTED_SERVICE_STATUS`, vb.) pipeline'a `validator.setLocale(...)` ile geçirilen Türkçe locale ile dolduruluyor. TR çevirileri `src/main/resources/dss-messages_tr.properties` (Unicode escape'li); eksik anahtarlar otomatik İngilizce default'a fallback eder. Override: `verification.i18n-locale=en`. Config sınıfı: `I18nProviderConfiguration`. |
| `Unreleased` | **TR tam çeviri (823 anahtar)**: `dss-messages_tr.properties` artık DSS 6.3 dss-messages.properties dosyasındaki TÜM 823 anahtarı içerir — BBB constraint'leri (FC/CV/ICS/RFC/SAV/TAV/VCI/XCV + SubXCV/PSV/PCV/TSV), ADEST/BSV/LTV/ARCH/ACCM, QUAL_TL/QUAL_CERT/QC/QSCD, QWAC + TLS Certificate Binding, tokens, additional info template'leri, validation süreç başlıkları, ETSI EN 319 102-1 semantics. |
| `Unreleased` | **UTF-8 source-of-truth + build-time `native2ascii`**: Source dosyası klasik Spring Boot konumunda `src/main/resources/dss-messages_tr.properties` (UTF-8, IDE'de temiz okunur) — `pom.xml`'de `<build><resources>` bloğunda `maven-resources-plugin`'in default copy'sinden **exclude** edildi (UTF-8 byte'lar runtime'da mojibake'e yol açmasın diye). `maven-antrun-plugin` + Apache Ant 1.10.x ile `process-resources` phase'inde `<native2ascii>` task'ı Unicode escape (`\uXXXX`) dönüşümü yapıp `target/classes/`'a yazar. Tek kanal = encoding tutarlılığı (IDE incremental builds dahil). Geliştirici manuel pass çalıştırmaz; üretilen escape sürüm kaynak kontrolüne girmez (yalnız `target/` altındadır). |
| `Unreleased` | **Yapısal hata alanı**: BBB FAIL constraint'leri artık `signatures[i].rootCause: {key, message}` ile **tek bir** kök neden olarak dönüyor (önceki turda eklenen `failedConstraints[]` array yerine). DSS pipeline'ı tek kök neden için birden fazla NOT_OK üretiyor (XCV-top roll-up + SAV/CV cascade) — backend bunları sessizce filtreliyor. Helper: `AdvancedSignatureVerificationService.selectRootCause` + `collectFailingBbbConstraintDetails`. Yeni model: `io.mersel.dss.verify.api.models.FailedConstraint`. |
| `Unreleased` | **Opt-in DSS DetailedReport JSON**: `?includeDetailedReport=true` query parameter ile response top-level'ında `detailedReport: XmlDetailedReport` alanı doldurulur — `Reports.getDetailedReportJaxb()` JAXB modeli, Spring Boot / Jackson tarafından yapısal JSON'a serialize edilir (tüm imzalar için BBB blokları + SubXCV katmanları). XML değil JSON: tag duplication yok, frontend native navigate, ~%42 daha küçük (global `spring.jackson.default-property-inclusion=non_null` ile). Default kapalı, NON_NULL ile alan görünmez. Forensic, audit, regresyon kanıtı için. Helper: `AdvancedSignatureVerificationService.attachDetailedReport`. |
