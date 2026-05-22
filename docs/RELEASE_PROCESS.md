# Release Süreci & Versioning

> Mersel DSS Verify API'nin release hattı, **immutable** (değişmez) ve
> **audit-trail-friendly** (kanıtlanabilir) olmak üzere tasarlandı.
> Her release'in **hangi commit'ten**, **hangi CI run'undan**, **hangi
> timestamp'te** üretildiği hem JAR manifest'ine, hem Spring Boot
> `build-info.properties` dosyasına gömülü olduğundan production'da
> çalışan bir instance'ın provenance'ı tek HTTP çağrısıyla doğrulanabilir.

---

## İçindekiler

1. [Versioning Politikası](#versioning-politikası)
2. [Immutability Garantileri](#immutability-garantileri)
3. [CHANGELOG Disiplini](#changelog-disiplini)
4. [Release Akışı (Adım Adım)](#release-akışı-adım-adım)
5. [Otomatik CI/CD Bileşenleri](#otomatik-cicd-bileşenleri)
6. [Runtime Doğrulama (Build Provenance)](#runtime-doğrulama-build-provenance)
7. [Hotfix & Rollback Senaryosu](#hotfix--rollback-senaryosu)
8. [SSS](#sss)

---

## Versioning Politikası

### SemVer 2.0.0

Sürüm numarası **`MAJOR.MINOR.PATCH`** formatındadır:

| Parça | Anlamı | Ne zaman artırılır |
|---|---|---|
| **MAJOR** | Geriye uyumsuz API değişikliği | Kamu API kontratı kırılırsa (endpoint kaldırma, response şeması değişimi, env var rename) |
| **MINOR** | Geriye uyumlu yeni özellik | Yeni endpoint, yeni imza formatı desteği, yeni opsiyonel parametre |
| **PATCH** | Geriye uyumlu hata düzeltmesi | Bug fix, performans iyileştirme, dependency security update |

Pre-release etiketleri: `-rc.N`, `-beta.N`, `-alpha.N` (örn. `1.0.0-rc.1`).
Pre-release sürümleri GitHub Release'de **prerelease** flag'i ile yayınlanır.

### Tag Formatı

- Git tag: **`vX.Y.Z`** (`v` prefix'i zorunlu; örn. `v0.2.0`, `v1.0.0-rc.1`)
- Tag oluşturulduğu commit, o sürümün **tek doğru kaynak commit'idir**.
- Tag annotated olmalı (`git tag -a`). Mümkünse signed (`git tag -s`).

### pom.xml Tek Doğruluk Kaynağı

Sürüm bilgisi **yalnızca** `pom.xml`'in proje-level `<version>` elementinde
tanımlıdır. Diğer her yer (CHANGELOG header'ı, GitHub Release tag'i,
Docker image tag'i, JAR manifest'i) buradan **türetilir**. Tag → pom version
eşleşmesi `release.yml` workflow'unda **build-time doğrulanır** —
uyuşmazlık fail.

---

## Immutability Garantileri

| # | Kural | Nerede uygulanır |
|---|---|---|
| 1 | **Tag bir kere oluşturulup push edildikten sonra silinmemeli/taşınmamalı** | İnsan kuralı + `release.sh` lokal kontrol |
| 2 | **Aynı tag için ikinci kez GitHub Release oluşturulmaz** | `release.yml` job `validate`'da `gh release view` ile pre-check |
| 3 | **`-SNAPSHOT` versiyonlar tag'lenemez** | `release.sh` + `release.yml` her ikisi de regex kontrolü |
| 4 | **Tag commit'i ile pom.xml versiyonu eşleşmek zorunda** | `release.yml` validate job |
| 5 | **JAR'a build-revision (commit SHA) + build-time gömülür** | `pom.xml` `maven-jar-plugin` manifestEntries + `spring-boot-maven-plugin` build-info goal |
| 6 | **SHA-256 checksum yayınlanır** | `release.yml` build job |
| 7 | **CycloneDX SBOM yayınlanır** | `pom.xml` cyclonedx-maven-plugin + `release.yml` |
| 8 | **Reproducible build timestamp**: commit'in author date'i kullanılır | `release.yml` `-Dproject.build.outputTimestamp` |

### Neden Mutable Release Kötüdür?

Eski bir tag'in altındaki commit değiştirilirse:

- Aynı versiyona ait JAR'ı farklı zamanlarda indiren iki kullanıcı **farklı bytes**
  alır → reproducible audit imkansızlaşır.
- Üretimde çalışan instance'ın "hangi kod" olduğu belirsiz hale gelir.
- Kayıtlı vulnerability fix'leri (CVE) eski sürümlerin değişmediği varsayımına
  dayanır; mutation bu varsayımı kırar.

Bu sebeple eski bir release'i geri çağırmanın **tek doğru yolu** yeni bir
PATCH sürüm yayınlamaktır.

---

## CHANGELOG Disiplini

[Keep a Changelog 1.0.0](https://keepachangelog.com/en/1.0.0/) formatına uyulur:

```markdown
## [Unreleased]

### Added
- Yeni XAdES-T zaman damgası desteği (#42).

### Fixed
- GİB Mali Mühür DER-encoded ECDSA imza doğrulama hatası düzeltildi (#43).

### Changed
- Default verification policy STRICT olarak güncellendi.

### Deprecated
- `/v1/verify/xades` endpoint'i; `/api/v1/verify/signature` kullanın.

### Removed
- Eski `SignatureCallback` interface'i (v0.1.0'da deprecated edilmişti).

### Security
- DSS 6.3.1 → 6.3.2 (CVE-2026-XXXX).

## [0.1.0] - 2026-03-11
...
```

### PR Kuralı

PR `src/main/`, `src/test/`, `pom.xml`, `devops/`, `scripts/` (test data generator'lar hariç) veya
`.github/workflows/` altında bir dosyayı değiştiriyorsa, **CHANGELOG.md'nin
`[Unreleased]` bölümüne karşılık gelen bir giriş eklenmelidir**.

Bu otomatik olarak `changelog-check.yml` PR workflow'unda kontrol edilir.

**Bypass** (sadece trivial değişiklikler için):
- PR title veya commit message'a `[skip changelog]` ekleyin.

### Release Anında

`release.sh` scripti çağrıldığında `[Unreleased]` başlığı korunur ama hemen
altına **yeni sürüm başlığı eklenir**:

```diff
 ## [Unreleased]

+## [0.2.0] - 2026-05-22
+
 ### Added
 - ...
```

Yani `[Unreleased]` her zaman var ve boş — bir sonraki dev için hazır.

---

## Release Akışı (Adım Adım)

### Ön Koşullar

- `main` branch'inde olmalı, working tree temiz.
- `CHANGELOG.md`'nin `[Unreleased]` bölümünde release'lenecek değişiklikler birikmiş olmalı.
- Local'de `mvn`, `git`, `perl` kurulu.
- (Opsiyonel ama önerilir) GPG/SSH commit imzalama key'i set edilmiş: `git config user.signingkey ...`

### 1. Lokal Release Hazırlığı

```bash
# Patch release (örn. 0.1.0 → 0.1.1)
./scripts/release.sh patch

# Minor release
./scripts/release.sh minor

# Major release
./scripts/release.sh major

# Pre-release candidate
./scripts/release.sh 0.2.0-rc.1

# Explicit version
./scripts/release.sh 1.0.0

# Dry-run (hiçbir şeyi değiştirmeden ne olacağını gör)
./scripts/release.sh patch --dry-run
```

Script şunları yapar:
1. ✓ Working tree temiz mi kontrolü
2. ✓ Branch kontrolü (main üstünde miyiz?)
3. ✓ Tag çakışması (lokal + remote)
4. ✓ `pom.xml` sürümünü bump'lar
5. ✓ `CHANGELOG.md`'yi finalize eder (`[Unreleased]` → `[X.Y.Z] - YYYY-MM-DD`)
6. ✓ `mvn test` koşar (`--no-test` ile atlanabilir)
7. ✓ `mvn package -DskipTests` koşar (`--no-build` ile atlanabilir)
8. ✓ `release: vX.Y.Z` commit'i oluşturur
9. ✓ Annotated (mümkünse signed) `vX.Y.Z` tag'i atar
10. ⏸ **Push'u sana bırakır** (manuel onay)

### 2. Remote'a Push

```bash
git push origin main
git push origin v0.2.0
```

### 3. CI/CD Otomatik Akışı

Tag push'undan itibaren paralel olarak:

```
v0.2.0 tag push
   │
   ├─→ release.yml         ─► validate → build → publish (GitHub Release)
   │                              │           │
   │                              │           ├── mersel-dss-verify-api-0.2.0.jar
   │                              │           ├── mersel-dss-verify-api-0.2.0.jar.sha256
   │                              │           ├── mersel-dss-verify-api-0.2.0-sources.jar
   │                              │           ├── mersel-dss-verify-api-0.2.0-sbom.json
   │                              │           ├── mersel-dss-verify-api-0.2.0-sbom.xml
   │                              │           └── RELEASE_NOTES.md (CHANGELOG'tan)
   │
   └─→ docker-publish.yml  ─► build → push ghcr.io/.../mersel-dss-verifier-api-java:0.2.0
                                                                                       :0.2
                                                                                       :latest
```

### 4. Doğrulama

```bash
# GitHub Release'i kontrol et
gh release view v0.2.0

# JAR'ı indir ve checksum doğrula
gh release download v0.2.0 -p '*.jar' -p '*.jar.sha256'
sha256sum -c mersel-dss-verify-api-0.2.0.jar.sha256

# JAR'a gömülü provenance'ı oku
unzip -p mersel-dss-verify-api-0.2.0.jar META-INF/MANIFEST.MF | grep -E 'Build|Implementation'
unzip -p mersel-dss-verify-api-0.2.0.jar BOOT-INF/classes/META-INF/build-info.properties
```

---

## Otomatik CI/CD Bileşenleri

| Dosya | Tetiklenme | İşlevi |
|---|---|---|
| `.github/workflows/release.yml` | `v*` tag push, `workflow_dispatch` | JAR + SBOM + checksum + GitHub Release |
| `.github/workflows/docker-publish.yml` | `main` push, `v*` tag push | GHCR Docker imajı yayınlama |
| `.github/workflows/changelog-check.yml` | PR (non-draft) | CHANGELOG güncelliği kontrolü |

| Script | Konum | İşlevi |
|---|---|---|
| `release.sh` | `scripts/` | Lokal release hazırlama (pom + CHANGELOG + tag) |
| `bump-version.sh` | `scripts/` | `pom.xml` sürüm bump (major/minor/patch/rc/explicit) |
| `extract-release-notes.sh` | `scripts/` | CHANGELOG.md'den ilgili sürüm bölümünü çıkar |
| `build-release-notes.sh` | `scripts/` | Release notes + build provenance footer |
| `check-changelog-updated.sh` | `scripts/` | PR-time CHANGELOG güncellik kontrolü |

---

## Runtime Doğrulama (Build Provenance)

Üretilen JAR'a hem `MANIFEST.MF` hem `META-INF/build-info.properties`
düzeyinde build metadata gömülür. Çalışan instance üzerinde HTTP ile
sorgulanabilir:

### Endpoint: `/actuator/info`

```bash
curl -s http://verify-host:8086/actuator/info | jq .
```

Örnek yanıt:

```json
{
  "build": {
    "artifact": "mersel-dss-verify-api",
    "name": "mersel-dss-verify-api",
    "time": "2026-05-22T13:30:00Z",
    "version": "0.2.0",
    "group": "io.mersel.dss",
    "revision": "9a3b1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b",
    "buildNumber": "127",
    "buildTime": "2026-05-22T13:30:00Z",
    "buildHost": "Linux-X64",
    "buildJdk": "1.8",
    "buildOs": "Linux amd64"
  }
}
```

### JAR İçinden Doğrulama

```bash
unzip -p mersel-dss-verify-api-0.2.0.jar META-INF/MANIFEST.MF | grep -E 'Implementation|Build'
```

Çıktı:

```
Implementation-Title: mersel-dss-verify-api
Implementation-Version: 0.2.0
Implementation-Vendor: Mersel DSS
Build-Time: 2026-05-22T13:30:00Z
Build-Revision: 9a3b1c2d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b
Build-Number: 127
Build-Jdk: 1.8
Built-By: mersel-dss-ci
X-Mersel-Component: verify-api
```

### SBOM (Supply-Chain)

Her release'de `mersel-dss-verify-api-X.Y.Z-sbom.json` (CycloneDX 1.5)
yayınlanır. OWASP Dependency-Track veya `cyclonedx-cli` ile CVE
taraması yapılabilir:

```bash
cyclonedx-cli analyze --input-file mersel-dss-verify-api-0.2.0-sbom.json
```

---

## Hotfix & Rollback Senaryosu

### Bozuk Bir Release Yayınladım, Ne Yaparım?

**Yapmaman gereken**: Tag'i silip yeniden push etmek. Bu, JAR'ı önceden
indirmiş kullanıcıların elindeki bytes ile remote'taki bytes arasında
sessiz bir uyumsuzluk yaratır.

**Doğru yol**:

1. Bug fix'i `main`'e merge et.
2. `./scripts/release.sh patch` → yeni patch sürümü (örn. 0.2.1) yayınla.
3. Bozuk olan eski release'i GitHub'da **"deprecated" notuyla işaretle**
   ama silme — referans/audit için kalsın:

   ```bash
   gh release edit v0.2.0 --notes "⚠️ DEPRECATED: v0.2.0'da ECDSA preprocessor
   regresyonu vardı. Lütfen v0.2.1 veya üzerini kullanın."
   ```

4. Docker imajını yeniden tag'le: `ghcr.io/.../mersel-dss-verifier-api-java:0.2`
   ve `:latest` pointer'larını v0.2.1'e güncelle (Docker workflow zaten yapar).

### Hotfix Branch'i

Eski bir MAJOR/MINOR sürüm hâlâ destekleniyor ve oraya backport gerekiyorsa:

```bash
git checkout -b hotfix/v0.1.x v0.1.0
# fix commit'lerini cherry-pick et
./scripts/release.sh 0.1.1
git push origin hotfix/v0.1.x v0.1.1
```

---

## SSS

### "Release notes" otomatik mi yazılıyor?

CHANGELOG.md'nin `[X.Y.Z]` bölümünden **otomatik çıkartılır** ve GitHub Release
body'sine yazılır. Üzerine bir "Build Provenance" tablosu (tag, commit, build time,
build number, artifact listesi, runtime doğrulama komutu) eklenir. Yani **insan
yazımı changelog + otomatik provenance** = release notes.

### Conventional Commits zorunlu mu?

Zorunlu değil ama önerilir (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`).
CHANGELOG.md insan tarafından küratörce yazılıyor — Conventional Commits
otomatik changelog üretimi için değil, sadece commit history okunabilirliği için.

### Pre-release nasıl yayınlanır?

```bash
./scripts/release.sh 0.2.0-rc.1
```

`release.yml` workflow `-` içeren tag'leri otomatik olarak GitHub'da
**Pre-release** flag'i ile işaretler. Pre-release'ler `latest` Docker tag'ini
güncellemez.

### Workflow başarısız oldu, tag zaten push edildi. Ne yaparım?

`release.yml` idempotent'tir. Workflow re-run edildiğinde:
- Eğer GitHub Release zaten oluşmuşsa → skip.
- Henüz oluşmamışsa → kaldığı yerden devam (build + publish).

`workflow_dispatch` ile re-run da edebilirsin.

### "Reproducible build" gerçekten reproducible mı?

Evet, ama bir avuç koşulla:
- Aynı commit'ten build edildiğinde aynı bytes çıkar (Maven 3.6.1+ ile
  `project.build.outputTimestamp` set edildiği için).
- JDK, Maven, runner OS aynı olmalı (aksi takdirde JAR `META-INF/services`
  sıralaması veya `.class` bytecode'da küçük farklar olabilir).
- `mvn package` çağrısında `mersel.build.revision`, `mersel.build.number`,
  `mersel.build.timestamp` property'leri **release ile aynı değerlerle** verilmeli;
  aksi takdirde bu üç değer manifest'te farklı görünür (içerik üretim semantiği bozulmaz).

### CycloneDX SBOM'u nasıl tüketirim?

Birkaç pratik kullanım:

```bash
# Tüm dependency'leri listele
jq -r '.components[] | "\(.group):\(.name):\(.version)"' bom.json

# OWASP Dependency-Track API'ye yükle
curl -X POST -H "X-Api-Key: $DT_KEY" \
  -F "bom=@mersel-dss-verify-api-0.2.0-sbom.json" \
  https://dt.example.org/api/v1/bom

# CycloneDX CLI ile vulnerability tarama
cyclonedx-cli analyze --input-file bom.json
```

---

> **Sorularınız mı var?** Issue açın ([etiket: `release`](../../issues?q=label%3Arelease)).
