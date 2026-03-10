# GitHub Actions Workflows

## Docker Build & Publish

Bu workflow, verify-api projesini otomatik olarak derler, testleri çalıştırır ve GitHub Container Registry'ye (ghcr.io) yükler.

### Tetiklenme Koşulları

Workflow aşağıdaki durumlarda otomatik olarak çalışır:

1. **Push Events:**
   - `main` branch'e push
   - Version tag'i (örn: `v1.0.0`) push edildiğinde

2. **Manuel Tetikleme:**
   - GitHub Actions sekmesinden "Run workflow" ile manuel olarak çalıştırılabilir

### Jobs

Workflow iki aşamalı çalışır:

1. **test** - Maven ile build ve test
2. **docker** - Docker image build, GHCR'a push ve smoke test

### Gerekli GitHub Secrets

GHCR için ek secret tanımlamaya gerek yoktur. `GITHUB_TOKEN` otomatik olarak sağlanır.

Tek gereksinim: Repository Settings > Actions > General > Workflow permissions bölümünde **"Read and write permissions"** seçili olmalıdır.

### Docker Image Tag Stratejisi

Workflow otomatik olarak aşağıdaki tag'leri oluşturur:

- `latest`: Main branch'ten build edildiğinde
- `main`: Main branch ref tag'i
- `1.0.0`: Version tag'i push edildiğinde (`v1.0.0`)
- `1.0`: Minor version tag
- `main-abc1234`: Branch adı ve commit SHA

### Kullanım Örnekleri

#### 1. Production Release

```bash
git checkout main
git add .
git commit -m "feat: yeni özellik"
git push origin main

# Version tag ekle
git tag v1.0.0
git push origin v1.0.0
```

Bu aşağıdaki image'leri oluşturur:
- `ghcr.io/mersel-dss/mersel-dss-verifier-api-java:latest`
- `ghcr.io/mersel-dss/mersel-dss-verifier-api-java:1.0.0`
- `ghcr.io/mersel-dss/mersel-dss-verifier-api-java:1.0`

#### 2. Manuel Çalıştırma

1. GitHub repository'de Actions sekmesine gidin
2. "Docker Build & Publish" workflow'unu seçin
3. "Run workflow" butonuna tıklayın
4. Branch seçin ve "Run workflow" ile başlatın

### Docker Image Kullanımı

Build edilen image'leri çekmek için:

```bash
# Latest version
docker pull ghcr.io/mersel-dss/mersel-dss-verifier-api-java:latest

# Specific version
docker pull ghcr.io/mersel-dss/mersel-dss-verifier-api-java:1.0.0
```

### Workflow Özellikleri

- ✅ GitHub Container Registry (ghcr.io) entegrasyonu
- ✅ Multi-architecture build (linux/amd64, linux/arm64)
- ✅ Maven dependency caching
- ✅ Docker layer caching (GitHub Actions cache)
- ✅ Automated testing (test job)
- ✅ Smoke test (health check doğrulaması)
- ✅ Semantic versioning support

### Troubleshooting

#### Build Başarısız Oluyor

1. Actions sekmesinde failed workflow'u açın
2. Failed step'in loglarını inceleyin
3. Maven build hatalarını kontrol edin

#### GHCR'a Push Yapamıyor

1. Repository Settings > Actions > General > Workflow permissions bölümünü kontrol edin
2. "Read and write permissions" seçili olmalı
3. Organization seviyesinde package write izni verildiğinden emin olun

#### Image Çekilemiyor

1. Image visibility'yi kontrol edin (Settings > Packages)
2. Public yapmak için: Package Settings > Change visibility > Public
3. Private ise: `docker login ghcr.io -u USERNAME -p GITHUB_TOKEN`

### Best Practices

1. **Version Tags**: Semantic versioning kullanın (v1.0.0, v1.1.0, vs.)
2. **Commit Messages**: Conventional commits kullanın (feat:, fix:, vs.)
3. **Testing**: Main branch'e merge öncesi PR açın ve testlerin geçmesini bekleyin
4. **Security**: GITHUB_TOKEN otomatik yönetilir, ek secret gerekmez
