# GitHub Actions Workflows

## Docker Build and Push

Bu workflow, verify-api projesini otomatik olarak derler ve Docker Hub'a yükler.

### Tetiklenme Koşulları

Workflow aşağıdaki durumlarda otomatik olarak çalışır:

1. **Push Events:**
   - `main` branch'e push
   - `develop` branch'e push
   - Version tag'i (örn: `v1.0.0`) push edildiğinde

2. **Pull Request:**
   - `main` branch'e PR açıldığında (sadece build, push yapmaz)

3. **Manuel Tetikleme:**
   - GitHub Actions sekmesinden "Run workflow" ile manuel olarak çalıştırılabilir

### Gerekli GitHub Secrets

Workflow'un çalışması için aşağıdaki secrets'ların repository settings'de tanımlanması gerekir:

1. **DOCKERHUB_USERNAME**: Docker Hub kullanıcı adınız
2. **DOCKERHUB_TOKEN**: Docker Hub access token'ınız

#### Docker Hub Token Oluşturma

1. Docker Hub'a giriş yapın
2. Account Settings > Security > New Access Token
3. Token'a bir isim verin (örn: "GitHub Actions")
4. "Read, Write, Delete" yetkilerini seçin
5. Generate edilen token'ı kopyalayın

#### GitHub Secrets Ekleme

1. GitHub repository'nizde Settings > Secrets and variables > Actions
2. "New repository secret" butonuna tıklayın
3. Her bir secret için:
   - Name: `DOCKERHUB_USERNAME` veya `DOCKERHUB_TOKEN`
   - Value: İlgili değeri girin

### Docker Image Tag Stratejisi

Workflow otomatik olarak aşağıdaki tag'leri oluşturur:

- `latest`: Main branch'ten build edildiğinde
- `develop`: Develop branch'ten build edildiğinde
- `v1.0.0`: Version tag'i push edildiğinde
- `1.0`: Minor version tag
- `1`: Major version tag
- `main-abc1234`: Branch adı ve commit SHA

### Kullanım Örnekleri

#### 1. Development Build

```bash
# Develop branch'e push
git checkout develop
git add .
git commit -m "feat: yeni özellik"
git push origin develop
```

Bu `yourusername/verify-api:develop` image'ini oluşturur.

#### 2. Production Release

```bash
# Main branch'e merge
git checkout main
git merge develop
git push origin main

# Version tag ekle
git tag v1.0.0
git push origin v1.0.0
```

Bu aşağıdaki image'leri oluşturur:
- `yourusername/verify-api:latest`
- `yourusername/verify-api:v1.0.0`
- `yourusername/verify-api:1.0`
- `yourusername/verify-api:1`

#### 3. Manuel Çalıştırma

1. GitHub repository'de Actions sekmesine gidin
2. "Build and Push Verify API Docker Image" workflow'unu seçin
3. "Run workflow" butonuna tıklayın
4. Branch seçin ve "Run workflow" ile başlatın

### Docker Image Kullanımı

Build edilen image'leri çekmek için:

```bash
# Latest version
docker pull yourusername/verify-api:latest

# Specific version
docker pull yourusername/verify-api:v1.0.0

# Development version
docker pull yourusername/verify-api:develop
```

### Workflow Özellikleri

- ✅ Multi-architecture build (linux/amd64, linux/arm64)
- ✅ Maven dependency caching
- ✅ Docker layer caching
- ✅ Automated testing
- ✅ Docker Hub README sync
- ✅ Semantic versioning support

### Troubleshooting

#### Build Başarısız Oluyor

1. Actions sekmesinde failed workflow'u açın
2. Failed step'in loglarını inceleyin
3. Maven build hatalarını kontrol edin

#### Docker Hub'a Push Yapamıyor

1. DOCKERHUB_USERNAME ve DOCKERHUB_TOKEN secrets'larını kontrol edin
2. Docker Hub token'ın süresi dolmamış olduğundan emin olun
3. Token'ın "Write" yetkisine sahip olduğunu doğrulayın

#### Image Çekilemiyor

1. Docker Hub'da image'in public olduğundan emin olun
2. Doğru tag'i kullandığınızı kontrol edin
3. Docker Hub'da login olduğunuzdan emin olun (private repo ise)

### Best Practices

1. **Version Tags**: Semantic versioning kullanın (v1.0.0, v1.1.0, vs.)
2. **Commit Messages**: Conventional commits kullanın (feat:, fix:, vs.)
3. **Testing**: Main branch'e merge öncesi PR açın ve testlerin geçmesini bekleyin
4. **Security**: Token'larınızı asla code'a commit etmeyin

### İletişim

Sorularınız için issue açabilirsiniz.

