# INVALID Signature Notifications — Operatör Rehberi

Bu doküman, **Mersel DSS Verifier API**'nin bir imza doğrulama sonucu
`INVALID` olduğunda kuracağı bildirim mekanizmasını anlatır:

- **Generic webhook** — operatörün kendi alert/ticket/audit sistemine
  JSON POST (full DSS sonucu + opsiyonel base64 içerik + HMAC imza)
- **Slack incoming webhook** — Slack kanalında kırmızı yan-şerit'li
  Block Kit alarm mesajı
- **Slack-only inline base64** — operatörün bot token / external storage
  kuramayacağı senaryolar için: dosya base64 + code block olarak
  doğrudan Slack mesajının **içine** gömülür (tek URL kurulum)
- **Slack bot file upload** — aynı anda dosyayı kanala indirilebilir
  ek olarak yükleme (yeni 3-adımlı Slack API)

Tüm bu kanallar **birbirinden bağımsız**dır; sadece ilgili env
değişkenleri set edilerek aktivasyon yapılır. Servisin doğrulama akışı
asla bildirim hatasından etkilenmez (best-effort, async).

---

## 1. Hızlı başlangıç

```bash
# A) Sadece generic webhook'una alert at:
export INVALID_SIGNATURE_WEBHOOK_URL=https://alerts.example.com/hooks/mersel-dss
export INVALID_SIGNATURE_WEBHOOK_SECRET=$(openssl rand -hex 32)  # önerilir

# B) Sadece Slack'e kırmızı alert mesajı:
export INVALID_SIGNATURE_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/XXX

# C) ÖNERİLEN — Slack mesajına ek olarak dosyayı da indirilebilir ek olarak yükle:
#    Slack ekosisteminin İÇİNDE kalır (files.slack.com), 1GB'a kadar.
#    e-Belge XML'leri (>250KB~) için TEK doğru yol.
export INVALID_SIGNATURE_SLACK_BOT_TOKEN=xoxb-…
export INVALID_SIGNATURE_SLACK_CHANNEL=C0123456789  # kanal ADI değil, ID

# D) Bot token kuramıyorsan VE dosyalar ≤28KB ise: dosyayı Slack mesajının İÇİNE göm.
#    Yalnız incoming webhook URL yetiyor — harici depo yok, bot yok.
#    Default 8KB cap; küçük XAdES tek-imza dosyaları için ideal.
#    DİKKAT: >28KB için Slack mesaj 40k char limitini aşar → C seçeneğine geç.
export INVALID_SIGNATURE_SLACK_INLINE_BASE64_ENABLED=true
export INVALID_SIGNATURE_SLACK_INLINE_BASE64_MAX_BYTES=8192  # default; max ~28000 güvenli

# Gizlilik kısıtı varsa base64 içeriği gönderme (sadece metadata + sha256):
export INVALID_SIGNATURE_NOTIFICATION_INCLUDE_CONTENT=false

# Geçici susturma (URL'leri sökmeden):
export INVALID_SIGNATURE_NOTIFICATION_ENABLED=false
```

---

## 2. Hangi modu seçeyim? — Boyut bazlı karar rehberi

Tipik dosya boyutunuza göre **en doğru** dağıtım modu:

| Tipik dosya boyutu | Önerilen mod | Neden |
|---|---|---|
| **≤8KB** (XAdES tek-imza, küçük UBL) | Slack-only inline base64 | Tek-URL kurulum; chat'te direkt görünür |
| **8KB – 28KB** (orta XAdES, çok-imzalı) | Slack-only inline base64 + `MAX_BYTES` arttır | Hâlâ tek-URL; Slack 40k char mesaj limitiyle ⚠️ dikkatli (binary ≤28KB güvenli üst sınır) |
| **>28KB** (PDF imzalı fatura, 250KB UBL paketi…) | **Slack bot file upload** | Inline'a fiziksel SIĞMIYOR; bot upload Slack ekosisteminin İÇİNDE kalır (`files.slack.com`), 1GB'a kadar |
| Çok büyük (>10MB) veya gizlilik kritik | Generic webhook + receiver tarafında base64 dump | Slack zaten 1GB üstünü almaz; receiver tarafında kontrollü arşivleme |

**Matematik özet** — neden 250KB inline'a sığmaz:

```
binary boyutu × 4/3 (base64 expansion) ≈ Slack mesajındaki char
+ Block Kit overhead + decode hint + chunk fences
─────────────────────────────────────────────
ÜST SINIR: Slack mesajı toplam 40,000 char (sert sınır)

250KB × 4/3 = ~333,000 char    →   8× kat fazla, REDDEDİLİR (400 invalid_blocks)
 28KB × 4/3 =  ~37,300 char    →   güvenli üst sınır
  8KB × 4/3 =  ~10,900 char    →   default; ~5 chunk, rahatça sığar
```

---

## 3. Aktivasyon matrisi

| Env Var Set | Etki |
|---|---|
| `INVALID_SIGNATURE_WEBHOOK_URL` | Generic webhook aktif |
| `INVALID_SIGNATURE_WEBHOOK_URL` + `INVALID_SIGNATURE_WEBHOOK_SECRET` | Generic webhook + HMAC imza |
| `INVALID_SIGNATURE_SLACK_WEBHOOK_URL` | Slack kanal mesajı (kırmızı bantlı, sade alarm) |
| `INVALID_SIGNATURE_SLACK_WEBHOOK_URL` + `INVALID_SIGNATURE_SLACK_INLINE_BASE64_ENABLED=true` | Slack mesajı + dosya inline base64 (tek-URL, single-URL mod) |
| `INVALID_SIGNATURE_SLACK_BOT_TOKEN` + `INVALID_SIGNATURE_SLACK_CHANNEL` | Slack'e indirilebilir dosya upload (her boyut, ayrı download) |
| Hiçbiri | No-op (sıfır network/heap maliyeti) |
| `INVALID_SIGNATURE_NOTIFICATION_ENABLED=false` | Hepsi susturulur (URL'ler kalsa bile) |

> **Önemli**: Slack bot file upload için **hem token hem kanal ID**
> gerekli. Token tek başına aktivasyon için yetmez (Slack
> `completeUploadExternal` API'si çağrıyı channel ile bağlar).

---

## 4. Generic webhook payload şeması

```json
{
  "event": "invalid-signature",
  "source": "mersel-dss-verify-api/0.3.1",
  "notificationTime": "2026-05-24T15:13:20.000+00:00",
  "file": {
    "name": "fatura-2026-00042.xml",
    "sizeBytes": 18234,
    "contentType": "application/xml",
    "sha256Hex": "a3f8c9b1...",
    "base64Content": "PD94bWwgdmVyc2lvbj0iMS4wIiB...",
    "contentOmittedReason": null
  },
  "originalDocument": null,
  "result": {
    "valid": false,
    "status": "INVALID",
    "signatureType": "XADES",
    "signatures": [{
      "signatureId": "Signature-1",
      "valid": false,
      "indication": "INDETERMINATE",
      "subIndication": "SIG_CONSTRAINTS_FAILURE",
      "signatureFormat": "XAdES-BASELINE-B",
      "signerCertificate": { /* CertificateInfo */ },
      "certificateChain": [ /* tüm zincir, COMPREHENSIVE modda */ ],
      "appliedRejections": [{
        "code": "MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
        "title": "...",
        "reason": "...",
        "evidence": { /* somut tanı verisi */ }
      }],
      "validationDetails": { /* COMPREHENSIVE modda */ }
    }],
    "errors": [ "..." ],
    "warnings": [ "..." ]
  }
}
```

**Önemli alanlar**:

- `result` — DSS doğrulama sonucu **olduğu gibi** gömülür. Receiver
  ayrı bir kısaltma kontratı parse etmek zorunda değildir; verification
  endpoint'inin döndürdüğü her şey burada da var.
- `file.base64Content` — `INVALID_SIGNATURE_NOTIFICATION_INCLUDE_CONTENT=false`
  veya dosya `INVALID_SIGNATURE_NOTIFICATION_MAX_CONTENT_SIZE_BYTES`
  (default 10MB) üstündeyse **null** gelir; bu durumda
  `contentOmittedReason` doludur (`EXCLUDED_BY_CONFIG` veya
  `EXCEEDED_MAX_SIZE`).
- `file.sha256Hex` — her zaman doludur (içerik atlansa bile).
  Receiver dosyayı kendi arşivinden eşleştirebilsin diye.
- `originalDocument` — sadece XAdES detached imzada doludur
  (CAdES/PAdES'te `null`).

---

## 5. Webhook HTTP header'ları & HMAC doğrulama

| Header | Her zaman | Açıklama |
|---|---|---|
| `X-Mersel-Event: invalid-signature` | ✅ | Event tipi |
| `X-Mersel-Webhook-Id: <uuid>` | ✅ | Her bildirim için eşsiz — idempotency |
| `X-Mersel-Webhook-Timestamp: <epoch-seconds>` | ✅ | Replay protection |
| `X-Mersel-Signature: sha256=<hex>` | Secret set ise | HMAC-SHA256(`"{ts}.{rawBody}"`, secret) |
| `User-Agent: mersel-dss-verify-api/<ver>` | ✅ | Versiyon |

### Receiver tarafında doğrulama (Node.js örneği)

```javascript
const crypto = require('crypto');

function verifyMerselWebhook(req, secret) {
  const sigHeader = req.headers['x-mersel-signature'];
  const ts = req.headers['x-mersel-webhook-timestamp'];
  const rawBody = req.rawBody;  // Express: body-parser raw veya bytes

  // 1) Replay protection: timestamp 5 dakikadan eski olmasın
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(ts, 10)) > 300) {
    throw new Error('webhook timestamp out of window');
  }

  // 2) HMAC kontrolü — constant-time karşılaştırma şart
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(`${ts}.${rawBody}`)
    .digest('hex');

  if (!crypto.timingSafeEqual(
        Buffer.from(sigHeader), Buffer.from(expected))) {
    throw new Error('webhook signature mismatch');
  }
}
```

### Python örneği

```python
import hmac, hashlib, time

def verify(headers, raw_body: bytes, secret: str) -> None:
    ts = int(headers['X-Mersel-Webhook-Timestamp'])
    if abs(time.time() - ts) > 300:
        raise ValueError('timestamp out of window')

    expected = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        f'{ts}.'.encode('utf-8') + raw_body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(headers['X-Mersel-Signature'], expected):
        raise ValueError('signature mismatch')
```

### Java örneği

```java
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

static boolean verify(
        String tsHeader, String sigHeader, byte[] rawBody, String secret) {
    long ts = Long.parseLong(tsHeader);
    if (Math.abs(System.currentTimeMillis() / 1000 - ts) > 300) {
        return false;
    }
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
    String message = ts + ".";
    mac.update(message.getBytes(StandardCharsets.UTF_8));
    byte[] computed = mac.doFinal(rawBody);
    StringBuilder hex = new StringBuilder(computed.length * 2);
    for (byte b : computed) hex.append(String.format("%02x", b & 0xff));
    String expected = "sha256=" + hex;
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8),
        sigHeader.getBytes(StandardCharsets.UTF_8));
}
```

> **Constant-time karşılaştırma** zorunlu — `==` veya `equals()` ile
> karşılaştırırsanız timing saldırılarına açık kalırsınız.

---

## 6. Slack incoming webhook mesajı

Mesaj `attachments` legacy field'ı içinde Block Kit ile gönderilir;
bu sayede **mesajın sol tarafında kırmızı dikey şerit** (`#A30200`)
görünür — bir bakışta INVALID alarmı tanıyın.

**İçerik**:
1. **Header** — "🚨 Mersel DSS Verify – INVALID Signature"
2. **Summary fields** — Dosya, Status, İmza Tipi, İmza Sayısı, Doğrulama Zamanı
3. **Hata listesi** — DSS jenerik mesajları + Mersel rejection kodları
   (en fazla 5 satır, kalanlar özetlenir)
4. **Per-signature blok** — indication / subIndication / imzacı CN +
   Mersel rejection kodu (multi-imzalı XML için kritik)

Default'ta base64 içerik Slack mesajına dahil edilmez (chat ergonomi).
Eğer **bot token kurma şansınız yoksa** ve dosyayı yine Slack içinde
istiyorsanız, bir sonraki bölümdeki **inline base64 modu**na bakın.

---

## 7. Slack-only / Single-URL deployment — Inline Base64 (≤28KB)

**Ne zaman lazım?** Bot token + `files:write` scope yönetmek
istemediğiniz/kuramayacağınız durumlar:

- Kurumsal IT politikası bot creation'a izin vermiyor.
- Hızlı POC veya küçük ekip — kurulum yükünü minimize etmek istiyorsunuz.
- Externalde dosya barındıracak yer yok / istemiyorsunuz; her şey
  Slack içinde kalsın.

Bu modda yalnızca **bir tek Slack incoming webhook URL'i** set
edersiniz; doğrulanan dosya base64 olarak Slack mesajının **içine** —
triple-backtick code block içinde — gömülür. Operatör için decode bir
`pbpaste | base64 -d` komutu.

### Aktivasyon

```bash
export INVALID_SIGNATURE_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/XXX
export INVALID_SIGNATURE_SLACK_INLINE_BASE64_ENABLED=true
# Opsiyonel — limit ayarı (default 8192 byte = 8KB)
export INVALID_SIGNATURE_SLACK_INLINE_BASE64_MAX_BYTES=8192
```

> **Opt-in tasarımı**: Default `false`. Operatör bilinçli olarak
> `true` yapmadıkça Slack mesajı sade alarm olarak kalır (chat'i
> base64 dump'larıyla kirletmeme kuralı).

### Boyut sınırı & chunking matematik

| Constraint | Değer | Notlar |
|---|---|---|
| Default `MAX_BYTES` | **8192** (8KB binary) | Base64 expansion 4/3× → ~10.9KB string |
| Slack mesaj toplam limit | 40,000 char | Default 8KB için rahatça altında |
| Block Kit per-section text | **3000 char (TIGHTER)** | Asıl darboğaz; 40k limitten önce vurur |
| Notifier chunk boyu | **2700 char** | 3000 - prefix/code-fence/decode-hint payı |
| Block Kit max blok/mesaj | 50 | 8KB için ~5 chunk yeterli, sınırın çok altında |

Notifier, base64 string'ini otomatik olarak ~2700 char'lık parçalara
böler ve **birden fazla section block**'a basar. Round-trip garantisi:
chunk'lar sırayla concat edildiğinde orijinal base64'e **birebir**
eşit (tek char drift bile dosyayı bozar — test ile korunur).

### Limit aşılırsa ne olur?

Dosya `MAX_BYTES` üstündeyse inline base64 atlanır; mesaj yine gider
ama dosya yerine **omission notice satırı** belirir:

```
*İçerik:* Dosya boyutu (24576 bytes) inline limiti (8192 bytes) aşıyor.
Tam içerik için webhook payload'una veya Slack bot file upload'una başvurun.
```

Sessiz drop YOK — operatör Slack'te dosyanın neden eksik olduğunu
direkt görür.

### Mesaj içinde nasıl görünür?

Slack rendered halinde:

```
🚨 Mersel DSS Verify - INVALID Signature

Dosya: fatura-2026-00042.xml      Status: INVALID
İmza Tipi: XADES                   İmza Sayısı: 1

Hatalar:
• İmza geçersiz: INDETERMINATE (SIG_CONSTRAINTS_FAILURE)

İmza: Signature-1
• Indication: INDETERMINATE / SIG_CONSTRAINTS_FAILURE
• İmzacı: CN=Test Imzaci, O=Mersel, C=TR

İçerik (base64, 1024 bytes):

PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4K...
...continues across chunks if file is larger...

Decode: pbpaste | base64 -d > signed.bin (macOS)
       / xclip -o | base64 -d > signed.bin (Linux)
```

### Alıcı tarafı decode

**Tek-chunk durumu** (küçük dosyalar — ≤2KB binary):

```bash
# Slack'te code block içeriğini seç & kopyala, sonra:
pbpaste | base64 -d > signed.bin      # macOS
xclip -o | base64 -d > signed.bin     # Linux
```

**Multi-chunk durumu** (>2KB binary, birden fazla section block):

Tüm code block içeriklerini sırayla kopyalayın ve tek bir komuta
verin:

```bash
# Slack'teki tüm code block'ların içeriği birleştirilmiş halde clipboard'da:
pbpaste | base64 -d > signed.bin
```

Slack mobil/desktop her ikisinde de code block içeriği seçilebilir
(triple-backtick monospace render sayesinde).

### Bot upload ile karşılaştırma

| Boyut | Inline Base64 (single-URL) | Bot Upload (3-adımlı API) |
|---|---|---|
| **Kurulum** | 1 env var (`INLINE_BASE64_ENABLED=true`) | 4 adım (app oluştur + scope + install + invite) |
| **Bağımlılık** | Yalnız Slack incoming webhook URL | Bot token + kanal ID |
| **Dosya boyutu** | Default ≤8KB (config ile artırılabilir) | Slack default ≤1GB |
| **UX (download)** | Code block seç → terminal'de decode | Tek-tık download |
| **Mobile UX** | Code block selection (kısmen) | Native download |
| **Chat kirliliği** | Code block'lar mesajı uzatır | Mesaj sade, dosya ayrı görünür |

İkisi aynı anda da set edilebilir (bağımsız kanallar); inline base64
operatörün "tek-URL deploy" trade-off'udur.

---

## 8. Slack bot file upload — 250KB+ ve büyük dosyalar için **en doğru yol** (3-adımlı yeni API)

Slack `files.upload` Kasım 2025'te sunset edildi. Modül artık zorunlu
olan 3-adımlı flow'u kullanır:

1. **`POST https://slack.com/api/files.getUploadURLExternal`**
   - Auth: `Bearer xoxb-…`
   - Form params: `filename`, `length`
   - → `{ ok: true, upload_url, file_id }`
2. **`POST <upload_url>`** — raw octet-stream byte'lar
   - Bu istekte token YOK; URL kendi içinde time-bound auth taşır
3. **`POST https://slack.com/api/files.completeUploadExternal`**
   - Auth: `Bearer xoxb-…`
   - JSON: `{ files: [{ id, title }], channel_id, initial_comment }`

### Bot kurulumu — Adım adım (toplam ~4 dakika)

> **Slack workspace'inde admin haklarına ihtiyacın yok**; standart üye
> olarak da Slack app oluşturabilirsin. Workspace admini "Apps must be
> approved" politikası uygulamışsa app **pending** olur, admin
> onaylayınca token gelir. Bu yaygın değil — Slack workspace'inin
> çoğunda direkt çalışır.

#### YÖNTEM A — App Manifest ile hızlı kurulum (önerilen, ~2 dakika)

App Manifest YAML'i Slack'in resmi "bir bot'u tek dosyayla oluştur"
mekanizmasıdır. Aşağıdaki YAML'i kopyala-yapıştır yeterli:

1. **Aç**: <https://api.slack.com/apps?new_app=1>
2. **From an app manifest** seçeneğine tıkla
3. **Pick a workspace** → kendi workspace'ini seç → **Next**
4. **YAML** sekmesini seç (JSON değil), aşağıdaki manifest'i yapıştır:

```yaml
display_information:
  name: Mersel DSS Notify
  description: INVALID imza dogrulama alarmlarini Slack kanalina basar
  background_color: "#A30200"
features:
  bot_user:
    display_name: mersel-dss-notify
    always_online: true
oauth_config:
  scopes:
    bot:
      - files:write       # dosya upload icin yeterli (en az ayricalik)
      - chat:write        # initial_comment ve fallback chat icin
      # NOT: chat:write zaten incoming webhook tarafindan kullaniliyor;
      # bot upload icin yalniz files:write yeterli ama chat:write
      # bot'un kanala once mesaj atip sonra dosya upload etmesini
      # mumkun kilar (Slack tarafindaki bazi edge case'lerde gerekli).
settings:
  org_deploy_enabled: false
  socket_mode_enabled: false
  token_rotation_enabled: false
```

5. **Next** → **Create** butonuna tıkla
6. Sol menü → **Install App** → **Install to <WorkspaceAdı>**
   - Slack onay ekranı çıkar (bot ne yapacak özetle gösterir)
   - **Allow** butonuna tıkla
7. **Bot User OAuth Token** alanından `xoxb-...` token'ı **Copy**
   butonuyla kopyala — bu senin `INVALID_SIGNATURE_SLACK_BOT_TOKEN`
   değerin.

> Token formatı: `xoxb-` ile başlar, ~70 char uzunluğunda. Eğer
> `xapp-` ile başlıyorsa **app-level token** kopyalamışsındır; o
> değil, **bot user OAuth token**'ı seç.

---

#### YÖNTEM B — Manuel UI tıklama (eğer manifest çalışmazsa, ~5 dakika)

1. **Aç**: <https://api.slack.com/apps>
2. **Create New App** → **From scratch**
3. **App Name**: `Mersel DSS Notify` (istediğin isim olabilir)
   **Pick a workspace**: kendi workspace'in → **Create App**
4. Sol menü → **OAuth & Permissions**
   - Aşağı kaydır → **Scopes** bölümü → **Bot Token Scopes**
   - **Add an OAuth Scope** → `files:write` ekle
   - (Opsiyonel) `chat:write` da ekle (önerilir; bazı Slack edge
     case'leri için)
5. Sol menü → **App Home**
   - **Your App's Presence in Slack** → **Edit** butonuyla bot
     display name'i set et (örn. `mersel-dss-notify`)
6. Sol menü → **Install App** → **Install to Workspace**
   - Slack onay ekranı → **Allow**
7. **Bot User OAuth Token** (`xoxb-...`) görünür → **Copy**

---

#### Kanal ID'sini bulma (3 yöntem; en kolayı 1.)

**Yöntem 1 — Slack desktop UI** (en hızlı):

1. Slack uygulamasında alarm gitmesini istediğin kanala git
2. Kanal başlığına tıkla (en üstte kanal adının olduğu yer)
3. Açılan paneli en aşağı kaydır
4. **Channel ID** alanı görünür: `C0123ABCD45` formatında →
   **Copy** butonuna tıkla

**Yöntem 2 — Slack web URL'inden**:

Slack'i tarayıcıda aç, kanala tıkla. URL şu şekilde olur:

```
https://app.slack.com/client/T01234ABCD/C0123ABCD45
                              ^team-id  ^channel-id (bu sana lazım)
```

URL'in son segmenti kanal ID'sidir.

**Yöntem 3 — Slack API çağrısı** (otomasyon için):

```bash
curl -X GET 'https://slack.com/api/conversations.list?limit=200' \
  -H "Authorization: Bearer xoxb-..." | jq '.channels[] | {name, id}'
```

---

#### Kanala bot'u ekleme (kritik adım!)

Bot, mesaj atacağı / dosya yükleyeceği kanala **explicit olarak davet
edilmelidir** (Slack'in güvenlik modeli). Davet etmezsen
`step1 reddedildi: not_in_channel` hatasını alırsın.

Slack desktop UI'da hedef kanala git ve mesaj kutusuna yaz:

```
/invite @mersel-dss-notify
```

(Bot ismini App Manifest'te yazdığın `bot_user.display_name` değeri
olarak yazıyorsun — manifest yöntemiyle yukarıda `mersel-dss-notify`
demiştik.)

Slack onaylar; bot artık kanalda. Test için kanal mesaj kutusuna
`@mersel-dss-notify` yazıp Tab'a basabilirsin — autocomplete
gösterirse bot kanaldadır.

---

#### Kurulumu doğrula (smoke test)

Bot token + kanal ID'sini set ettiğin yerden manuel olarak Slack
API'sını çağırıp test edebilirsin:

```bash
# Sadece auth çalışıyor mu test et (hiçbir kanala yazmaz):
curl -X POST https://slack.com/api/auth.test \
  -H "Authorization: Bearer xoxb-..." \
  -H "Content-Type: application/json; charset=utf-8"

# Beklenen yanıt: {"ok":true,"url":"...","team":"...","user":"mersel-dss-notify",...}

# files:write scope çalışıyor mu test et:
curl -X POST 'https://slack.com/api/files.getUploadURLExternal' \
  -H "Authorization: Bearer xoxb-..." \
  --data-urlencode "filename=test.txt" \
  --data-urlencode "length=4"

# Beklenen yanıt: {"ok":true,"upload_url":"...","file_id":"..."}
# Eğer "missing_scope" donerse YÖNTEM A/B adım 4'e geri don.
```

Smoke test geçtiyse env'leri set et ve Mersel DSS Verify API'yi
restart et:

```bash
export INVALID_SIGNATURE_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T0/B0/XXX
export INVALID_SIGNATURE_SLACK_BOT_TOKEN=xoxb-...
export INVALID_SIGNATURE_SLACK_CHANNEL=C0123ABCD45
```

İlk INVALID imza doğrulamasında Slack kanalında **kırmızı bantlı
alarm mesajı + indirilebilir dosya** görmelisin.

---

#### Bot kuramıyorum / IT politikası izin vermiyor — alternatifler

Eğer workspace admin'i "Apps must be approved" politikası uyguluyor
ve onay gecikecekse:

| Senaryo | Çözüm |
|---|---|
| Admin "Apps must be approved" → app pending | Admin'e bu HOW_TO_USE'un manifest YAML'ını gönder, onay 5 dakika alır. App private + read-only (`files:write`), risk düşük |
| Workspace policy hiçbir bot'a izin vermiyor | Section 7 — **Slack-only inline base64** kullan. Dosyaların ≤28KB'sa direkt mesajda görünür, bot/scope yok |
| Workspace policy katı + dosyalar 250KB+ | Generic webhook + kendi sisteminize base64 receiver. Bu Slack'in dışı — eğer Slack zorunluysa IT'ye manifest sunulup approve ettirilmesi gerek |

### Boyut sınırı

Dosya `INVALID_SIGNATURE_NOTIFICATION_MAX_CONTENT_SIZE_BYTES` (default
10MB) üstündeyse Slack upload **atlanır** (`info` log'u düşer).
Webhook payload'ı yine gönderilir (metadata + omitted reason ile).
Slack'in kendi sert dosya limiti ise **1GB** — pratikte hiç vurmazsın.

---

## 9. Gizlilik & güvenlik

| Risk | Önlem |
|---|---|
| Mali Mühür PDF içinde VKN / TCKN | `INCLUDE_CONTENT=false` → sadece metadata gider |
| Receiver dışındaki birinin alert URL'i keşfetmesi | `WEBHOOK_SECRET` set et — HMAC olmadan istek reddedilir |
| Receiver eski bildirimi replay etmesi | Timestamp 5 dakika penceresi + `Webhook-Id` ile DB tarafında dedupe |
| Slack bot token leak | Sadece `files:write` scope ver, başka scope verme |
| Bilingual chat'te taşma | Default 5 hata + 5 imza Slack mesajına taşınır, kalanı webhook payload'ına |

---

## 10. Operasyonel davranış

- **Async + best-effort** — `notifyIfInvalid()` çağrısı doğrulama
  thread'ini bloklamaz; OkHttp `enqueue()` ile arka plana atılır.
- **Bildirim hatası verifier'ı bozmaz** — receiver 500 dönse, URL
  ölü olsa, token yanlış olsa: hep WARN log'u + akış devam.
- **Gerçek sıfır overhead** — `enabled=false` VEYA hiçbir destination
  env var'ı set edilmemişse `@PostConstruct` **OkHttpClient bile
  yaratmaz** (dispatcher thread pool + connection pool yok). Yalnız
  bean'in iki primitive field'ı yaşar (~birkaç byte). Bu sayede
  notification feature kapalıyken servisin steady-state heap kullanımı
  bu modüldan etkilenmez.
- **Verifier integration coverage** — Hem advanced hem de lite
  verifier (`AdvancedSignatureVerificationService` ve
  `SignatureVerificationService`) INVALID sonuçlarda bildirim
  tetikler. Yeni endpoint eklenirken hangi verifier kullanıldığını
  düşünmek zorunda değilsiniz.
- **Retry yok** — webhook receiver'ı kendi tarafında idempotent
  almalı. Daha agresif SLA için outbox pattern + retry queue'yu
  receiver tarafında kurmalısınız.

---

## 11. Sorun giderme

| Belirti | Olası neden |
|---|---|
| `webhook POST non-2xx: 401` | Secret eşleşmiyor — receiver tarafında secret değiştir |
| `step1 reddedildi: invalid_auth` | Token yanlış kopyalanmış — `xoxb-...` ile başlamalı, `xapp-` veya `xoxe-` değil. **OAuth & Permissions** → **Bot User OAuth Token** alanını tekrar kopyala |
| `step1 reddedildi: token_revoked` | App kaldırılmış veya admin tarafından devre dışı bırakılmış — Slack admin'i ile konuş, yeniden install et |
| `step1 reddedildi: not_in_channel` | Bot kanala davet edilmemiş. Kanalda `/invite @mersel-dss-notify` yaz |
| `step1 reddedildi: missing_scope` | Bot user OAuth scopes'a `files:write` ekleyin → workspace'e **yeniden** install edin (scope ekleyince re-install zorunlu) |
| `step1 reddedildi: channel_not_found` | `SLACK_CHANNEL` yanlış format — kanal **adı** değil **ID** (`C` ile başlayan ~10 char). Kanal başlığına tıkla → en altta görünür |
| `step1 reddedildi: ratelimited` | Slack API'sini hızlı çağırıyorsun (Tier 4 = 100+/dk). Verifier rate'i normalde altında; gerçekten 100+ INVALID/dakika düşüyorsa altyapı sorunu vardır |
| Slack mesajı geliyor ama dosya gelmiyor | `SLACK_CHANNEL` ID değil, ad set edilmiş — `C…` formatına çevirin |
| Slack'te tüm mesajlar nötr renkte | Eski versiyondasınız; v0.4.0+'a güncelleyin (attachment color eklendi) |
| Slack mesajında "boyut limit aşıyor" notice'i ama dosya gelmedi | `INVALID_SIGNATURE_SLACK_INLINE_BASE64_MAX_BYTES` çok küçük — dosya boyutuna göre artırın (Slack mesaj toplam 40KB limitini aşmayın → binary ≤28KB önerilir) veya bot upload'a geçin |
| Inline base64 enable ama mesajda code block görünmüyor | `INVALID_SIGNATURE_SLACK_INLINE_BASE64_ENABLED=true` mu? `enabled=false`'da hiç eklenmez |
| Decode edilen dosya bozuk | Multi-chunk durumda tüm code block'ları sıralı concat ettiğinizden emin olun (Slack mesaj sırası = chunk sırası); arada whitespace olmasın |

---

## 12. Pazardaki yerleşik çözümlerle karşılaştırma

Pazardaki bulut tabanlı muhasebe/e-Belge oyuncuları INVALID bir Mali
Mühür anomalisini fark ettiğinde bilgiyi genellikle (a) UI bildirimi
veya (b) günlük cron raporlarıyla mükellefe iletir; mükellef genelde
ertesi iş gününde fark eder. Mersel DSS Verifier ise:

- Doğrulama anında olay-tabanlı bildirim → ortalama tespit süresi
  saatlerden **saniyelere** iner.
- HMAC + delivery-id ile **bildirimden idempotency'e kadar** denetim
  ekibinin VUK Madde 227'ye uygun kanıt zinciri kurabileceği bir
  audit topology sunar.
- Slack kırmızı bant + indirilebilir dosya kombosu, muhasebe ekibinin
  RDP'siz / VPN'siz işle aksiyon almasını mümkün kılar — yerleşik
  çözümlerde her durumda web paneline login zorunluluğu vardır.
