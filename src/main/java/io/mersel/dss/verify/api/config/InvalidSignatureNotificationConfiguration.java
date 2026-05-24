package io.mersel.dss.verify.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * INVALID imza tespit edildiğinde tetiklenecek webhook/Slack bildirimleri
 * için konfigürasyon.
 *
 * <p><b>Aktivasyon kuralı</b>: Feature default <i>açık</i>tır
 * ({@link #enabled} = {@code true}). Ancak bildirim sadece en az bir URL
 * (generic webhook veya Slack) {@code @Value}'ya non-blank şekilde
 * geçtiğinde gerçekten ateşlenir. Yani <strong>tek başına env değişkenini
 * set etmek aktivasyon için yeterlidir</strong> — explicit master switch
 * gerekmez. Operatör URL'yi set bırakıp geçici olarak susturmak isterse
 * {@code INVALID_SIGNATURE_NOTIFICATION_ENABLED=false} kullanabilir.</p>
 *
 * <p><b>Generic webhook ile Slack farkı</b>:</p>
 * <ul>
 *   <li><b>Generic webhook</b> — operatörün kendi sistemi (alert manager,
 *       ticket sistemi, audit log toplayıcı). JSON body içine
 *       {@link io.mersel.dss.verify.api.services.notification.InvalidSignatureWebhookPayload}
 *       basılır; doğrulanan içerik base64 ile <em>opsiyonel</em> olarak
 *       eklenir ({@link #includeContent} + {@link #maxContentSizeBytes}).</li>
 *   <li><b>Slack incoming webhook</b> — chat kanalı. Default'ta yalnız
 *       özet metadata (dosya adı, hatalar, imza tipi) Slack Block Kit
 *       formatında basılır; base64 içerik gönderilmez. Operatör
 *       <em>tek URL'lik dağıtım modu</em> isterse
 *       {@link #slackInlineBase64Enabled} flag'iyle base64 içeriği
 *       Slack mesajının içine triple-backtick code block olarak da
 *       gömdürebilir (boyut sınırı {@link #slackInlineBase64MaxBytes};
 *       chunk'lanarak Block Kit 3000-char/section limitine uydurulur).</li>
 *   <li><b>Slack bot file upload</b> — alarm mesajına ek olarak
 *       dosyayı indirilebilir Slack file objesi olarak yükler (3-adımlı
 *       yeni API). Bot token + scope yönetimi gerektirir; chat'i temiz
 *       tutar. Inline base64 yolundan tamamen bağımsız — istenirse
 *       ikisi aynı anda da kullanılabilir.</li>
 * </ul>
 *
 * <p><b>İletişim modeli</b>: Her iki kanal da <em>best-effort + async</em>.
 * Bildirim hataları doğrulama akışını ASLA bozmaz — yalnızca WARN
 * loglanır. Bu sayede operatörün Slack URL'i yanlış olsa bile
 * imza doğrulama API'si HTTP 500 dönmez.</p>
 *
 * <p><b>Gizlilik</b>: Base64 içerik default açık. Doğrulanan doküman
 * PII / mali gizlilik taşıyorsa
 * {@code INVALID_SIGNATURE_NOTIFICATION_INCLUDE_CONTENT=false} ile
 * kapatılabilir; yalnız metadata gider. Slack kanalında zaten içerik
 * gitmez.</p>
 */
@Configuration
public class InvalidSignatureNotificationConfiguration {

    /**
     * Master switch. Operatör URL'leri set bıraktığı halde geçici olarak
     * bildirimleri susturmak istediğinde {@code false} yapılır.
     */
    @Value("${notification.invalid-signature.enabled:${INVALID_SIGNATURE_NOTIFICATION_ENABLED:true}}")
    private boolean enabled;

    /**
     * Generic webhook URL — operatörün kendi alert/ticket/audit sistemi.
     * Boş ise generic webhook tetiklenmez (Slack hâlâ tetiklenebilir).
     */
    @Value("${notification.invalid-signature.webhook.url:${INVALID_SIGNATURE_WEBHOOK_URL:}}")
    private String webhookUrl;

    /**
     * Slack incoming webhook URL'i (tipik:
     * {@code https://hooks.slack.com/services/T.../B.../...}).
     * Boş ise Slack mesaj kanalı tetiklenmez. Generic webhook ve Slack
     * bot file upload bağımsız olarak çalışmaya devam edebilir.
     */
    @Value("${notification.invalid-signature.slack.webhook.url:${INVALID_SIGNATURE_SLACK_WEBHOOK_URL:}}")
    private String slackWebhookUrl;

    /**
     * Slack <em>Bot User OAuth Token</em> ({@code xoxb-…}). Set edildiğinde
     * doğrulanan dosya, INVALID alarm mesajına ek olarak Slack kanalına
     * <strong>indirilebilir bir dosya</strong> olarak yüklenir
     * ({@code files.getUploadURLExternal} → binary POST →
     * {@code files.completeUploadExternal}).
     *
     * <p><b>Not</b>: {@code files.upload} (eski legacy yöntemi) Kasım 2025'te
     * Slack tarafından sunset edildi; bu modül yeni 3-adımlı flow'u
     * kullanır. Bot'a {@code files:write} scope'u verilmeli.</p>
     *
     * <p>Boş veya {@link #slackBotChannel} boşsa dosya upload yapılmaz —
     * yalnız incoming webhook mesajı gider.</p>
     */
    @Value("${notification.invalid-signature.slack.bot.token:${INVALID_SIGNATURE_SLACK_BOT_TOKEN:}}")
    private String slackBotToken;

    /**
     * Dosyanın yükleneceği Slack kanal ID'si (genelde {@code C…} formatında).
     * Kanal ADI değil ID gereklidir — Slack
     * {@code files.completeUploadExternal} channel-name kabul etmez. Boş
     * ise dosya upload tamamen devre dışıdır.
     */
    @Value("${notification.invalid-signature.slack.bot.channel:${INVALID_SIGNATURE_SLACK_CHANNEL:}}")
    private String slackBotChannel;

    /**
     * <strong>Slack-only / tek-URL dağıtım modu için inline base64 master
     * switch'i.</strong>
     *
     * <p>Operatörün Slack uygulaması + bot token + {@code files:write}
     * scope ayarlamak istemediği veya kuramayacağı senaryolarda
     * (kurumsal IT politikası, hızlı POC, küçük ekip) bot upload yolu yerine
     * doğrulanan dosyayı Slack chat mesajının <em>içine</em> base64 kodlu
     * triple-backtick code block olarak gömmek için. Default
     * {@code false} — operatör bilinçli olarak {@code true} yapmadığı
     * sürece Slack mesajı sade kalır (chat'i base64 ile kirletmiyoruz —
     * raw base64 bir kanalın okunabilirliğini bozar).</p>
     *
     * <p><b>Bot upload ile ilişki</b>: Bu kanal bot upload yolundan
     * <em>tamamen bağımsız</em>dır. Operatör genelde ya birini seçer ya
     * diğerini; ikisi de set edilirse <em>ikisi de</em> tetiklenir
     * (kanallar birbirini bastırmaz). Bot upload daha kaliteli sonuç verir
     * (gerçek download'lanabilir dosya, chat'te temiz görünüm), inline
     * base64 ise <em>tek URL</em> ile ayakta kalır — operatörün trade-off'u.</p>
     *
     * <p><b>Alıcı tarafında decode</b>: Mesajdaki base64 chunk'ları
     * (gerekirse birden fazla section block'tan) birleştirip:
     * <pre>
     * # macOS:
     * pbpaste | base64 -d &gt; signed.bin
     * # Linux:
     * xclip -o | base64 -d &gt; signed.bin
     * </pre>
     * komutuyla orijinal dosyaya geri dönülür.</p>
     */
    @Value("${notification.invalid-signature.slack.inline-base64-enabled:${INVALID_SIGNATURE_SLACK_INLINE_BASE64_ENABLED:false}}")
    private boolean slackInlineBase64Enabled;

    /**
     * <strong>Slack inline base64 üst boyut sınırı (byte).</strong>
     *
     * <p>{@link #slackInlineBase64Enabled} {@code true} iken yalnızca bu
     * eşiği aşmayan dosyalar Slack mesajına inline gömülür. Default
     * {@code 8192} (8KB) — Slack'in payload sınırlarıyla rahatça yaşamak
     * için seçildi:</p>
     * <ul>
     *   <li><b>Base64 expansion</b>: 4/3× → 8KB binary ≈ 10.9KB base64
     *       string.</li>
     *   <li><b>Slack mesaj toplam sınırı</b> ≈ 40KB (soft-reject) — 10.9KB
     *       base64 + Block Kit overhead'iyle rahatça altında kalır.</li>
     *   <li><b>Block Kit per-section text limiti</b> 3000 char/blok (TIGHTER
     *       constraint). Notifier base64 string'i otomatik olarak ~2700
     *       char'lık parçalara böler ve birden fazla section block'ta
     *       basar (Block Kit mesaj başına 50 blok izin verir, 8KB → ~5
     *       blok; sınırın çok altında).</li>
     * </ul>
     *
     * <p><b>Dosya boyutu &gt; bu eşik</b> ise inline base64 atlanır; mesaj
     * yine gider ama dosya yerine "boyut limit aşıldı" açıklama satırı
     * gömülür. Bu durumda gerçek dosya için ya generic webhook payload'ına
     * ({@code file.base64Content}) ya da bot upload kanalına başvurun —
     * her ikisi bağımsız çalışıyor olabilir.</p>
     *
     * <p>Operatör daha büyük dosyaları inline göndermek isterse bu sınırı
     * artırabilir, fakat <em>Slack mesaj toplam 40KB sınırı</em>
     * unutulmamalı (binary &lt;= 28KB önerilir).</p>
     */
    @Value("${notification.invalid-signature.slack.inline-base64-max-bytes:${INVALID_SIGNATURE_SLACK_INLINE_BASE64_MAX_BYTES:8192}}")
    private long slackInlineBase64MaxBytes;

    /**
     * <strong>Generic webhook HMAC paylaşılan secret'i.</strong> Set edilirse
     * her POST'a aşağıdaki güvenlik header'ları eklenir:
     * <ul>
     *   <li>{@code X-Mersel-Webhook-Id} — UUID, her bildirim için eşsiz
     *       (receiver idempotency için).</li>
     *   <li>{@code X-Mersel-Webhook-Timestamp} — Unix epoch saniye, replay
     *       saldırılarına karşı.</li>
     *   <li>{@code X-Mersel-Signature: sha256=<hex>} —
     *       HMAC-SHA256({@code timestamp + "." + rawBody}, secret) lowercase hex.
     *       Receiver bu header'ı kendi tarafındaki secret ile yeniden hesaplayıp
     *       eşitse Mersel'den geldiğine güvenir.</li>
     * </ul>
     *
     * <p>Secret boş ise header'lar yine eklenir ama {@code X-Mersel-Signature}
     * gönderilmez — receiver bu durumda yalnız URL gizliliğine güvenir
     * (Slack incoming webhook modelinin paralelidir).</p>
     *
     * <p>Slack için ayrı bir secret YOK: incoming webhook URL'inin kendisi
     * Slack'in resmi secret modelidir; HMAC eklemek Slack tarafında parse
     * edilemez. Bot token'la upload yapılırken bot token zaten secret
     * görevini görür.</p>
     */
    @Value("${notification.invalid-signature.webhook.secret:${INVALID_SIGNATURE_WEBHOOK_SECRET:}}")
    private String webhookSecret;

    /**
     * Doğrulanan dokümanın base64 içeriği generic webhook payload'una
     * dahil edilsin mi? Default açık — operatör forensik için içeriği
     * görmek ister. Gizlilik baskınsa kapatılır. Slack için ALAKASIZ
     * (Slack'e zaten gitmiyor).
     */
    @Value("${notification.invalid-signature.include-content:${INVALID_SIGNATURE_NOTIFICATION_INCLUDE_CONTENT:true}}")
    private boolean includeContent;

    /**
     * Bayt cinsinden üst sınır. Bu eşikten büyük dokümanlar için
     * {@code base64Content} hiç eklenmez — yalnız hash + metadata gider.
     * Default 10MB; webhook receiver'ları büyük payload kabul etmiyor
     * olabilir veya operatör trafiği sınırlamak isteyebilir.
     */
    @Value("${notification.invalid-signature.max-content-size-bytes:${INVALID_SIGNATURE_NOTIFICATION_MAX_CONTENT_SIZE_BYTES:10485760}}")
    private long maxContentSizeBytes;

    /**
     * HTTP connect timeout (ms) — webhook receiver TCP handshake aşaması
     * için. Default 5s; bildirim asla doğrulama latency'sini yutmamalı.
     */
    @Value("${notification.invalid-signature.connect-timeout-ms:${INVALID_SIGNATURE_NOTIFICATION_CONNECT_TIMEOUT_MS:5000}}")
    private int connectTimeoutMs;

    /**
     * HTTP read timeout (ms) — receiver ilk byte'ı yolladıktan sonra
     * iki paket arasında beklenecek azami süre.
     */
    @Value("${notification.invalid-signature.read-timeout-ms:${INVALID_SIGNATURE_NOTIFICATION_READ_TIMEOUT_MS:10000}}")
    private int readTimeoutMs;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getWebhookUrl() {
        return webhookUrl;
    }

    public void setWebhookUrl(String webhookUrl) {
        this.webhookUrl = webhookUrl;
    }

    public String getSlackWebhookUrl() {
        return slackWebhookUrl;
    }

    public void setSlackWebhookUrl(String slackWebhookUrl) {
        this.slackWebhookUrl = slackWebhookUrl;
    }

    public String getSlackBotToken() {
        return slackBotToken;
    }

    public void setSlackBotToken(String slackBotToken) {
        this.slackBotToken = slackBotToken;
    }

    public String getSlackBotChannel() {
        return slackBotChannel;
    }

    public void setSlackBotChannel(String slackBotChannel) {
        this.slackBotChannel = slackBotChannel;
    }

    public boolean isSlackInlineBase64Enabled() {
        return slackInlineBase64Enabled;
    }

    public void setSlackInlineBase64Enabled(boolean slackInlineBase64Enabled) {
        this.slackInlineBase64Enabled = slackInlineBase64Enabled;
    }

    public long getSlackInlineBase64MaxBytes() {
        return slackInlineBase64MaxBytes;
    }

    public void setSlackInlineBase64MaxBytes(long slackInlineBase64MaxBytes) {
        this.slackInlineBase64MaxBytes = slackInlineBase64MaxBytes;
    }

    public String getWebhookSecret() {
        return webhookSecret;
    }

    public void setWebhookSecret(String webhookSecret) {
        this.webhookSecret = webhookSecret;
    }

    public boolean isIncludeContent() {
        return includeContent;
    }

    public void setIncludeContent(boolean includeContent) {
        this.includeContent = includeContent;
    }

    public long getMaxContentSizeBytes() {
        return maxContentSizeBytes;
    }

    public void setMaxContentSizeBytes(long maxContentSizeBytes) {
        this.maxContentSizeBytes = maxContentSizeBytes;
    }

    public int getConnectTimeoutMs() {
        return connectTimeoutMs;
    }

    public void setConnectTimeoutMs(int connectTimeoutMs) {
        this.connectTimeoutMs = connectTimeoutMs;
    }

    public int getReadTimeoutMs() {
        return readTimeoutMs;
    }

    public void setReadTimeoutMs(int readTimeoutMs) {
        this.readTimeoutMs = readTimeoutMs;
    }

    /**
     * En az bir hedef (generic webhook / Slack incoming webhook / Slack bot
     * file upload) set edilmiş mi? Hızlı runtime check — notifier her
     * doğrulamada bu metoda bakarak gereksiz iş yapmamayı seçer.
     */
    public boolean hasAnyDestination() {
        return hasWebhookDestination() || hasSlackDestination() || hasSlackBotUploadDestination();
    }

    public boolean hasWebhookDestination() {
        return isNonBlank(webhookUrl);
    }

    public boolean hasSlackDestination() {
        return isNonBlank(slackWebhookUrl);
    }

    /**
     * Slack bot ile dosya upload aktif mi? Hem token hem kanal ID set
     * edilmedikçe upload yapmıyoruz — yalnız token ile destination yok
     * sayılır (Slack {@code completeUploadExternal} çağrısı channel
     * gerektirir).
     */
    public boolean hasSlackBotUploadDestination() {
        return isNonBlank(slackBotToken) && isNonBlank(slackBotChannel);
    }

    public boolean hasWebhookSecret() {
        return isNonBlank(webhookSecret);
    }

    private static boolean isNonBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }
}
