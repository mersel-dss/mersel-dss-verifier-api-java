package io.mersel.dss.verify.api.services.notification;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.mersel.dss.verify.api.config.InvalidSignatureNotificationConfiguration;
import io.mersel.dss.verify.api.config.LogHeadersFilter;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.VerificationResult;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * INVALID imza tespit edildiğinde konfigüre edilmiş generic webhook
 * ve/veya Slack incoming webhook'una <em>best-effort, fire-and-forget</em>
 * bildirim gönderir.
 *
 * <h3>Davranış</h3>
 * <ul>
 *   <li><b>Aktivasyon</b> — Notifier {@code enabled} ve en az bir URL set
 *       edilmediği sürece hiçbir şey yapmaz; ekstra heap/IO maliyeti
 *       sıfırdır.</li>
 *   <li><b>Sadece INVALID için tetiklenir</b> — VALID imzalarda no-op.
 *       Operatör "her doğrulamayı arşivle" tarzı bir akış için ayrı bir
 *       audit logger kurmalıdır; bu notifier alert kanalıdır.</li>
 *   <li><b>Async</b> — OkHttp {@code enqueue()} kullanılır; verifier
 *       thread'i HTTP'yi beklemez. Bildirim hataları doğrulama akışını
 *       ASLA bozmaz, yalnızca WARN/ERROR loglanır.</li>
 *   <li><b>İçerik</b> — Generic webhook'a doğrulanan dokümanın base64
 *       içeriği <em>opsiyonel</em> olarak eklenir. Slack mesajına
 *       default'ta içerik gitmez; ancak operatör <em>tek URL'lik
 *       dağıtım</em> isterse ({@code slackInlineBase64Enabled=true}) base64
 *       içerik chat mesajının kendisine triple-backtick code block olarak
 *       gömülür (boyut sınırına tabi, Block Kit 3000-char/section limiti
 *       için otomatik chunk'lanır).</li>
 * </ul>
 *
 * <h3>Slack payload</h3>
 * Slack <em>Block Kit</em> formatında zengin mesaj basılır:
 * <ol>
 *   <li>Header — "🚨 Mersel DSS Verify – INVALID Signature"</li>
 *   <li>Section (fields) — dosya, durum, imza tipi, imza sayısı</li>
 *   <li>Section — top-level hatalar (max 5 satır)</li>
 *   <li>Per signature section — indication / subIndication / signer DN /
 *       Mersel rejection kodları (varsa)</li>
 *   <li>(Opsiyonel) Inline base64 chunk'ları — yalnız
 *       {@code slackInlineBase64Enabled=true} ve dosya boyut sınırı
 *       altında ise. Chunk'lar arasında veri korunur (truncate edilmez).</li>
 * </ol>
 *
 * @see InvalidSignatureNotificationConfiguration
 * @see InvalidSignatureWebhookPayload
 */
@Service
public class InvalidSignatureNotifier {

    private static final Logger logger = LoggerFactory.getLogger(InvalidSignatureNotifier.class);

    static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    /** Webhook payload schema'sında sabit event tipi. */
    static final String EVENT_TYPE_INVALID_SIGNATURE = "invalid-signature";

    /** Operatöre rehberlik için contentOmittedReason kodları (kararlı API). */
    static final String OMITTED_BY_CONFIG = "EXCLUDED_BY_CONFIG";
    static final String OMITTED_EXCEEDED_MAX_SIZE = "EXCEEDED_MAX_SIZE";

    /** Slack mesajındaki hata listesinin üst sınırı — Block Kit 3000 char limiti için. */
    static final int SLACK_MAX_ERRORS_LISTED = 5;
    /** Slack mesajındaki per-signature blok sayısı üst sınırı — multi-imzalı XML için. */
    static final int SLACK_MAX_SIGNATURES_LISTED = 5;
    /**
     * Slack mesajında listelenecek korelasyon ({@code x-log-*}) header
     * sayısı üst sınırı. {@link LogHeadersFilter#MAX_HEADERS} request başına
     * 20 header kabul ediyor; mesajda hepsini göstermek Block Kit
     * 3000-char/section limitini zorlayabilir. Üstündeki header'lar
     * webhook payload'unun {@code logHeaders} alanından okunabilir.
     */
    static final int SLACK_MAX_LOG_HEADERS_LISTED = 10;

    /**
     * Slack inline base64 fallback: tek bir Block Kit {@code section} bloğunun
     * {@code mrkdwn} alanı için kullanabileceğimiz pratik karakter sayısı.
     *
     * <p>Slack'in resmi sert üst sınırı 3000 char/section; biz prefix
     * (<code>*İçerik (base64, N bytes):*</code>), code fence (<code>```</code>)
     * ve son blok'a ekli decode-hint satırı (<code>_Decode: ..._</code>) için
     * <strong>~200 char tampon</strong> bırakarak <strong>2700</strong>'de
     * tutuyoruz. Bu sayede {@link #slackSectionMarkdown}'ın
     * {@link #truncate(String, int)} (2900) eşiği ASLA tetiklenmez — base64
     * char'ı tek bir kayıp bile dosyayı bozar.</p>
     */
    static final int SLACK_INLINE_BASE64_CHUNK_CHARS = 2700;

    /**
     * Slack attachment color — danger/red yan şerit. Slack'in resmi "danger"
     * preset hex'i. Görsel sinyalleme: kanaldaki alarm mesajları INVALID
     * için her zaman kırmızı bantlı, tek bakışta ayırt edilir.
     */
    static final String SLACK_DANGER_COLOR = "#A30200";

    /** Generic webhook HMAC + replay-protection header isimleri (kararlı API). */
    static final String HEADER_WEBHOOK_ID = "X-Mersel-Webhook-Id";
    static final String HEADER_WEBHOOK_TIMESTAMP = "X-Mersel-Webhook-Timestamp";
    static final String HEADER_WEBHOOK_EVENT = "X-Mersel-Event";
    static final String HEADER_WEBHOOK_SIGNATURE = "X-Mersel-Signature";

    /** HMAC algoritması — sha256 endüstri standardı (Stripe/GitHub/Slack hepsi bunu kullanır). */
    static final String HMAC_ALGORITHM = "HmacSHA256";

    @Autowired
    private InvalidSignatureNotificationConfiguration config;

    /**
     * Spring Boot {@code spring-boot-maven-plugin:build-info} tarafından
     * üretilen META-INF/build-info.properties'tan gelir. <em>Test sırasında
     * yoksa</em> {@code null} olabilir — {@code source} alanını fallback
     * stringle dolduruyoruz.
     */
    @Autowired(required = false)
    private BuildProperties buildProperties;

    /**
     * JSON serileştirme için. Servis-scope tek instance; ObjectMapper
     * thread-safe.
     */
    private final ObjectMapper objectMapper;

    /**
     * OkHttp client — context yaşam döngüsü boyunca yeniden kullanılır.
     * {@code @PostConstruct}'ta config'e göre timeout'larıyla kurulur.
     */
    private OkHttpClient httpClient;

    /**
     * Slack'e indirilebilir dosya yükleme için 3-adımlı API sarmalı.
     * {@link #httpClient} ile aynı OkHttp instance'ını paylaşır
     * (timeout/connection pool tek noktada).
     */
    private SlackFileUploader slackFileUploader;

    /**
     * Test ve runtime gözlem için override edilebilir; default sistem
     * saatini döner. Tests {@link #setClock(java.util.function.Supplier)}
     * ile sabitleyebilir.
     */
    private java.util.function.Supplier<Date> clock = Date::new;

    /**
     * Unix epoch saniye saati — webhook timestamp header'ı için. Test
     * deterministik kılmak için ayrı bir hook.
     */
    private LongSupplier unixSecondsClock = () -> System.currentTimeMillis() / 1000L;

    /**
     * Webhook delivery-id üretici. Default UUID v4; testlerde sabit
     * ID basmak için override edilebilir.
     */
    private java.util.function.Supplier<String> idGenerator = () -> UUID.randomUUID().toString();

    public InvalidSignatureNotifier() {
        this.objectMapper = new ObjectMapper();
        // Pretty-print ON yapmıyoruz — webhook receiver'lar genelde tek satır
        // JSON ister, parsing maliyeti de düşer.
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    @PostConstruct
    void initialize() {
        // ====================================================================
        // LAZY HTTP CLIENT INIT — Heap maliyetini sıfırlama
        // ====================================================================
        // Önceki implementasyon: OkHttpClient @PostConstruct'ta KOŞULSUZ
        // oluşturulurdu — config'de URL set edilmemiş olsa bile bir
        // OkHttpClient + dispatcher thread pool + connection pool
        // yaşardı (~birkaç MB heap + 2-3 idle thread).
        //
        // Yeni davranış: Feature kapalıysa VEYA hiçbir destination
        // set edilmemişse OkHttpClient YARATILMAZ. {@link #httpClient}
        // null kalır; doNotifyIfInvalid()'ın üst gate'leri zaten bu
        // durumda dispatch yapmaz — null guard'lar her dispatch
        // metodunda da var (defense-in-depth, runtime config değişimine
        // karşı).
        //
        // Sonuç: Operatör hiç bildirim env'i set etmediyse heap maliyeti
        // GERÇEKTEN sıfır (sadece sınıf yüklemesi + iki primitive field).
        // ====================================================================
        if (!config.isEnabled()) {
            logger.info("InvalidSignatureNotifier: feature kapalı "
                    + "(notification.invalid-signature.enabled=false). "
                    + "INVALID imzalarda bildirim gönderilmeyecek. "
                    + "OkHttpClient kurulmadı (zero-overhead).");
            return;
        }
        if (!config.hasAnyDestination()) {
            logger.info("InvalidSignatureNotifier: hiçbir bildirim hedefi set edilmedi "
                    + "(INVALID_SIGNATURE_WEBHOOK_URL / INVALID_SIGNATURE_SLACK_WEBHOOK_URL / "
                    + "INVALID_SIGNATURE_SLACK_BOT_TOKEN+CHANNEL hepsi boş). "
                    + "Feature aktif ama bildirim hedefi yok — OkHttpClient kurulmadı (zero-overhead).");
            return;
        }

        // En az bir destination var; HTTP client'ı şimdi kuruyoruz.
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(config.getConnectTimeoutMs(), TimeUnit.MILLISECONDS)
                .readTimeout(config.getReadTimeoutMs(), TimeUnit.MILLISECONDS)
                .writeTimeout(config.getReadTimeoutMs(), TimeUnit.MILLISECONDS)
                // Webhook çoğu durumda 200/204 ile tek seferde döner. OkHttp
                // default'unda retry on connection failure açık; bu yeterli.
                // Daha agresif retry SLA'sı isteyen operatör kendi receiver'ı
                // üzerinden idempotency kontrolü yapmalı.
                .build();
        this.slackFileUploader = new SlackFileUploader(this.httpClient, this.objectMapper);

        logger.info("InvalidSignatureNotifier: aktif. webhook={}, webhookSecret={}, "
                        + "slackMessage={}, slackFileUpload={}, "
                        + "includeContent={}, maxContentSize={} bytes",
                config.hasWebhookDestination() ? "configured" : "<unset>",
                config.hasWebhookSecret() ? "configured" : "<unset>",
                config.hasSlackDestination() ? "configured" : "<unset>",
                config.hasSlackBotUploadDestination() ? "configured" : "<unset>",
                config.isIncludeContent(),
                config.getMaxContentSizeBytes());
    }

    @PreDestroy
    void shutdown() {
        if (httpClient == null) {
            return;
        }
        // OkHttp dispatcher executor'unu kapat — context shutdown'da
        // dangling thread bırakmayalım.
        try {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        } catch (Exception e) {
            logger.debug("InvalidSignatureNotifier shutdown sırasında küçük hata (yok sayıldı): {}",
                    e.getMessage());
        }
    }

    /**
     * Imza sonucu INVALID ise konfigüre edilmiş kanallara bildirim
     * gönderir. <strong>Best-effort</strong>: bildirim başarısız olsa
     * bile çağıran akış etkilenmez.
     *
     * @param result     DSS doğrulama sonucu. {@code null} veya VALID ise no-op.
     * @param signedBytes Doğrulanan dosyanın byte içeriği — base64 olarak
     *                   webhook payload'una dahil edilebilir. {@code null}
     *                   olabilir (notifier metadata-only payload üretir).
     * @param fileName   Multipart {@code originalFilename}. {@code null} olabilir.
     * @param contentType MIME tipi. {@code null} olabilir.
     * @param originalBytes Detached imzada orijinal doküman. Yoksa {@code null}.
     * @param originalFileName Orijinal dokümanın dosya adı. Yoksa {@code null}.
     */
    public void notifyIfInvalid(
            VerificationResult result,
            byte[] signedBytes,
            String fileName,
            String contentType,
            byte[] originalBytes,
            String originalFileName) {

        // ====================================================================
        // SÖZLEŞME: Bu metoddan HİÇBİR koşulda exception sızdırılmaz.
        // Verifier akışını bozma riskini sıfıra indirmek için tüm gövde
        // outer try/catch içine sarılmıştır; içerideki her dispatch
        // (webhook / Slack mesaj / Slack file upload) ayrıca KENDİ
        // try/catch'iyle izole edilir — birinin patlaması diğerinin
        // gönderimini engellemez. Async kısım zaten OkHttp dispatcher
        // thread'inde çalıştığı için verifier thread'i HTTP'yi beklemez.
        // ====================================================================
        try {
            doNotifyIfInvalid(result, signedBytes, fileName, contentType,
                    originalBytes, originalFileName);
        } catch (Throwable t) {
            // Throwable yakalıyoruz: NoClassDefFoundError, OOM sırasında
            // bile verifier akışını koruyalım. Throwable'ı yutmak kural
            // dışıdır ama burada ana akış doğrulama; bildirim ikinci
            // sınıf bir audit kanalı. WARN yetiyor — Sentry/Prometheus
            // bu logu zaten kendi tarafında alarm üretir.
            logger.warn("InvalidSignatureNotifier: beklenmedik hata, bildirim atlandı "
                    + "(verifier akışı etkilenmedi): {}", t.toString());
        }
    }

    /**
     * Asıl bildirim mantığı. {@link #notifyIfInvalid} bunu outer try/catch
     * içinde çağırır.
     */
    private void doNotifyIfInvalid(
            VerificationResult result,
            byte[] signedBytes,
            String fileName,
            String contentType,
            byte[] originalBytes,
            String originalFileName) {

        // Sıkı gate'ler — feature kapalı veya hedef yoksa hiç iş yapma.
        if (result == null) {
            return;
        }
        if (result.isValid()) {
            return;
        }
        if (!config.isEnabled() || !config.hasAnyDestination()) {
            return;
        }

        // x-log-* korelasyon header'larını request thread'inden YAKALA.
        // MDC thread-local'dir; OkHttp dispatcher thread'ine geçtikten
        // sonra erişim KAYBOLUR. Async dispatch öncesi sync olarak
        // snapshot alıp tüm dispatch kanallarına immutable bir kopyasını
        // taşıyoruz — verifier istek thread'inde dururken (LogHeadersFilter
        // tarafından doldurulmuş) MDC'yi okumak güvenli.
        Map<String, String> logHeaders = collectXlogHeadersFromMdc();

        // Payload + Slack body'yi tek seferde hazırla; iki kanal da aynı
        // doğrulama sonucundan üretildiği için işi tekrar etmiyoruz.
        InvalidSignatureWebhookPayload payload;
        String slackBody;
        try {
            payload = buildWebhookPayload(
                    result, signedBytes, fileName, contentType,
                    originalBytes, originalFileName, logHeaders);
            slackBody = buildSlackBody(result, fileName, signedBytes, logHeaders);
        } catch (Exception buildEx) {
            // Payload üretimi exception atarsa bildirim gönderemeyiz;
            // doğrulama akışını etkilemeden devam et.
            logger.warn("Invalid signature notification payload build failed; bildirim atlanıyor: {}",
                    buildEx.getMessage());
            return;
        }

        // ÖNEMLİ: Her dispatch kanalı KENDİ try/catch'inde izole. Bu
        // sayede webhook URL'i geçersiz olsa bile Slack mesajı yine
        // gider; Slack mesajı patlasa bile bot file upload yine
        // denenebilir. Kanallar birbirini SUSTURMAZ.
        if (config.hasWebhookDestination()) {
            try {
                fireWebhookPost(config.getWebhookUrl(), serializeOrEmpty(payload), logHeaders);
            } catch (Exception e) {
                logger.warn("InvalidSignatureNotifier webhook dispatch failed: {}", e.getMessage());
            }
        }
        if (config.hasSlackDestination()) {
            try {
                fireSimplePost(config.getSlackWebhookUrl(), slackBody, "slack");
            } catch (Exception e) {
                logger.warn("InvalidSignatureNotifier slack message dispatch failed: {}",
                        e.getMessage());
            }
        }
        if (config.hasSlackBotUploadDestination()
                && signedBytes != null
                && signedBytes.length > 0
                && (long) signedBytes.length <= config.getMaxContentSizeBytes()
                && slackFileUploader != null) {
            // Yalnız boyut sınırı içinde kalan dosyaları Slack'e yüklüyoruz —
            // max-content-size hem webhook hem Slack tarafında aynı gate.
            // Çok büyük dosyaları async upload trafiğine sokmak Slack
            // bot rate-limit'lerini de gereksiz tüketir.
            try {
                slackFileUploader.uploadAsync(
                        config.getSlackBotToken(),
                        config.getSlackBotChannel(),
                        signedBytes,
                        safeFileName(fileName),
                        buildSlackFileTitle(result, fileName),
                        buildSlackFileInitialComment(result, fileName, logHeaders));
            } catch (Exception e) {
                logger.warn("InvalidSignatureNotifier slack file upload dispatch failed: {}",
                        e.getMessage());
            }
        } else if (config.hasSlackBotUploadDestination()
                && signedBytes != null
                && (long) signedBytes.length > config.getMaxContentSizeBytes()) {
            logger.info("Slack bot file upload skipped: dosya boyutu {} bytes > "
                            + "max-content-size {} bytes. Webhook payload zaten "
                            + "metadata + omittedReason taşıyor.",
                    signedBytes.length, config.getMaxContentSizeBytes());
        }
    }

    /**
     * Request thread'inin MDC'sinden {@link LogHeadersFilter} tarafından
     * konulmuş {@code xlog.*} entry'lerini toplar ve orijinal {@code x-log-*}
     * header adına geri haritalar.
     *
     * <p>Sıralama deterministik olsun (snapshot eşitliği, test stabilite,
     * Slack mesaj okunabilirlik) diye {@link TreeMap} kullanılır —
     * sözlük sıralı çıktı operatörün gözden geçirmesini kolaylaştırır.
     * Hiç header yoksa {@link Collections#emptyMap()} döner; tüm dispatch
     * yolu bu boş haritayı sessizce geçer (JSON {@code logHeaders} alanı
     * {@code null} kalır, Slack block'u eklenmez).</p>
     *
     * <p><b>Async bağlam not</b>: Bu metod yalnız notifier'ın SYNC kısmında
     * (verifier request thread'i üzerinde) çağrılır. Filter tarafından
     * konulmuş MDC entry'leri OkHttp dispatcher thread'inde görünmez;
     * snapshot mantığı doğru async-safe değer aktarımı sağlar.</p>
     */
    Map<String, String> collectXlogHeadersFromMdc() {
        Map<String, String> mdc;
        try {
            mdc = MDC.getCopyOfContextMap();
        } catch (Exception e) {
            // SLF4J implementasyonu yoksa veya adapter NPE atarsa
            // (test ortamı dışı pratikte imkânsız) sessiz boş dön.
            return Collections.emptyMap();
        }
        if (mdc == null || mdc.isEmpty()) {
            return Collections.emptyMap();
        }
        TreeMap<String, String> out = new TreeMap<>();
        String prefix = LogHeadersFilter.MDC_KEY_PREFIX;
        for (Map.Entry<String, String> e : mdc.entrySet()) {
            String key = e.getKey();
            String value = e.getValue();
            if (key == null || value == null || value.isEmpty()) {
                continue;
            }
            if (!key.startsWith(prefix)) {
                continue;
            }
            // MDC anahtarı "xlog.x-log-id" → "x-log-id" header adına geri dön.
            String headerName = key.substring(prefix.length());
            if (headerName.isEmpty()) {
                continue;
            }
            out.put(headerName, value);
        }
        return out.isEmpty() ? Collections.emptyMap() : Collections.unmodifiableMap(out);
    }

    /**
     * Tam payload object'i oluşturur. <strong>Package-private</strong> —
     * birim testleri bu metodu doğrudan çağırarak serializasyon-öncesi
     * yapıyı doğrular (HTTP firing'i mock'lamaya gerek yok).
     */
    InvalidSignatureWebhookPayload buildWebhookPayload(
            VerificationResult result,
            byte[] signedBytes,
            String fileName,
            String contentType,
            byte[] originalBytes,
            String originalFileName,
            Map<String, String> logHeaders) {

        InvalidSignatureWebhookPayload payload = new InvalidSignatureWebhookPayload();
        payload.setEvent(EVENT_TYPE_INVALID_SIGNATURE);
        payload.setSource(resolveSource());
        payload.setNotificationTime(clock.get());
        payload.setResult(result);

        payload.setFile(buildFileEnvelope(signedBytes, fileName, contentType));

        if (originalBytes != null && originalBytes.length > 0) {
            // Detached imzanın orijinal dokümanı için MIME bilinmiyor;
            // controller multipart contentType'ı pass etmiyor. Receiver
            // file.contentType'tan ana dosyayı zaten bilir.
            payload.setOriginalDocument(buildFileEnvelope(originalBytes, originalFileName, null));
        }

        if (logHeaders != null && !logHeaders.isEmpty()) {
            // Map'i defensive olarak kopyalıyoruz — caller'ın referansı
            // sonradan mutate olursa serialization sırasında race olmasın.
            // TreeMap deterministik sıralama (Slack mesajı + JSON kararlı
            // çıktısı için aynı snapshot kullanılır).
            payload.setLogHeaders(new TreeMap<>(logHeaders));
        }

        return payload;
    }

    /**
     * Test/back-compat overload — explicit {@code logHeaders} verilmediği
     * durumda {@code null} olarak ilerler. Yeni kodlar tercihen üst
     * overload'ı (logHeaders'lı) çağırmalı.
     */
    InvalidSignatureWebhookPayload buildWebhookPayload(
            VerificationResult result,
            byte[] signedBytes,
            String fileName,
            String contentType,
            byte[] originalBytes,
            String originalFileName) {
        return buildWebhookPayload(result, signedBytes, fileName, contentType,
                originalBytes, originalFileName, null);
    }

    /**
     * Slack <em>Block Kit</em> JSON body'sini oluşturur. Doğrulanan
     * içerik base64 olarak burada ASLA görünmez — Slack chat kanalı için
     * yalnızca özet metadata + hatalar.
     *
     * <p><b>Görsel sinyalleme</b>: Block Kit kendi başına renk attribute'u
     * desteklemediği için Slack'in {@code attachments} legacy field'ını
     * sarmalayıcı olarak kullanıyoruz — {@code color: "#A30200"} mesajın
     * solunda <strong>kırmızı dikey şerit</strong> oluşturur. Bu hala
     * Slack tarafından desteklenen tek danger/error sinyalleme yoludur
     * (Block Kit-only mesajlar nötr görünür).</p>
     *
     * <p>Package-private — testler doğrudan string'i doğrulayabilsin.</p>
     *
     * @param signedBytes opsiyonel; null/boş değilse ve
     *                    {@link InvalidSignatureNotificationConfiguration#isSlackInlineBase64Enabled()}
     *                    true ise içerik code-fenced base64 chunk'larına
     *                    bölünerek mesaja eklenir. Bot upload aktifse veya
     *                    boyut config eşiğini aşıyorsa fallback ATLANIR.
     */
    String buildSlackBody(VerificationResult result, String fileName, byte[] signedBytes,
                          Map<String, String> logHeaders) {
        Map<String, Object> root = new LinkedHashMap<>();

        String title = "Mersel DSS Verify - INVALID Signature";
        String fallbackText = title + ": " + safeFileName(fileName);
        // "text" alanı notification preview (mobile push, email digest)
        // için zorunlu. blocks olmasa da Slack mesajı yine düşer.
        root.put("text", fallbackText);

        List<Map<String, Object>> blocks = buildSlackBlocks(
                result, fileName, title, signedBytes, logHeaders);

        // attachments[].color → mesajın sol kenarında kırmızı dikey şerit.
        // Block Kit içeriği attachments[].blocks alanına gömülür; Slack
        // bunu inline olarak render eder.
        Map<String, Object> attachment = new LinkedHashMap<>();
        attachment.put("color", SLACK_DANGER_COLOR);
        attachment.put("blocks", blocks);
        // fallback: legacy clients için (mobile push notification text)
        attachment.put("fallback", fallbackText);
        root.put("attachments", Collections.singletonList(attachment));

        return serializeOrEmpty(root);
    }

    /**
     * Test/back-compat overload — {@code logHeaders} verilmediğinde header
     * blok'u eklenmez.
     */
    String buildSlackBody(VerificationResult result, String fileName, byte[] signedBytes) {
        return buildSlackBody(result, fileName, signedBytes, null);
    }

    /**
     * Slack mesaj gövdesini oluşturan Block Kit listesi — attachment
     * wrapper'dan bağımsız, file upload {@code initial_comment} için de
     * yeniden kullanılabilir kalsın diye ayrıştırıldı (uploader şu an
     * markdown plain text kullanıyor; ileride zenginleştirmek için hazır).
     */
    private List<Map<String, Object>> buildSlackBlocks(
            VerificationResult result, String fileName, String title, byte[] signedBytes,
            Map<String, String> logHeaders) {
        List<Map<String, Object>> blocks = new ArrayList<>();

        // 1) Header — Slack Block Kit'in header type'i en fazla 150 char
        // alır ve plain_text bekler.
        blocks.add(slackHeader("\uD83D\uDEA8 " + title));

        // 2) Özet field'ları — 2 sütunlu görünüm: dosya/status/format/sayı.
        List<Map<String, Object>> summaryFields = new ArrayList<>();
        summaryFields.add(slackField("*Dosya:*\n" + safeFileName(fileName)));
        summaryFields.add(slackField("*Status:*\n`" + safeStatus(result) + "`"));
        if (result.getSignatureType() != null) {
            summaryFields.add(slackField("*İmza Tipi:*\n" + result.getSignatureType().name()));
        }
        if (result.getSignatureCount() != null) {
            summaryFields.add(slackField("*İmza Sayısı:*\n" + result.getSignatureCount()));
        }
        if (result.getVerificationTime() != null) {
            summaryFields.add(slackField("*Doğrulama Zamanı:*\n"
                    + result.getVerificationTime().toInstant().toString()));
        }
        blocks.add(slackSectionWithFields(summaryFields));

        // 2.5) Korelasyon header'ları — request'e {@code x-log-*}
        // prefix'iyle gelen tüm header'lar. Operatör chat'te alarmı
        // kendi upstream akışına (gateway request ID, tenant, trace ID)
        // anında bağlasın diye sözlük sıralı listeleniyor. Hiç header
        // yoksa blok eklenmez (gürültü olmaz).
        if (logHeaders != null && !logHeaders.isEmpty()) {
            StringBuilder hsb = new StringBuilder("*Korelasyon (x-log-*):*\n");
            int listed = 0;
            for (Map.Entry<String, String> e : logHeaders.entrySet()) {
                if (listed >= SLACK_MAX_LOG_HEADERS_LISTED) {
                    hsb.append("• … (").append(logHeaders.size() - SLACK_MAX_LOG_HEADERS_LISTED)
                            .append(" header daha)\n");
                    break;
                }
                hsb.append("• `").append(e.getKey()).append("`: ")
                        .append(truncate(e.getValue(), 200)).append('\n');
                listed++;
            }
            blocks.add(slackSectionMarkdown(hsb.toString()));
        }

        // 3) Top-level hatalar — DSS jenerik mesajları + tolerance/rejection
        // sonrası servisin oluşturduğu hata listesi.
        List<String> errors = result.getErrors();
        if (errors != null && !errors.isEmpty()) {
            StringBuilder sb = new StringBuilder("*Hatalar:*\n");
            int count = 0;
            for (String err : errors) {
                if (count >= SLACK_MAX_ERRORS_LISTED) {
                    sb.append("• … (").append(errors.size() - SLACK_MAX_ERRORS_LISTED)
                            .append(" hata daha)\n");
                    break;
                }
                sb.append("• ").append(truncate(err, 250)).append('\n');
                count++;
            }
            blocks.add(slackSectionMarkdown(sb.toString()));
        }

        // 4) Per-signature kısa detay — özellikle multi-imzalı XML
        // dokümanlarında hangi imzanın FAIL olduğunu görmek değerli.
        List<SignatureInfo> signatures = result.getSignatures();
        if (signatures != null && !signatures.isEmpty()) {
            int listed = 0;
            for (SignatureInfo s : signatures) {
                if (listed >= SLACK_MAX_SIGNATURES_LISTED) {
                    blocks.add(slackSectionMarkdown(
                            "_… ve " + (signatures.size() - SLACK_MAX_SIGNATURES_LISTED)
                                    + " imza daha; tam detay için webhook payload'una bakın._"));
                    break;
                }
                blocks.add(slackSectionMarkdown(buildSignatureBlockText(s)));
                listed++;
            }
        }

        // 5) Inline base64 fallback — operatör bilinçli olarak
        // slackInlineBase64Enabled=true yaptıysa, doğrulanan dosyayı
        // Slack mesajının kendisine code-fenced snippet olarak gömüyoruz.
        // Bu kanal bot upload yolundan TAMAMEN BAĞIMSIZ; ikisi aynı anda
        // da tetiklenebilir (operatörün trade-off'u).
        appendInlineBase64Sections(blocks, signedBytes);

        return blocks;
    }

    /**
     * Doğrulanan dosyayı Slack mesajına <em>opsiyonel</em> base64 inline
     * eki olarak ekler. Operatör explicit {@code slackInlineBase64Enabled}
     * flag'ini set etmedikçe hiç çalışmaz — chat'i base64 ile kirletmeyiz.
     *
     * <h4>Davranış matrisi</h4>
     * <table>
     *   <tr><th>Koşul</th><th>Sonuç</th></tr>
     *   <tr><td>{@code !slackInlineBase64Enabled}</td>
     *       <td>Hiçbir blok eklenmez.</td></tr>
     *   <tr><td>{@code signedBytes} null/boş</td>
     *       <td>Hiçbir blok eklenmez.</td></tr>
     *   <tr><td>{@code signedBytes.length > slackInlineBase64MaxBytes}</td>
     *       <td>TEK bir omission notice bloğu eklenir
     *           (mesajda neden eksik olduğu açıkça görünür).</td></tr>
     *   <tr><td>Yukarıdakiler değilse</td>
     *       <td>Base64 üretilir, {@link #chunkForSlackSection} ile
     *           parçalara bölünür, her parça ayrı section block'a basılır.
     *           İlk blok prefix ("*İçerik (base64, N bytes):*") taşır,
     *           son blok decode-hint satırı taşır.</td></tr>
     * </table>
     *
     * <p><b>Veri bütünlüğü</b>: Base64 chunk'ları ASLA {@link #truncate}
     * edilmez (tek char kayıp dosyayı bozar). {@link #SLACK_INLINE_BASE64_CHUNK_CHARS}
     * (2700) Block Kit 3000-char/section sınırının altında, wrapper'larla
     * birlikte {@code slackSectionMarkdown}'ın 2900-char truncate eşiğinin
     * de güvenle altında.</p>
     */
    private void appendInlineBase64Sections(
            List<Map<String, Object>> blocks, byte[] signedBytes) {

        if (!config.isSlackInlineBase64Enabled()) {
            return;
        }
        if (signedBytes == null || signedBytes.length == 0) {
            return;
        }

        long limit = config.getSlackInlineBase64MaxBytes();
        if ((long) signedBytes.length > limit) {
            // Sessizce atlamak yerine mesaja somut bir notice koyuyoruz —
            // operatör/okuyucu chat'te "dosya neden gelmedi?" sorusuna
            // anında cevap görsün, sebep + alternatif çıkışlar açık. Tipik
            // fatura/PDF imzaları 50KB-1MB araliginda; Slack 40k char
            // mesaj limiti ile bu boyutlar inline'a sigmaz. Operatori
            // bot upload'a yonlendir (Slack ekosisteminin ICINDE; 1GB'a
            // kadar). Cozum kontrati: operator notice'i goruyorsa
            // inline-base64-max-bytes'i artirmak DEGIL, bot upload'a
            // gecmek dogru hamledir.
            blocks.add(slackSectionMarkdown(
                    "*İçerik:* Dosya boyutu (" + signedBytes.length
                            + " bytes) Slack mesajı inline limiti (" + limit
                            + " bytes) aşıyor.\n"
                            + "_Tipik fatura/PDF imzaları (28KB+) Slack mesaj toplam"
                            + " 40 000 char sınırına sığmaz; en doğru yol *Slack bot"
                            + " file upload* (`SLACK_BOT_TOKEN` + `SLACK_CHANNEL` set"
                            + " edin → dosya `files.slack.com`'a yüklenir, kanalda"
                            + " native indirilebilir dosya olarak görünür). Tam"
                            + " base64 içerik webhook payload'unda da mevcut._"));
            logger.info("Slack inline base64 skipped (oversized): {} bytes > {} bytes limit; "
                            + "omission notice mesaja eklendi (bot upload onerildi).",
                    signedBytes.length, limit);
            return;
        }

        String base64;
        try {
            base64 = Base64.getEncoder().encodeToString(signedBytes);
        } catch (Exception e) {
            // Pratikte buraya düşmez (Base64 encoder thread-safe ve allocation-only),
            // ama defense-in-depth: encoder bir gün exception atarsa Slack mesajı
            // yine de gitsin (yalnız inline kısmı atlanır).
            logger.warn("Slack inline base64 encode failed; inline blok atlandı: {}",
                    e.getMessage());
            return;
        }

        List<String> chunks = chunkForSlackSection(base64, SLACK_INLINE_BASE64_CHUNK_CHARS);
        if (chunks.isEmpty()) {
            return;
        }

        // Sabit prefix + suffix string'leri; her chunk için substring + concat
        // dışında alokasyon yok.
        String prefix = "*İçerik (base64, " + signedBytes.length + " bytes):*\n";
        String decodeHint = "\n_Decode: `pbpaste | base64 -d > signed.bin` (macOS)"
                + " / `xclip -o | base64 -d > signed.bin` (Linux)_";

        int total = chunks.size();
        for (int i = 0; i < total; i++) {
            StringBuilder sb = new StringBuilder(SLACK_INLINE_BASE64_CHUNK_CHARS + 200);
            if (i == 0) {
                sb.append(prefix);
            }
            sb.append("```\n").append(chunks.get(i)).append("\n```");
            if (i == total - 1) {
                sb.append(decodeHint);
            }
            blocks.add(slackSectionMarkdown(sb.toString()));
        }
    }

    /**
     * Verilen metni char-pencere algoritmasıyla en fazla {@code chunkSize}
     * uzunluğunda parçalara böler. Slack Block Kit'in 3000 char/section
     * limitine sığdırma için kullanılır; base64 string'leri için
     * <strong>kritik</strong>: tek char drift bile decode'u bozar.
     *
     * <p><b>Algoritma</b>: Sıkı yarı-açık aralıklarla
     * ({@code [i, i+chunkSize)}) ilerler. Her iterasyonda {@code i = end}
     * deterministik advance; başlangıç koşulu {@code i = 0} ve bitiş
     * {@code i = len} kesin sınırlar. Karakter tabanlı substring
     * Java'da O(1) (paylaşılan char[]); böylece N char için toplam
     * O(N) zaman ve N/chunkSize çıktı oluşur.</p>
     *
     * <p><b>Round-trip garantisi</b>: {@code String.join("", result)
     * .equals(text)} her zaman {@code true} — bu metod testle de
     * doğrulanır.</p>
     *
     * @param text       bölünecek string. {@code null} veya boş ise
     *                   boş liste döner.
     * @param chunkSize  her parça için <strong>maksimum</strong> char.
     *                   {@code > 0} olmalı, aksi halde IllegalArgumentException.
     * @return Sıralı chunk listesi. Birleştirildiğinde orijinal metni verir.
     * @throws IllegalArgumentException {@code chunkSize <= 0}.
     */
    static List<String> chunkForSlackSection(String text, int chunkSize) {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException(
                    "chunkSize must be > 0; got " + chunkSize);
        }
        if (text == null || text.isEmpty()) {
            return Collections.emptyList();
        }
        int len = text.length();
        if (len <= chunkSize) {
            return Collections.singletonList(text);
        }
        int expected = (len + chunkSize - 1) / chunkSize;
        List<String> out = new ArrayList<>(expected);
        int i = 0;
        while (i < len) {
            int end = Math.min(i + chunkSize, len);
            out.add(text.substring(i, end));
            i = end;
        }
        return out;
    }

    /** Slack file upload title — Slack dosya başlığında görünür. */
    String buildSlackFileTitle(VerificationResult result, String fileName) {
        String name = safeFileName(fileName);
        String type = result.getSignatureType() != null
                ? result.getSignatureType().name() : "Signature";
        return "[INVALID " + type + "] " + name;
    }

    /**
     * Slack file upload initial_comment — dosyanın altında kanal mesajı
     * olarak görünür. Block Kit kullanmıyoruz çünkü
     * {@code completeUploadExternal} initial_comment için zengin format
     * desteği sınırlı; mrkdwn-flavored plain text en güvenli yol.
     */
    String buildSlackFileInitialComment(VerificationResult result, String fileName,
                                        Map<String, String> logHeaders) {
        StringBuilder sb = new StringBuilder();
        sb.append(":rotating_light: *Mersel DSS Verify – INVALID Signature*\n");
        sb.append("• Dosya: `").append(safeFileName(fileName)).append("`\n");
        sb.append("• Status: `").append(safeStatus(result)).append("`\n");
        if (result.getSignatureType() != null) {
            sb.append("• İmza Tipi: `").append(result.getSignatureType().name()).append("`\n");
        }
        if (result.getSignatureCount() != null) {
            sb.append("• İmza Sayısı: ").append(result.getSignatureCount()).append('\n');
        }
        List<String> errors = result.getErrors();
        if (errors != null && !errors.isEmpty()) {
            sb.append("• İlk Hata: ").append(truncate(errors.get(0), 250)).append('\n');
        }
        if (logHeaders != null && !logHeaders.isEmpty()) {
            sb.append("• Korelasyon (x-log-*):");
            int listed = 0;
            for (Map.Entry<String, String> e : logHeaders.entrySet()) {
                if (listed >= SLACK_MAX_LOG_HEADERS_LISTED) {
                    sb.append(" … (+")
                            .append(logHeaders.size() - SLACK_MAX_LOG_HEADERS_LISTED)
                            .append(")");
                    break;
                }
                sb.append(" `").append(e.getKey()).append("`=")
                        .append(truncate(e.getValue(), 120));
                listed++;
            }
            sb.append('\n');
        }
        return truncate(sb.toString(), 1500);
    }

    /**
     * Back-compat overload — eski testler korelasyon header'sız çağırabilsin.
     */
    String buildSlackFileInitialComment(VerificationResult result, String fileName) {
        return buildSlackFileInitialComment(result, fileName, null);
    }

    private InvalidSignatureWebhookPayload.FileEnvelope buildFileEnvelope(
            byte[] bytes, String fileName, String contentType) {
        InvalidSignatureWebhookPayload.FileEnvelope envelope =
                new InvalidSignatureWebhookPayload.FileEnvelope();
        envelope.setName(fileName);
        envelope.setContentType(contentType);

        if (bytes == null) {
            return envelope;
        }
        envelope.setSizeBytes((long) bytes.length);
        envelope.setSha256Hex(sha256Hex(bytes));

        if (!config.isIncludeContent()) {
            envelope.setContentOmittedReason(OMITTED_BY_CONFIG);
        } else if ((long) bytes.length > config.getMaxContentSizeBytes()) {
            envelope.setContentOmittedReason(OMITTED_EXCEEDED_MAX_SIZE);
            logger.debug("Webhook payload'una içerik dahil edilmedi: dosya boyutu {} > sınır {}",
                    bytes.length, config.getMaxContentSizeBytes());
        } else {
            envelope.setBase64Content(Base64.getEncoder().encodeToString(bytes));
        }
        return envelope;
    }

    /**
     * Generic webhook POST'u — HMAC imzası + delivery-id + timestamp
     * header'larını ekler. Receiver bu header'lardan üç şey doğrular:
     * <ol>
     *   <li><b>Authenticity</b> — {@code X-Mersel-Signature} secret'la
     *       yeniden hesaplanırsa eşleşir → istek Mersel'den geliyor.</li>
     *   <li><b>Replay protection</b> — {@code X-Mersel-Webhook-Timestamp}
     *       receiver'ın izin verdiği pencerede (örn. son 5 dakika).</li>
     *   <li><b>Idempotency</b> — {@code X-Mersel-Webhook-Id} UUID; aynı
     *       ID iki kere gelirse receiver tekrarı sessizce yutar.</li>
     * </ol>
     *
     * <p>Secret set değilse {@code X-Mersel-Signature} header'ı ATILMAZ —
     * receiver bu durumda yalnız URL gizliliğine güvenir (Slack incoming
     * webhook modeli paraleli).</p>
     */
    private void fireWebhookPost(String url, String jsonBody, Map<String, String> logHeaders) {
        if (httpClient == null) {
            // Lazy init + runtime config değişimi defansı: PostConstruct
            // sırasında hiçbir destination yoktu, OkHttpClient kurulmadı.
            // Şimdi config set edildi ve dispatch denendi — büyük olasılıkla
            // operatör hatası (bean refresh atlandı). WARN'la sus, akış
            // bozulmasın.
            logger.warn("InvalidSignatureNotifier webhook: HTTP client başlatılmamış "
                    + "(başlangıçta destination yoktu); bildirim atlanıyor. "
                    + "Bean'i yeniden yaratın veya servisi restart edin.");
            return;
        }
        if (jsonBody == null || jsonBody.isEmpty()) {
            logger.warn("InvalidSignatureNotifier webhook: serialized body boş, gönderim atlandı.");
            return;
        }

        String deliveryId = idGenerator.get();
        long timestampSeconds = unixSecondsClock.getAsLong();

        Request.Builder builder;
        try {
            builder = new Request.Builder()
                    .url(url)
                    .header("User-Agent", resolveSource())
                    .header("Accept", "application/json")
                    .header(HEADER_WEBHOOK_EVENT, EVENT_TYPE_INVALID_SIGNATURE)
                    .header(HEADER_WEBHOOK_ID, deliveryId)
                    .header(HEADER_WEBHOOK_TIMESTAMP, String.valueOf(timestampSeconds))
                    .post(RequestBody.create(jsonBody, JSON_MEDIA_TYPE));
        } catch (IllegalArgumentException badUrl) {
            logger.warn("InvalidSignatureNotifier webhook: URL geçersiz, gönderim atlandı: {}",
                    badUrl.getMessage());
            return;
        }

        // Korelasyon header'larını PASS-THROUGH olarak ekle — receiver
        // upstream'e zincirleme bağlandığında aynı x-log-* başlıklarıyla
        // kendi log'larını işaretleyebilsin. Header değerleri zaten
        // {@link LogHeadersFilter#sanitizeValue} ile CR/LF temizlenmiş;
        // ama yine de OkHttp Headers builder'ın illegal değer (örn.
        // header isminde Unicode/whitespace) atması durumunda zinciri
        // kesmeden geç — defense-in-depth.
        if (logHeaders != null && !logHeaders.isEmpty()) {
            for (Map.Entry<String, String> e : logHeaders.entrySet()) {
                try {
                    builder.header(e.getKey(), e.getValue());
                } catch (Exception headerEx) {
                    logger.debug("InvalidSignatureNotifier webhook: log header eklenemedi "
                                    + "(name={}): {}",
                            e.getKey(), headerEx.getMessage());
                }
            }
        }

        if (config.hasWebhookSecret()) {
            // signingString = "<timestamp>.<rawBody>" — Stripe-style. Sadece
            // body'i imzalamak yetmez: receiver eski bir bildirimi yakalayıp
            // replay edebilir. Timestamp'i imzanın içine almak bu vektörü
            // kapatır (receiver fresh timestamp window kontrol etmeli).
            String signingString = timestampSeconds + "." + jsonBody;
            String signatureHex = computeHmacSha256Hex(signingString, config.getWebhookSecret());
            if (signatureHex != null) {
                builder.header(HEADER_WEBHOOK_SIGNATURE, "sha256=" + signatureHex);
            }
        }

        Call call = httpClient.newCall(builder.build());
        call.enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                // OkHttp connect / read / write timeout, DNS hatası, TLS
                // handshake reset hepsi buraya düşer — async dispatcher
                // thread'inde. WARN log + sus.
                logger.warn("InvalidSignatureNotifier webhook POST başarısız ({}): {} [delivery-id={}]",
                        url, e.getMessage(), deliveryId);
            }

            @Override
            public void onResponse(Call call, Response response) {
                try {
                    int code = response.code();
                    if (code >= 200 && code < 300) {
                        logger.debug("InvalidSignatureNotifier webhook POST OK ({} {}) [delivery-id={}]",
                                code, url, deliveryId);
                    } else {
                        logger.warn("InvalidSignatureNotifier webhook POST non-2xx: "
                                        + "{} {} (receiver={}, delivery-id={})",
                                code, response.message(), url, deliveryId);
                    }
                } catch (Throwable t) {
                    // Defense-in-depth: callback'te response.code() veya
                    // response.message() tamamen güvenli olmalı ama
                    // OkHttp body parse error veya custom interceptor
                    // patolojilerine karşı yine de sarıyoruz. Uncaught
                    // dispatcher exception OkHttp pool'unda gürültü
                    // yaratır, biz susturuyoruz.
                    logger.warn("InvalidSignatureNotifier webhook callback beklenmedik hata: {}",
                            t.toString());
                } finally {
                    try { response.close(); } catch (Exception ignore) { }
                }
            }
        });
    }

    /**
     * Slack incoming webhook gibi <em>auth'u URL gizliliğine</em> dayanan
     * kanallar için sade POST. HMAC eklemek Slack tarafında parse
     * edilemez; receiver doğrulaması zaten URL'in kendisi.
     */
    private void fireSimplePost(String url, String jsonBody, String channelLabel) {
        if (httpClient == null) {
            // Aynı lazy-init guard'i (bkz. fireWebhookPost)
            logger.warn("InvalidSignatureNotifier {}: HTTP client başlatılmamış "
                    + "(başlangıçta destination yoktu); bildirim atlanıyor.",
                    channelLabel);
            return;
        }
        if (jsonBody == null || jsonBody.isEmpty()) {
            logger.warn("InvalidSignatureNotifier {}: serialized body boş, gönderim atlandı.",
                    channelLabel);
            return;
        }
        Request request;
        try {
            request = new Request.Builder()
                    .url(url)
                    .header("User-Agent", resolveSource())
                    .header("Accept", "application/json")
                    .post(RequestBody.create(jsonBody, JSON_MEDIA_TYPE))
                    .build();
        } catch (IllegalArgumentException badUrl) {
            logger.warn("InvalidSignatureNotifier {}: URL geçersiz, gönderim atlandı: {}",
                    channelLabel, badUrl.getMessage());
            return;
        }
        httpClient.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                logger.warn("InvalidSignatureNotifier {} POST başarısız ({}): {}",
                        channelLabel, url, e.getMessage());
            }

            @Override
            public void onResponse(Call call, Response response) {
                try {
                    int code = response.code();
                    if (code >= 200 && code < 300) {
                        logger.debug("InvalidSignatureNotifier {} POST OK ({} {})",
                                channelLabel, code, url);
                    } else {
                        logger.warn("InvalidSignatureNotifier {} POST non-2xx: {} {} (receiver={})",
                                channelLabel, code, response.message(), url);
                    }
                } catch (Throwable t) {
                    logger.warn("InvalidSignatureNotifier {} callback beklenmedik hata: {}",
                            channelLabel, t.toString());
                } finally {
                    try { response.close(); } catch (Exception ignore) { }
                }
            }
        });
    }

    /**
     * HMAC-SHA256 hesaplayıp lowercase hex döner. Anahtarın UTF-8 byte'ları
     * kullanılır — endüstri standardı (Stripe, GitHub, Slack hepsi UTF-8).
     * Algoritma platform'da yoksa (pratikte imkânsız) {@code null} döner;
     * caller header'ı atlar.
     */
    static String computeHmacSha256Hex(String message, String secret) {
        if (message == null || secret == null || secret.isEmpty()) {
            return null;
        }
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM));
            byte[] raw = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(raw.length * 2);
            for (byte b : raw) {
                hex.append(String.format("%02x", b & 0xff));
            }
            return hex.toString();
        } catch (Exception e) {
            logger.warn("HMAC-SHA256 hesaplanamadı: {}", e.getMessage());
            return null;
        }
    }

    private String serializeOrEmpty(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            logger.warn("InvalidSignatureNotifier serializasyon hatası ({}): {}",
                    obj.getClass().getSimpleName(), e.getMessage());
            return "";
        }
    }

    private String resolveSource() {
        if (buildProperties != null) {
            String name = buildProperties.getName() != null
                    ? buildProperties.getName() : "mersel-dss-verify-api";
            String version = buildProperties.getVersion() != null
                    ? buildProperties.getVersion() : "unknown";
            return name + "/" + version;
        }
        return "mersel-dss-verify-api/unknown";
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(bytes);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 her JRE'de zorunlu — pratikte buraya düşmez.
            return null;
        }
    }

    private static String safeFileName(String fileName) {
        if (fileName == null || fileName.trim().isEmpty()) {
            return "<unknown>";
        }
        return fileName;
    }

    private static String safeStatus(VerificationResult r) {
        return r.getStatus() != null ? r.getStatus() : "INVALID";
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, max - 1) + "…";
    }

    private static String buildSignatureBlockText(SignatureInfo s) {
        StringBuilder sb = new StringBuilder();
        sb.append("*İmza:* `").append(s.getSignatureId() != null ? s.getSignatureId() : "<no-id>").append("`\n");
        if (s.getSignatureFormat() != null) {
            sb.append("• Format: ").append(s.getSignatureFormat()).append('\n');
        }
        if (s.getIndication() != null) {
            sb.append("• Indication: `").append(s.getIndication()).append('`');
            if (s.getSubIndication() != null) {
                sb.append(" / `").append(s.getSubIndication()).append('`');
            }
            sb.append('\n');
        }
        if (s.getSignerCertificate() != null && s.getSignerCertificate().getCommonName() != null) {
            sb.append("• İmzacı: ").append(s.getSignerCertificate().getCommonName()).append('\n');
        }
        // Mersel rejection kodları — operatör için en değerli sinyal
        if (s.getAppliedRejections() != null && !s.getAppliedRejections().isEmpty()) {
            sb.append("• Mersel Rejection: ");
            int i = 0;
            for (io.mersel.dss.verify.api.models.AppliedRejection r : s.getAppliedRejections()) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append('`').append(r.getCode()).append('`');
                i++;
            }
            sb.append('\n');
        }
        return truncate(sb.toString(), 2900); // Block Kit section text ~3000 char
    }

    private static Map<String, Object> slackHeader(String text) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("type", "header");
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("type", "plain_text");
        t.put("text", truncate(text, 150));
        t.put("emoji", true);
        b.put("text", t);
        return b;
    }

    private static Map<String, Object> slackSectionMarkdown(String text) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("type", "section");
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("type", "mrkdwn");
        t.put("text", truncate(text, 2900));
        b.put("text", t);
        return b;
    }

    private static Map<String, Object> slackSectionWithFields(List<Map<String, Object>> fields) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("type", "section");
        b.put("fields", fields);
        return b;
    }

    private static Map<String, Object> slackField(String mrkdwn) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("type", "mrkdwn");
        f.put("text", truncate(mrkdwn, 2000));
        return f;
    }

    /** Test hook'u — sabit zamanla payload üretmek için. */
    void setClock(java.util.function.Supplier<Date> clock) {
        if (clock != null) {
            this.clock = clock;
        }
    }

    /** Test hook'u — webhook timestamp header'ını deterministik kılmak için. */
    void setUnixSecondsClock(LongSupplier unixSecondsClock) {
        if (unixSecondsClock != null) {
            this.unixSecondsClock = unixSecondsClock;
        }
    }

    /** Test hook'u — webhook delivery-id'sini sabitlemek için. */
    void setIdGenerator(java.util.function.Supplier<String> idGenerator) {
        if (idGenerator != null) {
            this.idGenerator = idGenerator;
        }
    }

    /** Test hook'u — gerçek OkHttp yerine MockWebServer'a yönlendirilmiş client koymak için. */
    void setHttpClient(OkHttpClient httpClient) {
        if (httpClient != null) {
            this.httpClient = httpClient;
        }
    }

    /** Test hook'u — özelleştirilmiş SlackFileUploader (örn. apiBaseUrl override edilmiş) inject etmek için. */
    void setSlackFileUploader(SlackFileUploader slackFileUploader) {
        this.slackFileUploader = slackFileUploader;
    }

    /** Test hook'u — config olmadan unit testlerin notifier'ı kurabilmesi için. */
    void setConfig(InvalidSignatureNotificationConfiguration config) {
        this.config = config;
    }
}
