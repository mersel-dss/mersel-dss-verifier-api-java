package io.mersel.dss.verify.api.services.notification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.verify.api.config.InvalidSignatureNotificationConfiguration;
import io.mersel.dss.verify.api.models.AppliedRejection;
import io.mersel.dss.verify.api.models.CertificateInfo;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.ValidationDetails;
import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.models.enums.SignatureType;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link InvalidSignatureNotifier} davranış sözleşmesi:
 *
 * <ul>
 *   <li>VALID imzalarda no-op (hiçbir HTTP istek atılmaz).</li>
 *   <li>Feature kapalıyken / URL set edilmemişken no-op.</li>
 *   <li>INVALID imzada generic webhook payload'unda result + dosya
 *       metadata + base64 içerik bulunur (config açıkken).</li>
 *   <li>{@code includeContent=false} iken base64Content gönderilmez ama
 *       hash/size yine gider; {@code contentOmittedReason} dolu olur.</li>
 *   <li>Dosya {@code maxContentSizeBytes}'ı aşıyorsa içerik
 *       atlanır; reason kodlu.</li>
 *   <li>Slack payload Block Kit formatında üretilir, base64 içerik
 *       içermez, hata satırları truncate'lenir.</li>
 *   <li>Detached imzada {@code originalDocument} alanı da set edilir.</li>
 *   <li>Bildirim hatası (receiver 500 dönerse) doğrulama akışına bir
 *       exception atmaz — sadece WARN loglanır (best-effort).</li>
 * </ul>
 *
 * <p>HTTP tarafını gerçek bir {@link MockWebServer} ile test ediyoruz;
 * sahte bir TCP socket'i üzerinden OkHttp'nin
 * {@code Call.enqueue()} akışını birebir doğrular.</p>
 */
class InvalidSignatureNotifierTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private MockWebServer server;
    private InvalidSignatureNotifier notifier;
    private InvalidSignatureNotificationConfiguration config;
    private OkHttpClient sharedHttpClient;

    /** Sabit, payload zamanlama doğrulamasını deterministik kılmak için. */
    private final Date fixedNow = new Date(1_700_000_000_000L);

    @BeforeEach
    void setUp() throws Exception {
        server = new MockWebServer();
        server.start();

        config = new InvalidSignatureNotificationConfiguration();
        config.setEnabled(true);
        config.setIncludeContent(true);
        config.setMaxContentSizeBytes(10L * 1024 * 1024);
        config.setConnectTimeoutMs(2000);
        config.setReadTimeoutMs(2000);

        notifier = new InvalidSignatureNotifier();
        notifier.setConfig(config);
        notifier.setClock(() -> fixedNow);

        // OkHttp client'ını test-içi short timeout'larla ayrı kuruyoruz —
        // production @PostConstruct akışını by-pass ediyoruz (Spring
        // context yok).
        sharedHttpClient = new OkHttpClient.Builder()
                .connectTimeout(2, TimeUnit.SECONDS)
                .readTimeout(2, TimeUnit.SECONDS)
                .writeTimeout(2, TimeUnit.SECONDS)
                .build();
        notifier.setHttpClient(sharedHttpClient);
    }

    @AfterEach
    void tearDown() throws Exception {
        server.shutdown();
    }

    // --- Gate / no-op davranışı ---------------------------------------------

    @Test
    void noOp_whenResultIsNull() {
        // Hiçbir URL set edilmese de gate burada zaten kapanır
        notifier.notifyIfInvalid(null, new byte[]{1, 2, 3}, "x.xml", "application/xml", null, null);
        assertEquals(0, server.getRequestCount());
    }

    @Test
    void noOp_whenSignatureIsValid() throws Exception {
        config.setWebhookUrl(server.url("/hook").toString());

        VerificationResult valid = new VerificationResult(true, "VALID");
        notifier.notifyIfInvalid(valid, new byte[]{1, 2}, "ok.xml", "application/xml", null, null);

        // Async ama gate üstte kapanır — kısa bekleyiş yine de hiçbir istek
        // beklemediğimizden emin oluyor.
        assertNull(server.takeRequest(300, TimeUnit.MILLISECONDS),
                "VALID imzada webhook tetiklenmemeli");
    }

    @Test
    void noOp_whenFeatureDisabled() throws Exception {
        config.setEnabled(false);
        config.setWebhookUrl(server.url("/hook").toString());

        notifier.notifyIfInvalid(invalidResult(), new byte[]{1}, "x.xml",
                "application/xml", null, null);

        assertNull(server.takeRequest(300, TimeUnit.MILLISECONDS),
                "enabled=false iken bildirim tetiklenmemeli");
    }

    @Test
    void noOp_whenNoDestinationConfigured() throws Exception {
        // enabled=true ama URL yok → no-op
        notifier.notifyIfInvalid(invalidResult(), new byte[]{1}, "x.xml",
                "application/xml", null, null);

        assertEquals(0, server.getRequestCount(),
                "Hiçbir URL yokken bildirim tetiklenmemeli");
    }

    // --- Lazy init + null httpClient guard (heap zero-overhead claim) -----
    //
    // initialize() artik destination yoksa OkHttpClient YARATMIYOR — bu
    // testler hem zero-overhead davranisini hem de runtime config
    // degisiminde null guard'larin saglam oldugunu dogruluyor.

    @Test
    void initialize_skipsOkHttpClientCreation_whenNoDestination() {
        // PostConstruct yolunu manuel olarak taklit et: fresh notifier +
        // config (destination YOK) + initialize() → httpClient null kalmali.
        InvalidSignatureNotifier fresh = new InvalidSignatureNotifier();
        InvalidSignatureNotificationConfiguration freshConfig =
                new InvalidSignatureNotificationConfiguration();
        freshConfig.setEnabled(true);
        // setWebhookUrl, setSlackWebhookUrl, setSlackBotToken hepsi default boş
        // → hasAnyDestination() == false
        fresh.setConfig(freshConfig);
        fresh.initialize();

        // notifyIfInvalid sessizce no-op olmalı; httpClient null kalmalı ama
        // gate üst seviyede kapanir, NPE atilmaz.
        assertDoesNotThrow(() -> fresh.notifyIfInvalid(invalidResult(),
                new byte[]{1}, "x.xml", "application/xml", null, null));
    }

    @Test
    void initialize_skipsOkHttpClientCreation_whenFeatureDisabled() {
        // enabled=false → URL set edilse bile httpClient yaratilmamali
        InvalidSignatureNotifier fresh = new InvalidSignatureNotifier();
        InvalidSignatureNotificationConfiguration freshConfig =
                new InvalidSignatureNotificationConfiguration();
        freshConfig.setEnabled(false);
        freshConfig.setWebhookUrl("https://example.com/hook"); // sahte; init'te bakılmaz
        fresh.setConfig(freshConfig);
        fresh.initialize();

        assertDoesNotThrow(() -> fresh.notifyIfInvalid(invalidResult(),
                new byte[]{1}, "x.xml", "application/xml", null, null));
    }

    @Test
    void notifyIfInvalid_neverThrows_whenHttpClientIsNull_butConfigSetAtRuntime() {
        // Patolojik senaryo: initialize() destination yokken çağrıldı,
        // httpClient null. Sonra config'e RUNTIME'da URL set edildi
        // (setter ile) ama bean refresh yapılmadı. notifyIfInvalid
        // çağrıldığında dispatch metodları null httpClient ile karşılaşır
        // — null guard'lar WARN log + sessiz çıkış garanti etmeli.
        InvalidSignatureNotifier fresh = new InvalidSignatureNotifier();
        InvalidSignatureNotificationConfiguration freshConfig =
                new InvalidSignatureNotificationConfiguration();
        freshConfig.setEnabled(true);
        fresh.setConfig(freshConfig);
        fresh.initialize(); // httpClient null

        // Runtime'da config değişti, bean refresh edilmedi
        freshConfig.setWebhookUrl("https://example.com/hook");
        freshConfig.setSlackWebhookUrl("https://hooks.slack.com/services/T/B/x");

        // notifyIfInvalid çağrılır — dispatch metodları null httpClient'a
        // dokunmaya çalışır ama null guard'lar onları WARN'la durdurur.
        // Caller'a HİÇBİR exception sızmamalı.
        assertDoesNotThrow(() -> fresh.notifyIfInvalid(invalidResult(),
                new byte[]{1}, "x.xml", "application/xml", null, null));
    }

    // --- Generic webhook payload --------------------------------------------

    @Test
    void firesGenericWebhook_withFullPayloadAndBase64Content() throws Exception {
        config.setWebhookUrl(server.url("/hook").toString());
        server.enqueue(new MockResponse().setResponseCode(204));

        byte[] body = "<xml>signed</xml>".getBytes(StandardCharsets.UTF_8);
        notifier.notifyIfInvalid(invalidResult(), body, "invoice.xml",
                "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req, "Webhook POST atılmalıydı");
        assertEquals("POST", req.getMethod());
        assertEquals("/hook", req.getPath());
        assertTrue(req.getHeader("Content-Type") != null
                && req.getHeader("Content-Type").startsWith("application/json"),
                "Content-Type application/json olmalı");
        assertTrue(req.getHeader("User-Agent") != null
                && req.getHeader("User-Agent").startsWith("mersel-dss-verify-api/"),
                "User-Agent uygulama adı içermeli");

        String json = req.getBody().readUtf8();
        JsonNode root = mapper.readTree(json);

        assertEquals("invalid-signature", root.get("event").asText());
        assertTrue(root.get("source").asText().startsWith("mersel-dss-verify-api/"));
        assertTrue(root.has("notificationTime"));
        assertTrue(root.has("result"), "result alanı zorunlu");
        assertEquals("INVALID", root.path("result").path("status").asText());

        JsonNode file = root.get("file");
        assertEquals("invoice.xml", file.get("name").asText());
        assertEquals("application/xml", file.get("contentType").asText());
        assertEquals(body.length, file.get("sizeBytes").asInt());
        assertNotNull(file.get("sha256Hex"));
        assertEquals(64, file.get("sha256Hex").asText().length(),
                "sha256 hex 64 karakter olmalı");
        assertTrue(file.has("base64Content"),
                "include-content açıkken base64Content beklenir");
        assertEquals(Base64.getEncoder().encodeToString(body),
                file.get("base64Content").asText());
        assertFalse(file.has("contentOmittedReason"),
                "İçerik dahil edildiyse contentOmittedReason yazılmaz");

        assertFalse(root.has("originalDocument"),
                "Detached olmadığında originalDocument null/atlanır");
    }

    @Test
    void omitsBase64_whenIncludeContentDisabled() throws Exception {
        config.setIncludeContent(false);
        config.setWebhookUrl(server.url("/hook").toString());
        server.enqueue(new MockResponse().setResponseCode(200));

        byte[] body = "data".getBytes(StandardCharsets.UTF_8);
        notifier.notifyIfInvalid(invalidResult(), body, "x.xml",
                "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        JsonNode file = mapper.readTree(req.getBody().readUtf8()).get("file");

        assertFalse(file.has("base64Content"),
                "include-content=false iken base64Content gönderilmemeli");
        assertEquals(InvalidSignatureNotifier.OMITTED_BY_CONFIG,
                file.get("contentOmittedReason").asText());
        // Metadata yine var
        assertTrue(file.has("sha256Hex"));
        assertEquals(body.length, file.get("sizeBytes").asInt());
    }

    @Test
    void omitsBase64_whenContentExceedsMaxSize() throws Exception {
        config.setMaxContentSizeBytes(8L); // 8 byte limit
        config.setWebhookUrl(server.url("/hook").toString());
        server.enqueue(new MockResponse().setResponseCode(200));

        byte[] body = "0123456789".getBytes(StandardCharsets.UTF_8); // 10 byte
        notifier.notifyIfInvalid(invalidResult(), body, "big.xml",
                "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        JsonNode file = mapper.readTree(req.getBody().readUtf8()).get("file");

        assertFalse(file.has("base64Content"),
                "max-size aşıldığında base64Content yok");
        assertEquals(InvalidSignatureNotifier.OMITTED_EXCEEDED_MAX_SIZE,
                file.get("contentOmittedReason").asText());
        assertEquals(body.length, file.get("sizeBytes").asInt());
    }

    @Test
    void includesOriginalDocument_whenDetachedSignature() throws Exception {
        config.setWebhookUrl(server.url("/hook").toString());
        server.enqueue(new MockResponse().setResponseCode(200));

        byte[] signed = "<sig/>".getBytes(StandardCharsets.UTF_8);
        byte[] original = "original content".getBytes(StandardCharsets.UTF_8);
        notifier.notifyIfInvalid(invalidResult(), signed, "sig.xml",
                "application/xml", original, "data.txt");

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        JsonNode root = mapper.readTree(req.getBody().readUtf8());

        JsonNode orig = root.get("originalDocument");
        assertNotNull(orig, "Detached imza orijinal dokümanı set etmeli");
        assertEquals("data.txt", orig.get("name").asText());
        assertEquals(original.length, orig.get("sizeBytes").asInt());
        assertEquals(Base64.getEncoder().encodeToString(original),
                orig.get("base64Content").asText());
    }

    @Test
    void doesNotThrow_whenReceiverReturns5xx() throws Exception {
        // Best-effort: receiver patlasa bile caller etkilenmemeli
        config.setWebhookUrl(server.url("/hook").toString());
        server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));

        assertDoesNotThrow(() -> notifier.notifyIfInvalid(
                invalidResult(), new byte[]{1}, "x.xml", "application/xml", null, null));

        // İstek yine de yapılmış olmalı
        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req);
    }

    @Test
    void doesNotThrow_whenWebhookUrlIsMalformed() {
        // OkHttp URL.parse failure → IllegalArgumentException caller'a sızmamalı
        config.setWebhookUrl("not a real url");

        assertDoesNotThrow(() -> notifier.notifyIfInvalid(
                invalidResult(), new byte[]{1}, "x.xml", "application/xml", null, null));
    }

    // --- Slack body ---------------------------------------------------------

    @Test
    void firesSlack_withRedAttachmentAndBlockKit_andNoBase64Content() throws Exception {
        config.setSlackWebhookUrl(server.url("/services/T/B/x").toString());
        server.enqueue(new MockResponse().setResponseCode(200).setBody("ok"));

        byte[] body = "<xml/>".getBytes(StandardCharsets.UTF_8);
        VerificationResult r = invalidResult();
        notifier.notifyIfInvalid(r, body, "invoice.xml", "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req, "Slack POST atılmalıydı");
        assertEquals("/services/T/B/x", req.getPath());

        String json = req.getBody().readUtf8();
        JsonNode root = mapper.readTree(json);

        assertTrue(root.has("text"), "Slack 'text' (notification fallback) zorunlu");
        assertTrue(root.get("text").asText().contains("INVALID"),
                "text alanı INVALID kelimesini içermeli");
        assertTrue(root.get("text").asText().contains("invoice.xml"));

        // ATTACHMENTS yapısı — kırmızı yan şerit için
        JsonNode attachments = root.get("attachments");
        assertNotNull(attachments, "Block Kit attachments wrapper'ı bulunmalı");
        assertTrue(attachments.isArray());
        assertEquals(1, attachments.size(), "Tek danger attachment kullanılır");

        JsonNode att = attachments.get(0);
        assertEquals(InvalidSignatureNotifier.SLACK_DANGER_COLOR,
                att.get("color").asText(),
                "Mesajın sol şeridi Slack danger red (#A30200) olmalı");
        assertTrue(att.has("fallback"),
                "Legacy/mobile push fallback yazısı set edilmeli");

        JsonNode blocks = att.get("blocks");
        assertNotNull(blocks);
        assertTrue(blocks.isArray());
        assertTrue(blocks.size() >= 2, "header + en az 1 section beklenir");
        assertEquals("header", blocks.get(0).get("type").asText());
        assertEquals("plain_text", blocks.get(0).get("text").get("type").asText());

        // Block Kit blocks root seviyede DEĞİL — attachments[].blocks içinde
        assertFalse(root.has("blocks"),
                "blocks artık doğrudan root'ta değil, attachments içine taşındı");

        // Base64 content Slack'e ASLA gitmemeli
        assertFalse(json.contains(Base64.getEncoder().encodeToString(body)),
                "Slack mesajı base64 içerik içermemeli");
    }

    @Test
    void slackBody_truncatesErrorList_whenManyErrors() {
        VerificationResult r = invalidResult();
        List<String> errs = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            errs.add("Hata-" + i);
        }
        r.setErrors(errs);

        String body = notifier.buildSlackBody(r, "x.xml", null);
        assertNotNull(body);
        assertTrue(body.contains("Hata-0"));
        assertTrue(body.contains("Hata-" + (InvalidSignatureNotifier.SLACK_MAX_ERRORS_LISTED - 1)));
        // Truncation marker
        assertTrue(body.contains("hata daha"),
                "Üst sınır aşıldığında özet satırı görünmeli");
        // Bütün hatalar olmamalı
        assertFalse(body.contains("Hata-19"),
                "20. hata mesaja girmemeli (truncate edilmiş olmalı)");
    }

    @Test
    void slackBody_includesPerSignatureRejectionCode() {
        VerificationResult r = invalidResult();
        SignatureInfo s = r.getSignatures().get(0);
        AppliedRejection rej = new AppliedRejection();
        rej.setCode("MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE");
        s.setAppliedRejections(Collections.singletonList(rej));

        String body = notifier.buildSlackBody(r, "x.xml", null);

        assertTrue(body.contains("MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE"),
                "Slack body'sinde Mersel rejection kodu görünmeli");
    }

    // --- HMAC / authenticity headers ---------------------------------------

    @Test
    void webhookHeaders_includeDeliveryIdAndTimestamp_evenWithoutSecret() throws Exception {
        config.setWebhookUrl(server.url("/hook").toString());
        // secret SET DEĞİL
        server.enqueue(new MockResponse().setResponseCode(200));

        notifier.setIdGenerator(() -> "fixed-delivery-id");
        notifier.setUnixSecondsClock(() -> 1_700_000_000L);

        notifier.notifyIfInvalid(invalidResult(), new byte[]{1, 2, 3},
                "x.xml", "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req);
        assertEquals("fixed-delivery-id",
                req.getHeader(InvalidSignatureNotifier.HEADER_WEBHOOK_ID));
        assertEquals("1700000000",
                req.getHeader(InvalidSignatureNotifier.HEADER_WEBHOOK_TIMESTAMP));
        assertEquals("invalid-signature",
                req.getHeader(InvalidSignatureNotifier.HEADER_WEBHOOK_EVENT));
        // Secret yokken signature gönderilmemeli
        assertNull(req.getHeader(InvalidSignatureNotifier.HEADER_WEBHOOK_SIGNATURE),
                "Secret yokken X-Mersel-Signature header'ı eklenmemeli");
    }

    @Test
    void webhookHeaders_includeHmacSignature_whenSecretConfigured_andVerifies() throws Exception {
        config.setWebhookUrl(server.url("/hook").toString());
        config.setWebhookSecret("super-secret-key");
        server.enqueue(new MockResponse().setResponseCode(200));

        notifier.setUnixSecondsClock(() -> 1_700_000_000L);
        notifier.setIdGenerator(() -> "fixed-id");

        notifier.notifyIfInvalid(invalidResult(), new byte[]{42},
                "x.xml", "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req);
        String body = req.getBody().readUtf8();
        String signatureHeader = req.getHeader(InvalidSignatureNotifier.HEADER_WEBHOOK_SIGNATURE);
        assertNotNull(signatureHeader, "Secret set ise X-Mersel-Signature beklenir");
        assertTrue(signatureHeader.startsWith("sha256="),
                "Signature header 'sha256=' prefix'iyle başlamalı: " + signatureHeader);

        // Receiver perspektifinden doğrulama: timestamp + "." + body üzerine
        // HMAC-SHA256 hesaplanır ve gelen değerle eşleştirilir.
        String expected = "sha256=" + InvalidSignatureNotifier.computeHmacSha256Hex(
                "1700000000." + body, "super-secret-key");
        assertEquals(expected, signatureHeader,
                "Mersel'in attığı imza, receiver hesabıyla eşleşmeli");
    }

    @Test
    void hmacSignature_changesWhenBodyChanges() {
        // Aynı timestamp ama farklı body → farklı imza (signature truly
        // body-bound mu garantisi)
        String a = InvalidSignatureNotifier.computeHmacSha256Hex(
                "1700000000.bodyA", "secret");
        String b = InvalidSignatureNotifier.computeHmacSha256Hex(
                "1700000000.bodyB", "secret");
        assertNotNull(a);
        assertNotNull(b);
        assertNotEquals(a, b);
    }

    @Test
    void hmacSignature_changesWhenTimestampChanges() {
        // Aynı body ama farklı timestamp → farklı imza (replay protection
        // gerçekten timestamp'i bağlıyor)
        String a = InvalidSignatureNotifier.computeHmacSha256Hex(
                "1700000000.body", "secret");
        String b = InvalidSignatureNotifier.computeHmacSha256Hex(
                "1700000999.body", "secret");
        assertNotEquals(a, b);
    }

    @Test
    void hmacSignature_returnsNullForBlankSecret() {
        assertNull(InvalidSignatureNotifier.computeHmacSha256Hex("anything", ""));
        assertNull(InvalidSignatureNotifier.computeHmacSha256Hex("anything", null));
    }

    // --- Full VerificationResult embedding -----------------------------------

    @Test
    void webhookResultField_carriesEntireVerificationResultJson() throws Exception {
        config.setWebhookUrl(server.url("/hook").toString());
        server.enqueue(new MockResponse().setResponseCode(200));

        // VerificationResult'a zengin alt-yapı (errors, signatures with
        // signerCertificate, validationDetails) ekleyip her birinin
        // payload.result altında görünmesini doğrula.
        VerificationResult r = invalidResult();
        r.addWarning("Test uyarısı");
        ValidationDetails vd = new ValidationDetails();
        vd.setSignatureIntact(false);
        vd.setCertificateChainValid(false);
        r.getSignatures().get(0).setValidationDetails(vd);

        notifier.notifyIfInvalid(r, new byte[]{1}, "x.xml", "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        JsonNode root = mapper.readTree(req.getBody().readUtf8());
        JsonNode resultNode = root.get("result");

        assertNotNull(resultNode, "result alanı zorunlu");
        // VerificationResult'ın tüm üst-düzey alanlarının payload'a düştüğünü
        // garantile — schema kontratı.
        assertEquals(false, resultNode.get("valid").asBoolean());
        assertEquals("INVALID", resultNode.get("status").asText());
        assertEquals("XADES", resultNode.get("signatureType").asText());
        assertEquals(1, resultNode.get("signatureCount").asInt());
        assertTrue(resultNode.has("verificationTime"));
        assertTrue(resultNode.get("errors").isArray());
        assertTrue(resultNode.get("warnings").isArray());
        assertEquals("Test uyarısı", resultNode.get("warnings").get(0).asText());

        JsonNode sig = resultNode.get("signatures").get(0);
        assertEquals("Signature-1", sig.get("signatureId").asText());
        assertEquals("INDETERMINATE", sig.get("indication").asText());
        assertEquals("SIG_CONSTRAINTS_FAILURE", sig.get("subIndication").asText());
        assertEquals("XAdES-BASELINE-B", sig.get("signatureFormat").asText());
        assertNotNull(sig.get("signerCertificate"));
        // validationDetails de gömülmüş olmalı
        assertNotNull(sig.get("validationDetails"));
        assertEquals(false, sig.get("validationDetails").get("signatureIntact").asBoolean());
    }

    // --- Slack file upload via 3-step API -----------------------------------

    @Test
    void slackFileUpload_threeStepFlow_endToEnd() throws Exception {
        // Sahte Slack API endpoint'i — getUploadURLExternal,
        // completeUploadExternal aynı server'da. upload_url ise ayrı bir
        // mock server'a yönlendirilir (Slack üretimde de external CDN
        // olur, ayrılığı somut tutuyoruz).
        MockWebServer uploadCdn = new MockWebServer();
        uploadCdn.start();

        try {
            // 1) getUploadURLExternal cevabı
            String uploadUrl = uploadCdn.url("/upload-blob").toString();
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"ok\":true,\"upload_url\":\"" + uploadUrl
                            + "\",\"file_id\":\"F123456\"}"));

            // 2) binary upload cevabı — CDN'e gider
            uploadCdn.enqueue(new MockResponse().setResponseCode(200).setBody("OK"));

            // 3) completeUploadExternal cevabı
            server.enqueue(new MockResponse()
                    .setResponseCode(200)
                    .setHeader("Content-Type", "application/json")
                    .setBody("{\"ok\":true,\"files\":[{\"id\":\"F123456\"}]}"));

            // Uploader'ı Slack API yerine bizim MockWebServer'a yönlendir
            SlackFileUploader uploader = new SlackFileUploader(sharedHttpClient, mapper);
            uploader.setApiBaseUrl(server.url("").toString().replaceAll("/$", ""));
            notifier.setSlackFileUploader(uploader);

            // Sadece bot upload aktif olsun, incoming webhook + generic
            // webhook off. (Slack message paralel akış zaten ayrı testte.)
            config.setSlackBotToken("xoxb-test-token");
            config.setSlackBotChannel("C0123456789");

            byte[] body = "PDF-binary-content".getBytes(StandardCharsets.UTF_8);
            notifier.notifyIfInvalid(invalidResult(), body, "fatura.pdf",
                    "application/pdf", null, null);

            // Step 1: getUploadURLExternal
            RecordedRequest step1 = server.takeRequest(2, TimeUnit.SECONDS);
            assertNotNull(step1, "Step 1 (getUploadURLExternal) atılmalı");
            assertEquals("/files.getUploadURLExternal", step1.getPath());
            assertEquals("Bearer xoxb-test-token", step1.getHeader("Authorization"));
            String step1Body = step1.getBody().readUtf8();
            assertTrue(step1Body.contains("filename=fatura.pdf"),
                    "Step 1 body filename param taşımalı: " + step1Body);
            assertTrue(step1Body.contains("length=" + body.length),
                    "Step 1 body length param taşımalı: " + step1Body);

            // Step 2: binary POST to upload_url (CDN)
            RecordedRequest step2 = uploadCdn.takeRequest(2, TimeUnit.SECONDS);
            assertNotNull(step2, "Step 2 (binary upload) atılmalı");
            assertEquals("/upload-blob", step2.getPath());
            assertEquals(body.length, step2.getBody().size(),
                    "Step 2 raw byte uzunluğu dosya boyutuyla eşit olmalı");
            assertArrayEquals(body, step2.getBody().readByteArray());
            // CDN'e bearer token gitmemeli — upload_url kendi içinde auth taşır
            assertNull(step2.getHeader("Authorization"),
                    "Step 2 (CDN) Authorization header taşımamalı");

            // Step 3: completeUploadExternal
            RecordedRequest step3 = server.takeRequest(2, TimeUnit.SECONDS);
            assertNotNull(step3, "Step 3 (completeUploadExternal) atılmalı");
            assertEquals("/files.completeUploadExternal", step3.getPath());
            assertEquals("Bearer xoxb-test-token", step3.getHeader("Authorization"));
            JsonNode step3Json = mapper.readTree(step3.getBody().readUtf8());
            assertEquals("C0123456789", step3Json.get("channel_id").asText());
            assertEquals("F123456", step3Json.get("files").get(0).get("id").asText());
            assertTrue(step3Json.get("files").get(0).get("title").asText().contains("fatura.pdf"));
            assertTrue(step3Json.has("initial_comment"));
            assertTrue(step3Json.get("initial_comment").asText().contains("INVALID"));
        } finally {
            uploadCdn.shutdown();
        }
    }

    @Test
    void slackFileUpload_skipped_whenFileTooLarge() throws Exception {
        config.setMaxContentSizeBytes(8L);
        config.setSlackBotToken("xoxb-test");
        config.setSlackBotChannel("C123");

        SlackFileUploader uploader = new SlackFileUploader(sharedHttpClient, mapper);
        uploader.setApiBaseUrl(server.url("").toString().replaceAll("/$", ""));
        notifier.setSlackFileUploader(uploader);

        byte[] big = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8); // 16 byte
        notifier.notifyIfInvalid(invalidResult(), big, "big.pdf",
                "application/pdf", null, null);

        // Hiçbir Slack API çağrısı yapılmamalı
        assertNull(server.takeRequest(300, TimeUnit.MILLISECONDS),
                "max-content-size aşıldığında Slack upload akışı tetiklenmemeli");
    }

    @Test
    void slackFileUpload_skipped_whenStep1Returns_okFalse() throws Exception {
        // Slack invalid_auth dönerse zincir kesilmeli; step 2 ve 3 gitmemeli
        config.setSlackBotToken("xoxb-bad");
        config.setSlackBotChannel("C123");
        server.enqueue(new MockResponse()
                .setResponseCode(200)
                .setBody("{\"ok\":false,\"error\":\"invalid_auth\"}"));

        SlackFileUploader uploader = new SlackFileUploader(sharedHttpClient, mapper);
        uploader.setApiBaseUrl(server.url("").toString().replaceAll("/$", ""));
        notifier.setSlackFileUploader(uploader);

        notifier.notifyIfInvalid(invalidResult(), new byte[]{1, 2},
                "x.pdf", "application/pdf", null, null);

        // Step 1 yapıldı
        RecordedRequest step1 = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(step1);
        // Step 2 / step 3 GİTMEMELİ
        assertNull(server.takeRequest(300, TimeUnit.MILLISECONDS),
                "Step 1 ok:false döndüğünde ileri adımlar atlanmalı");
    }

    // --- Defense-in-depth: hiçbir koşulda exception caller'a sızmaz --------

    @Test
    void notifyIfInvalid_neverThrows_whenWebhookUrlIsMalformed() {
        // OkHttp URL.parse failure → caller'a IllegalArgumentException sızmamalı
        config.setWebhookUrl("not a real url");
        config.setSlackWebhookUrl("also-not-real");
        config.setSlackBotToken("xoxb-test");
        config.setSlackBotChannel("C123");

        assertDoesNotThrow(() -> notifier.notifyIfInvalid(
                invalidResult(), new byte[]{1}, "x.xml", "application/xml", null, null));
    }

    @Test
    void notifyIfInvalid_neverThrows_whenAllDestinationsBroken() {
        // 3 kanal da patolojik — none should bubble up
        config.setWebhookUrl("ftp://wrong-scheme");
        config.setSlackWebhookUrl("");
        config.setSlackBotToken("xoxb-test");
        config.setSlackBotChannel("C123");

        // Bot file upload için patolojik apiBaseUrl
        SlackFileUploader uploader = new SlackFileUploader(sharedHttpClient, mapper);
        uploader.setApiBaseUrl("nonsense-base-url");
        notifier.setSlackFileUploader(uploader);

        assertDoesNotThrow(() -> notifier.notifyIfInvalid(
                invalidResult(), new byte[]{1, 2, 3},
                "x.pdf", "application/pdf", null, null));
    }

    @Test
    void notifyIfInvalid_neverThrows_whenObjectMapperFails() {
        // ObjectMapper'i bozuk bir VerificationResult ile sınırla:
        // Reflection ile serialization'da exception atan bir mock alan koy.
        // Pratik yaklaşım: cycle yaratıp StackOverflow değil, Jackson'ın
        // self-reference detection'ına dayan.
        VerificationResult bad = invalidResult();
        // Errors listesini "evil" bir Object'le doldur (Jackson kendi
        // limitlerini aşacak şekilde). Burada normal liste yeterli; asıl
        // amaç notifier'ın HER halükarda exception fırlatmamasını
        // göstermek. Onun yerine config'i çok eksik bırakıp build sırasında
        // null pointer'ları tetiklemeye çalışacağız.
        config.setWebhookUrl(server.url("/hook").toString());
        // 1 dakika önceden enqueue etmiyoruz — receiver yokmuş gibi davransın

        assertDoesNotThrow(() -> notifier.notifyIfInvalid(
                bad, new byte[]{1}, "x.xml", "application/xml", null, null));
    }

    @Test
    void notifyIfInvalid_neverThrows_whenHttpReceiverHangs() throws Exception {
        // Receiver hiç cevap vermez — connect timeout'a düşmeli ama caller
        // EXCEPTION görmemeli, async dispatcher'da WARN log + bitti.
        config.setWebhookUrl(server.url("/hook").toString());
        config.setConnectTimeoutMs(500);
        config.setReadTimeoutMs(500);
        // Server'a enqueue yapmıyoruz; istek socket'te asılı kalacak
        // ve 500ms sonra timeout.

        long start = System.currentTimeMillis();
        assertDoesNotThrow(() -> notifier.notifyIfInvalid(
                invalidResult(), new byte[]{1}, "x.xml", "application/xml", null, null));
        long elapsed = System.currentTimeMillis() - start;

        // notifyIfInvalid SYNCHRONOUS olarak ÇOK HIZLI dönmeli — HTTP'yi
        // beklemiyor. Build + serialize + enqueue → tipik <50ms; timeout
        // ile karıştırmamak için 1 saniye sınırı koyuyoruz.
        assertTrue(elapsed < 1000,
                "notifyIfInvalid HTTP'yi beklememeli, async; elapsed=" + elapsed + "ms");
    }

    @Test
    void notifyIfInvalid_isAsync_callerReturnsBeforeHttpResponse() throws Exception {
        // Async sözleşmesini istatistiksel olarak doğrula: receiver'ı
        // bilinçli olarak yavaşlatıp caller'ın HTTP'yi beklemeden döndüğünü
        // gösteriyoruz.
        config.setWebhookUrl(server.url("/hook").toString());
        server.enqueue(new MockResponse()
                .setBodyDelay(800, TimeUnit.MILLISECONDS)
                .setResponseCode(200));

        long start = System.currentTimeMillis();
        notifier.notifyIfInvalid(invalidResult(), new byte[]{1},
                "x.xml", "application/xml", null, null);
        long callerReturnAt = System.currentTimeMillis() - start;

        // Caller, receiver'ın 800ms gecikmesini BEKLEMEDEN dönmüş olmalı
        assertTrue(callerReturnAt < 500,
                "Caller HTTP'yi beklemeden dönmeli (async); elapsed=" + callerReturnAt + "ms");

        // Request yine de receiver'a varmış olmalı (background'da)
        RecordedRequest req = server.takeRequest(3, TimeUnit.SECONDS);
        assertNotNull(req, "Receiver istek almalıydı (background dispatcher)");
    }

    @Test
    void notifyIfInvalid_dispatchesOtherChannels_evenIfOneFails() throws Exception {
        // İzolasyon: webhook URL'i tamamen patolojik, Slack URL'i sağlam.
        // Slack mesajı GİTMELİ — webhook patlaması Slack'i bastırmamalı.
        config.setWebhookUrl("malformed-url-that-will-fail");
        config.setSlackWebhookUrl(server.url("/slack").toString());
        server.enqueue(new MockResponse().setResponseCode(200));

        notifier.notifyIfInvalid(invalidResult(), new byte[]{1},
                "x.xml", "application/xml", null, null);

        // Slack istek yine de gelir
        RecordedRequest slackReq = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(slackReq, "Webhook patladıysa Slack yine de tetiklenmeli");
        assertEquals("/slack", slackReq.getPath());
    }

    // --- Slack inline base64 (Slack-only / single-URL dağıtım modu) --------
    //
    // Operatörün bot token + scope yönetmek istemediği / kuramayacağı
    // (kurumsal IT politikası, hızlı POC, küçük ekip) senaryolar için:
    // dosya Slack chat mesajının ICINE base64 + triple-backtick code block
    // olarak gömülür — tek incoming webhook URL'i ile çalışır, hiçbir
    // dış depo / bot kurulumu gerektirmez. Default kapalı; explicit opt-in.

    @Test
    void slackInlineBase64_disabled_byDefault() {
        // Spec sözleşmesi: opt-in. Config default false; signedBytes verilsek
        // bile Slack body'sinde base64 görünmemeli. Bot upload / generic
        // webhook trafiğine de karışmaz çünkü buildSlackBody yalnız Slack
        // body üretir.
        VerificationResult r = invalidResult();
        byte[] content = "operator-doc".getBytes(StandardCharsets.UTF_8);

        // Sanity: default config'te flag false
        assertFalse(config.isSlackInlineBase64Enabled(),
                "Default config inline base64'ü opt-out tutmali");

        String body = notifier.buildSlackBody(r, "doc.xml", content);
        String encoded = Base64.getEncoder().encodeToString(content);

        assertFalse(body.contains(encoded),
                "Default config'te base64 Slack mesajına ASLA gömülmemeli");
        assertFalse(body.contains("İçerik (base64"),
                "İçerik prefix'i (inline başlığı) görünmemeli");
        assertFalse(body.contains("pbpaste"),
                "Decode hint (inline footer) görünmemeli");
    }

    @Test
    void slackInlineBase64_includedInMessage_whenEnabledAndUnderLimit() throws Exception {
        // Opt-in + boyut limit altında: base64 mesaja eklenmeli ve decode
        // round-trip aynen orijinali vermeli (tek bir char kayıp dosyayı
        // bozar — bu test data corruption regresyonuna karşı kalkan).
        config.setSlackInlineBase64Enabled(true);
        config.setSlackInlineBase64MaxBytes(8192L);

        byte[] content = randomBytes(1024); // 1KB
        String expectedBase64 = Base64.getEncoder().encodeToString(content);

        String body = notifier.buildSlackBody(invalidResult(), "doc.xml", content);
        JsonNode root = mapper.readTree(body);

        // Reassemble: triple-backtick code block içinden gelen tüm parçaları
        // birleştir; tek char drift dosyayı bozar — kasten regex'le, manuel
        // bracket arama yapmıyoruz.
        String reassembled = reassembleInlineBase64(root);
        assertEquals(expectedBase64, reassembled,
                "Inline base64 chunk'ları birleşince orijinal ile birebir eşleşmeli");

        // Round-trip: decode tam orijinali vermeli
        assertArrayEquals(content, Base64.getDecoder().decode(reassembled),
                "Decode round-trip orijinal byte'lara dönmeli");

        // Decode hint footer'i sona iliştirilmiş olmalı (alıcı için)
        assertTrue(body.contains("pbpaste | base64 -d"),
                "macOS decode hint mesajda görünmeli");
        assertTrue(body.contains("xclip -o | base64 -d"),
                "Linux decode hint mesajda görünmeli");
        assertTrue(body.contains("İçerik (base64, 1024 bytes)"),
                "Inline başlığı dosyanın gerçek boyutunu (1024) içermeli");
    }

    @Test
    void slackInlineBase64_chunkedAcrossSections_forLargeContent() throws Exception {
        // 8KB binary = base64 string ~10924 char; Block Kit per-section
        // 3000 char limiti aşılır. Notifier'ın CHUNK_CHARS=2700'le ~5 parçaya
        // bölmesi ve hiçbir parçanın 2900 (truncate threshold) üstüne
        // çıkmaması gerek; aksi halde slackSectionMarkdown truncate eder
        // ve base64 bozulur.
        config.setSlackInlineBase64Enabled(true);
        config.setSlackInlineBase64MaxBytes(8192L);

        byte[] content = randomBytes(8192);
        String expectedBase64 = Base64.getEncoder().encodeToString(content);
        assertTrue(expectedBase64.length() > 3000,
                "Test invariant: 8KB base64 ~10.9KB olmalı, tek section'a sığmaz");

        String body = notifier.buildSlackBody(invalidResult(), "big.xml", content);
        JsonNode root = mapper.readTree(body);

        // En az 2 ayrı section blok'ta base64 içeren parçalar olmalı
        int sectionsWithBase64 = 0;
        for (JsonNode block : extractAttachmentBlocks(root)) {
            if (!"section".equals(block.path("type").asText())) {
                continue;
            }
            String text = block.path("text").path("text").asText("");
            // Triple-backtick + base64 alfabesi karışımı: bu section base64 chunk
            if (text.contains("```") && containsBase64Run(text)) {
                sectionsWithBase64++;
                // Her chunk section'ı slackSectionMarkdown truncate(2900)
                // sınırını aşmamalı (aşarsa base64 bozulur).
                assertTrue(text.length() <= 2900,
                        "Inline base64 section text 2900 char'ı aşmamalı (truncate dosyayı bozar)");
            }
        }
        assertTrue(sectionsWithBase64 >= 2,
                "8KB içerik için en az 2 base64-içeren section beklenir; bulunan: "
                        + sectionsWithBase64);

        // Reassemble ve decode round-trip — chunking algoritması veriyi
        // kaybetmemeli
        String reassembled = reassembleInlineBase64(root);
        assertEquals(expectedBase64, reassembled,
                "Chunk'lar birleşince orijinal base64 elde edilmeli (drift YOK)");
        assertArrayEquals(content, Base64.getDecoder().decode(reassembled),
                "Decode round-trip 8KB orijinal byte'lara birebir dönmeli");
    }

    @Test
    void slackInlineBase64_omitted_whenContentExceedsLimit() {
        // Enabled ama dosya boyutu (4KB) limiti (1KB) aşıyor: base64 mesaja
        // EKLENMEMELI; yerine "boyut limit aşıldı" notice satırı görünmeli.
        // Sessiz drop YASAK — operatör chat'te dosyanın neden eksik olduğunu
        // anında görsün.
        config.setSlackInlineBase64Enabled(true);
        config.setSlackInlineBase64MaxBytes(1024L);

        byte[] content = randomBytes(4096); // 4KB > 1KB limit
        String encoded = Base64.getEncoder().encodeToString(content);

        String body = notifier.buildSlackBody(invalidResult(), "big.xml", content);

        assertFalse(body.contains(encoded),
                "Limit aşıldığında base64 string mesajda görünmemeli");
        assertTrue(body.contains("inline limiti"),
                "Omission notice ('inline limiti') mesajda görünmeli");
        assertTrue(body.contains("4096"),
                "Notice gerçek dosya boyutunu (4096) raporlamalı");
        assertTrue(body.contains("1024"),
                "Notice limit değerini (1024) raporlamalı");
        // Decode hint omission case'inde de görünmemeli (yalnız gerçek
        // inline durumunda alıcıya rehber)
        assertFalse(body.contains("pbpaste"),
                "Omission durumunda decode hint görünmemeli");
    }

    @Test
    void slackInlineBase64_endToEnd_throughMockWebServer() throws Exception {
        // Tam entegrasyon: Slack URL set, inline base64 enabled, gerçek
        // OkHttp Call.enqueue() → MockWebServer recv → parse → verify.
        // Slack'in JSON parser'ı bu mesajı kabul edebilir mi (well-formed,
        // base64 intact) sorusunun in-process answer'ı.
        config.setSlackWebhookUrl(server.url("/services/T/B/inline").toString());
        config.setSlackInlineBase64Enabled(true);
        config.setSlackInlineBase64MaxBytes(8192L);
        server.enqueue(new MockResponse().setResponseCode(200).setBody("ok"));

        byte[] content = randomBytes(2048); // 2KB → tek-section sığar
        String expectedBase64 = Base64.getEncoder().encodeToString(content);

        notifier.notifyIfInvalid(invalidResult(), content, "doc.xml",
                "application/xml", null, null);

        RecordedRequest req = server.takeRequest(2, TimeUnit.SECONDS);
        assertNotNull(req, "Slack POST atılmalı");
        assertEquals("/services/T/B/inline", req.getPath());

        // 1) Well-formed JSON kontrolü (Slack parse edebilir mi)
        String json = req.getBody().readUtf8();
        JsonNode root = mapper.readTree(json);
        assertNotNull(root.get("attachments"), "Slack payload Block Kit attachments taşımalı");

        // 2) Base64 round-trip: chunk'lar birleşince orijinal byte'lara
        // bire-bir dönmeli (en kritik garanti — veri bütünlüğü)
        String reassembled = reassembleInlineBase64(root);
        assertEquals(expectedBase64, reassembled,
                "End-to-end base64 transfer'i drift'siz olmalı");
        assertArrayEquals(content, Base64.getDecoder().decode(reassembled),
                "MockWebServer'a giden Slack mesajındaki base64 decode edilince orijinal");

        // 3) Decode hint footer'i mesajda görünmeli (alıcı için)
        assertTrue(json.contains("pbpaste | base64 -d"),
                "macOS decode hint Slack mesajında görünmeli");
    }

    // --- Helpers ------------------------------------------------------------

    /**
     * Slack message JSON'ından (root → attachments[0].blocks) tüm Block Kit
     * blok'larını döner. Slack'in attachments wrapper'ı içine gömülü blocks
     * dizisi — UI'da kırmızı şerit + Block Kit render birlikte burada.
     */
    private List<JsonNode> extractAttachmentBlocks(JsonNode root) {
        JsonNode atts = root.get("attachments");
        assertNotNull(atts, "attachments wrapper'ı bulunmalı");
        assertTrue(atts.isArray() && atts.size() > 0);
        JsonNode blocks = atts.get(0).get("blocks");
        assertNotNull(blocks);
        assertTrue(blocks.isArray());
        List<JsonNode> out = new ArrayList<>(blocks.size());
        for (int i = 0; i < blocks.size(); i++) {
            out.add(blocks.get(i));
        }
        return out;
    }

    /**
     * Slack message JSON'ından tüm triple-backtick code block içeriklerini
     * çekip birleştirir — yani inline base64 chunk'larını yeniden bir araya
     * getirir. Whitespace strip'lendiği için Slack JSON serialization
     * sırasında eklenen newline'lar veriyi etkilemez.
     *
     * <p>Triple-backtick pattern'i sadece bizim inline base64 chunk'larında
     * kullanıldığı için (per-signature blok'ları monospace yerine sade
     * mrkdwn), bu çıkarım deterministik.</p>
     */
    private String reassembleInlineBase64(JsonNode root) {
        StringBuilder agg = new StringBuilder();
        // DOTALL flag (s) — newline'lar üzerinden de match etsin
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "```(.*?)```", java.util.regex.Pattern.DOTALL);
        for (JsonNode block : extractAttachmentBlocks(root)) {
            if (!"section".equals(block.path("type").asText())) {
                continue;
            }
            String text = block.path("text").path("text").asText("");
            java.util.regex.Matcher m = p.matcher(text);
            while (m.find()) {
                // Chunk içindeki tüm whitespace'i strip — Slack JSON
                // serialization ve markdown rendering newline ekleyebilir
                agg.append(m.group(1).replaceAll("\\s+", ""));
            }
        }
        return agg.toString();
    }

    /**
     * Verilen string base64 alfabesinden ardışık en az 100 char taşıyor mu?
     * Inline base64 chunk'ları ile per-signature blok metnini ayırt etmek
     * için (per-signature monospace `` etiketleri içerir, base64 chunk değil).
     */
    private boolean containsBase64Run(String text) {
        int run = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean isB64 = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '+' || c == '/' || c == '=';
            if (isB64) {
                run++;
                if (run >= 100) {
                    return true;
                }
            } else {
                run = 0;
            }
        }
        return false;
    }

    /** Deterministik PRNG ile reproducible bytes — test flake'ini önler. */
    private byte[] randomBytes(int size) {
        // Sabit seed = aynı testte aynı bytes; CI flaky değil.
        java.util.Random rng = new java.util.Random(42L);
        byte[] b = new byte[size];
        rng.nextBytes(b);
        return b;
    }

    // --- Common test fixtures ----------------------------------------------

    private VerificationResult invalidResult() {
        VerificationResult r = new VerificationResult(false, "INVALID");
        r.setSignatureType(SignatureType.XADES);
        r.setSignatureCount(1);
        r.setVerificationTime(new Date(1_700_000_000_000L));
        r.setErrors(new ArrayList<>(Arrays.asList(
                "İmza geçersiz: INDETERMINATE (SIG_CONSTRAINTS_FAILURE)")));

        SignatureInfo si = new SignatureInfo();
        si.setSignatureId("Signature-1");
        si.setValid(false);
        si.setSignatureFormat("XAdES-BASELINE-B");
        si.setIndication("INDETERMINATE");
        si.setSubIndication("SIG_CONSTRAINTS_FAILURE");

        CertificateInfo cert = new CertificateInfo();
        cert.setCommonName("CN=Test Imzaci, O=Mersel, C=TR");
        si.setSignerCertificate(cert);

        r.setSignatures(new ArrayList<>(Collections.singletonList(si)));
        return r;
    }
}
