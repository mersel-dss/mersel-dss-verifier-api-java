package io.mersel.dss.verify.api.services.notification;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mersel.dss.verify.api.models.VerificationResult;

import java.util.Date;
import java.util.Map;

/**
 * INVALID imza tespit edildiğinde generic webhook receiver'a basılan JSON
 * payload'ı.
 *
 * <p><b>Tasarım kararları</b>:</p>
 * <ul>
 *   <li><code>result</code> — orijinal {@link VerificationResult} olduğu
 *       gibi gömülür. Receiver hatalar, signatureInfo, certificateChain,
 *       appliedRejections vb. tüm DSS verisini görür; ayrı bir kısaltılmış
 *       özet kontratı tutmuyoruz (DSS data'sının zenginliği = audit
 *       değeri).</li>
 *   <li><code>file</code> — doğrulanan dosyanın adı, boyutu, MIME ve
 *       isteğe bağlı SHA-256 hex. Hash her zaman vardır; base64 içerik
 *       opsiyonel (config + boyut sınırı).</li>
 *   <li><code>file.base64Content</code> — operatör forensik için doğrudan
 *       receiver tarafında orijinal byte'lara ulaşsın. Default açık,
 *       gizlilik baskınsa
 *       {@code notification.invalid-signature.include-content=false}
 *       ile kapatılabilir.</li>
 *   <li><code>notificationTime</code> — receiver'ın sunucu saatiyle
 *       sapma analizi yapabilmesi için ISO-8601 Date (Jackson default).</li>
 *   <li><code>source</code> — bildirimi üreten uygulama adı +
 *       <code>"invalid-signature"</code> sabit event tipi. Receiver
 *       gelecekte başka bildirim tiplerini de ayırt edebilsin diye event
 *       şemasının ilk alanı olarak konuluyor.</li>
 * </ul>
 *
 * <p><b>Şema kararlılığı</b>: alan adları kararlı API kontratıdır;
 * silinmez, yeniden adlandırılmaz. Yeni alanlar eklenebilir
 * (forward-compatible).</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InvalidSignatureWebhookPayload {

    /**
     * Olay türü. Sabit: <code>"invalid-signature"</code>. Receiver
     * gelecekte başka Mersel bildirim tipleri eklendiğinde (örn.
     * "trusted-root-refresh-failure") tek dispatcher kullanabilsin diye.
     */
    private String event;

    /**
     * Bildirim kaynağı — uygulama adı + versiyon (bilgi amaçlı).
     * Örn: <code>"mersel-dss-verify-api/0.3.1"</code>.
     */
    private String source;

    /**
     * Bildirim üretildiği an (server-time, ISO-8601). Receiver'ın saat
     * sapma analizi için.
     */
    private Date notificationTime;

    /**
     * Doğrulanan dokümana ait metadata + (opsiyonel) base64 içerik.
     * Detached imza durumunda ana dosya = imza dosyası; orijinal doküman
     * ayrı {@link #originalDocument} alanına yazılır.
     */
    private FileEnvelope file;

    /**
     * Detached imza için orijinal (signed) doküman. CAdES/PAdES için
     * her zaman null; XAdES detached varyantında set edilir.
     */
    private FileEnvelope originalDocument;

    /**
     * DSS doğrulama sonucu — olduğu gibi gömülür.
     */
    private VerificationResult result;

    /**
     * İsteğe {@code x-log-*} prefix'iyle gelen korelasyon/audit header'larının
     * {@code Map<headerName, value>} kopyası. Anahtarlar her zaman küçük
     * harf ({@code x-log-id}, {@code x-log-tenant}, …); değerler
     * {@link io.mersel.dss.verify.api.config.LogHeadersFilter} tarafından
     * sanitize edilmiş hâli (CR/LF temizliği + uzunluk kırpma).
     *
     * <p>Receiver bu alanı doğrulama olayını çağıran upstream akışla (örn.
     * API gateway istek ID, kullanıcı/tenant, trace ID) eşleştirmek için
     * kullanır. Hiç {@code x-log-*} header'ı yoksa alan {@code null}
     * (JSON'a da düşmez — {@link JsonInclude} sayesinde).</p>
     */
    private Map<String, String> logHeaders;

    public InvalidSignatureWebhookPayload() {}

    public String getEvent() {
        return event;
    }

    public void setEvent(String event) {
        this.event = event;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public Date getNotificationTime() {
        return notificationTime;
    }

    public void setNotificationTime(Date notificationTime) {
        this.notificationTime = notificationTime;
    }

    public FileEnvelope getFile() {
        return file;
    }

    public void setFile(FileEnvelope file) {
        this.file = file;
    }

    public FileEnvelope getOriginalDocument() {
        return originalDocument;
    }

    public void setOriginalDocument(FileEnvelope originalDocument) {
        this.originalDocument = originalDocument;
    }

    public VerificationResult getResult() {
        return result;
    }

    public void setResult(VerificationResult result) {
        this.result = result;
    }

    public Map<String, String> getLogHeaders() {
        return logHeaders;
    }

    public void setLogHeaders(Map<String, String> logHeaders) {
        this.logHeaders = logHeaders;
    }

    /**
     * Tek bir dosya (signed document veya detached original) için
     * metadata + base64 içerik zarfı.
     *
     * <p><code>base64Content</code> alanı boyut sınırını aşan dosyalarda
     * veya operatör {@code includeContent=false} yaptığında null gelir
     * ({@link JsonInclude} sayesinde JSON'a da düşmez). Bu durumda
     * {@code sha256Hex} alanı yine doludur — receiver dosyayı kendi
     * arşivinden eşleştirebilsin diye.</p>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class FileEnvelope {

        /** Dosya adı (multipart {@code originalFilename}). */
        private String name;

        /** Bayt cinsinden boyut. {@code base64Content} verilmese de set'tir. */
        private Long sizeBytes;

        /** MIME tipi (multipart {@code contentType}); bilinmezse null. */
        private String contentType;

        /** Tüm dosyanın SHA-256 hash'i (lowercase hex). Forensik korelasyon için. */
        private String sha256Hex;

        /**
         * Tüm dosyanın base64 encoding'i. Operatör
         * {@code includeContent=false} yaptıysa veya dosya
         * {@code maxContentSizeBytes}'ı aşıyorsa <code>null</code>.
         */
        private String base64Content;

        /**
         * {@code base64Content} alanı neden boş? — operatöre rehberlik
         * için kısa kod. Olası değerler: {@code "EXCLUDED_BY_CONFIG"},
         * {@code "EXCEEDED_MAX_SIZE"}. {@code base64Content} doluysa null.
         */
        private String contentOmittedReason;

        public FileEnvelope() {}

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Long getSizeBytes() {
            return sizeBytes;
        }

        public void setSizeBytes(Long sizeBytes) {
            this.sizeBytes = sizeBytes;
        }

        public String getContentType() {
            return contentType;
        }

        public void setContentType(String contentType) {
            this.contentType = contentType;
        }

        public String getSha256Hex() {
            return sha256Hex;
        }

        public void setSha256Hex(String sha256Hex) {
            this.sha256Hex = sha256Hex;
        }

        public String getBase64Content() {
            return base64Content;
        }

        public void setBase64Content(String base64Content) {
            this.base64Content = base64Content;
        }

        public String getContentOmittedReason() {
            return contentOmittedReason;
        }

        public void setContentOmittedReason(String contentOmittedReason) {
            this.contentOmittedReason = contentOmittedReason;
        }
    }
}
