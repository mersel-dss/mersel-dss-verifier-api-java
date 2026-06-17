package io.mersel.dss.verify.api.metrics;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Doğrulama servisinin tüm iş (business) metriklerinin <strong>tek
 * giriş noktası</strong>. HTTP/JVM/cache metrikleri Spring Boot
 * Actuator + Micrometer binder'ları tarafından otomatik üretilir; bu
 * sınıf onların <em>üzerine</em> domain'e özel görünürlük ekler:
 *
 * <ul>
 *   <li><b>İstek sonuçlanma süreleri</b> — uçtan uca + aşama bazlı
 *       (read → preprocess → build → dss_validate → parse → notify)
 *       Timer'lar (percentile histogram, application.properties'te
 *       açık). "Bir doğrulama neden yavaş?" sorusu aşama kıran ile
 *       cevaplanır.</li>
 *   <li><b>Sonuç dağılımı</b> — VALID / INVALID / ERROR + imza başına
 *       indication / sub_indication. "Neden FAIL?" sorusu kök neden
 *       etiketiyle cevaplanır.</li>
 *   <li><b>Bağımlılık sağlığı</b> — OCSP / CRL / AIA fetch süresi +
 *       sonucu, retry recovered/exhausted, KamuSM kök sertifika
 *       refresh durumu. "Sorun bizde mi, KamuSM'de mi?" sorusu burada
 *       ayrışır.</li>
 *   <li><b>Bildirim kanalları</b> — webhook / Slack dispatch
 *       attempt/success/failure.</li>
 * </ul>
 *
 * <h3>Güvenlik sözleşmesi</h3>
 * <p><strong>Hiçbir metrik kaydı doğrulama akışını bozmamalıdır.</strong>
 * {@link MeterRegistry} context'te yoksa ({@link ObjectProvider} null
 * döner — minimal test slice'ı veya Actuator devre dışı) tüm metotlar
 * sessiz no-op olur. Kayıt sırasında beklenmedik bir hata atılırsa
 * (örn. tag kardinalite koruması) yakalanır ve yutulur; çağıran akış
 * etkilenmez.</p>
 *
 * <p>Prometheus metric ailesi (Micrometer dot → Prometheus underscore):</p>
 * <pre>
 *   mdss_verification_duration_seconds{type,level,result}      (Timer)
 *   mdss_verification_stage_duration_seconds{stage,result}     (Timer)
 *   mdss_verification_errors_total{exception}                  (Counter)
 *   mdss_signature_results_total{type,indication,sub_indication}(Counter)
 *   mdss_timestamp_duration_seconds{result}                    (Timer)
 *   mdss_revocation_fetch_duration_seconds{type,outcome}       (Timer)
 *   mdss_revocation_retry_total{type,event}                    (Counter)
 *   mdss_aia_fetch_duration_seconds{outcome}                   (Timer)
 *   mdss_trusted_root_refresh_total{result}                    (Counter)
 *   mdss_trusted_root_certificates                             (Gauge)
 *   mdss_trusted_root_last_success_timestamp_seconds           (Gauge)
 *   mdss_notification_dispatch_total{channel,event}            (Counter)
 * </pre>
 */
@Component
public class VerificationMetrics {

    private static final Logger logger = LoggerFactory.getLogger(VerificationMetrics.class);

    // --- Metric isimleri (Micrometer dot-notation) ---
    static final String VERIFICATION_DURATION = "mdss.verification.duration";
    static final String VERIFICATION_STAGE_DURATION = "mdss.verification.stage.duration";
    static final String VERIFICATION_ERRORS = "mdss.verification.errors";
    static final String SIGNATURE_RESULTS = "mdss.signature.results";
    static final String TIMESTAMP_DURATION = "mdss.timestamp.duration";
    static final String REVOCATION_FETCH_DURATION = "mdss.revocation.fetch.duration";
    static final String REVOCATION_RETRY = "mdss.revocation.retry";
    static final String AIA_FETCH_DURATION = "mdss.aia.fetch.duration";
    static final String TRUSTED_ROOT_REFRESH = "mdss.trusted_root.refresh";
    static final String TRUSTED_ROOT_CERTIFICATES = "mdss.trusted_root.certificates";
    static final String TRUSTED_ROOT_LAST_SUCCESS = "mdss.trusted_root.last_success.timestamp";
    static final String NOTIFICATION_DISPATCH = "mdss.notification.dispatch";

    /** Tag değerleri null/boş geldiğinde kullanılan emniyet değeri (kardinalite ve PromQL netliği için). */
    static final String UNKNOWN = "unknown";
    static final String NONE = "none";

    private final MeterRegistry registry;

    /** Güven deposundaki aktif kök sertifika sayısı (gauge state holder). */
    private final AtomicLong trustedRootCount = new AtomicLong(0);

    /** Son başarılı kök sertifika refresh'inin epoch-saniye zamanı (gauge state holder). 0 = henüz yok. */
    private final AtomicLong trustedRootLastSuccessEpochSeconds = new AtomicLong(0);

    public VerificationMetrics(ObjectProvider<MeterRegistry> registryProvider) {
        this.registry = registryProvider != null ? registryProvider.getIfAvailable() : null;
        if (this.registry == null) {
            logger.info("VerificationMetrics: MeterRegistry yok; tüm iş metrikleri no-op "
                    + "(doğrulama akışı etkilenmez).");
            return;
        }
        // Gauge'ları bir kez, state holder'lara bağlı olarak kaydet.
        try {
            Gauge.builder(TRUSTED_ROOT_CERTIFICATES, trustedRootCount, AtomicLong::doubleValue)
                    .description("Güven deposundaki aktif KamuSM kök sertifika sayısı")
                    .register(registry);
            Gauge.builder(TRUSTED_ROOT_LAST_SUCCESS, trustedRootLastSuccessEpochSeconds, AtomicLong::doubleValue)
                    .baseUnit("seconds")
                    .description("Son başarılı kök sertifika refresh'inin Unix epoch saniyesi")
                    .register(registry);
        } catch (RuntimeException e) {
            logger.warn("VerificationMetrics: trusted-root gauge kaydı başarısız: {}", e.getMessage());
        }
    }

    // =====================================================================
    // İmza doğrulama
    // =====================================================================

    /**
     * Uçtan uca imza doğrulama süresini + sonucunu kaydeder.
     *
     * @param type      imza tipi (XAdES/PAdES/CAdES); null → unknown
     * @param level     doğrulama seviyesi (SIMPLE/COMPREHENSIVE); null → unknown
     * @param result    sonuç sınıfı: {@code valid} / {@code invalid} / {@code error}
     * @param durationNanos {@link System#nanoTime()} farkı
     */
    public void recordVerification(String type, String level, String result, long durationNanos) {
        if (registry == null) {
            return;
        }
        try {
            registry.timer(VERIFICATION_DURATION,
                    "type", safe(type), "level", safe(level), "result", safe(result))
                    .record(durationNanos, TimeUnit.NANOSECONDS);
        } catch (RuntimeException ignore) {
            // metrik akışı bozamaz
        }
    }

    /**
     * Tek bir doğrulama aşamasının süresini kaydeder — "zaman nerede
     * harcandı?" sorusunun cevabı. Tipik stage değerleri:
     * {@code read_input}, {@code preprocess}, {@code build_validator},
     * {@code dss_validate}, {@code parse_result}, {@code notify}.
     *
     * @param outcome aşama başarılıysa {@code ok}, exception attıysa {@code error}
     */
    public void recordStage(String stage, String outcome, long durationNanos) {
        if (registry == null) {
            return;
        }
        try {
            registry.timer(VERIFICATION_STAGE_DURATION,
                    "stage", safe(stage), "result", safe(outcome))
                    .record(durationNanos, TimeUnit.NANOSECONDS);
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    /**
     * Doğrulama akışı bir exception ile patladığında exception sınıf
     * adıyla sayaç artırır (parse hatası, IO hatası, vb. ayrışsın).
     */
    public void recordVerificationError(String exceptionSimpleName) {
        if (registry == null) {
            return;
        }
        try {
            registry.counter(VERIFICATION_ERRORS, "exception", safe(exceptionSimpleName)).increment();
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    /**
     * Tek bir imzanın DSS kararını (indication + sub_indication) kaydeder.
     * Kök neden dağılımı bu sayaçtan çıkar:
     * {@code sum by (sub_indication) (rate(mdss_signature_results_total{indication!="TOTAL_PASSED"}[10m]))}.
     */
    public void recordSignatureResult(String type, String indication, String subIndication) {
        if (registry == null) {
            return;
        }
        try {
            registry.counter(SIGNATURE_RESULTS,
                    "type", safe(type),
                    "indication", safe(indication),
                    "sub_indication", subIndication == null || subIndication.isEmpty() ? NONE : subIndication)
                    .increment();
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    // =====================================================================
    // Zaman damgası doğrulama
    // =====================================================================

    public void recordTimestamp(String result, long durationNanos) {
        if (registry == null) {
            return;
        }
        try {
            registry.timer(TIMESTAMP_DURATION, "result", safe(result))
                    .record(durationNanos, TimeUnit.NANOSECONDS);
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    // =====================================================================
    // Revocation (OCSP / CRL) — KamuSM bağımlılığı
    // =====================================================================

    /**
     * Gerçek bir revocation fetch'inin (cache-miss) süresi + sonucu.
     *
     * @param type    {@code ocsp} veya {@code crl}
     * @param outcome {@code success} (token döndü) / {@code empty} (responder
     *                token üretmedi) / {@code error} (HTTP/retry tükendi)
     */
    public void recordRevocationFetch(String type, String outcome, long durationNanos) {
        if (registry == null) {
            return;
        }
        try {
            registry.timer(REVOCATION_FETCH_DURATION, "type", safe(type), "outcome", safe(outcome))
                    .record(durationNanos, TimeUnit.NANOSECONDS);
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    /**
     * Revocation retry olayları.
     *
     * @param type  {@code ocsp} veya {@code crl}
     * @param event {@code retried} (bir retry tetiklendi) /
     *              {@code recovered} (retry sonrası başarı) /
     *              {@code exhausted} (tüm denemeler bitti, hata yükseliyor)
     */
    public void recordRevocationRetry(String type, String event) {
        if (registry == null) {
            return;
        }
        try {
            registry.counter(REVOCATION_RETRY, "type", safe(type), "event", safe(event)).increment();
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    // =====================================================================
    // AIA (ara CA fetch)
    // =====================================================================

    /**
     * @param outcome {@code success} / {@code empty} / {@code error}
     */
    public void recordAiaFetch(String outcome, long durationNanos) {
        if (registry == null) {
            return;
        }
        try {
            registry.timer(AIA_FETCH_DURATION, "outcome", safe(outcome))
                    .record(durationNanos, TimeUnit.NANOSECONDS);
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    // =====================================================================
    // Güvenilir kök sertifika (KamuSM XML depo) refresh
    // =====================================================================

    /**
     * Kök sertifika refresh sonucunu kaydeder; başarılıysa aktif sertifika
     * sayısı gauge'ını ve son-başarı zaman damgası gauge'ını günceller.
     *
     * @param success      refresh başarılı mı
     * @param certificateCount başarılıysa yüklenen sertifika sayısı (gauge'a yazılır; başarısızsa -1 geç)
     */
    public void recordTrustedRootRefresh(boolean success, int certificateCount) {
        if (registry == null) {
            return;
        }
        try {
            registry.counter(TRUSTED_ROOT_REFRESH, "result", success ? "success" : "failure").increment();
            if (success) {
                if (certificateCount >= 0) {
                    trustedRootCount.set(certificateCount);
                }
                trustedRootLastSuccessEpochSeconds.set(System.currentTimeMillis() / 1000L);
            }
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    // =====================================================================
    // INVALID imza bildirimi
    // =====================================================================

    /**
     * @param channel {@code webhook} / {@code slack} / {@code slack_file}
     * @param event   {@code attempt} / {@code success} / {@code failure}
     */
    public void recordNotification(String channel, String event) {
        if (registry == null) {
            return;
        }
        try {
            registry.counter(NOTIFICATION_DISPATCH, "channel", safe(channel), "event", safe(event)).increment();
        } catch (RuntimeException ignore) {
            // no-op
        }
    }

    private static String safe(String value) {
        return (value == null || value.isEmpty()) ? UNKNOWN : value;
    }
}
