package io.mersel.dss.verify.api.exceptions;

import org.springframework.http.HttpStatus;

/**
 * Etkin doğrulama politikası uç noktasının (/api/v1/policy/active) reddettiği istekler.
 * {@code error} alanı {@link io.mersel.dss.verify.api.models.ErrorResponse#getError()} değeridir.
 */
public class PolicyActivationException extends RuntimeException {
    public static final String INVALID_POLICY = "INVALID_POLICY";
    public static final String ACTIVATION_DISABLED = "POLICY_ACTIVATION_DISABLED";
    public static final String CONFLICT = "CONFLICT";
    public static final String UNAVAILABLE = "POLICY_UNAVAILABLE";

    private final HttpStatus status;
    private final String error;
    private final String details;
    /** Yalnız {@link #UNAVAILABLE}: hatanın oluştuğu andaki güncel revizyon (kurtarma için expectedPolicyId). */
    private final String policyId;
    /** Yalnız {@link #UNAVAILABLE}: bu sunucuda POST /api/v1/policy/active açık mı? */
    private final Boolean activationEnabled;

    private PolicyActivationException(HttpStatus status, String error, String message, String details) {
        this(status, error, message, details, null, null);
    }

    private PolicyActivationException(HttpStatus status, String error, String message, String details,
            String policyId, Boolean activationEnabled) {
        super(message);
        this.status = status; this.error = error; this.details = details;
        this.policyId = policyId; this.activationEnabled = activationEnabled;
    }

    public static PolicyActivationException invalid(String message) {
        return new PolicyActivationException(HttpStatus.BAD_REQUEST, INVALID_POLICY, message,
                "Politika etkinleştirilmedi; sunucudaki etkin politika değişmedi");
    }
    public static PolicyActivationException disabled() {
        return new PolicyActivationException(HttpStatus.FORBIDDEN, ACTIVATION_DISABLED,
                "Politikanın arayüzden etkinleştirilmesi bu sunucuda kapalı. Yalnız TÜBİTAK Uyum Değerlendirme "
                        + "sürecindeki deployment'lar için geliştirilmiştir ve POLICY_ACTIVATION_ENABLED=true ile "
                        + "açılır; prod ortamında kesinlikle kullanmayın.",
                "dss.policy.activation-enabled=false");
    }
    public static PolicyActivationException conflict() {
        return new PolicyActivationException(HttpStatus.CONFLICT, CONFLICT,
                "Etkin politika değişti veya backend yeniden başladı. Etkin politikayı yenileyip tekrar deneyin.",
                "expectedPolicyId güncel policyId ile eşleşmiyor");
    }

    /**
     * Yapılandırmadaki politika ({@code dss.policy.path}) yüklenemedi. Yapılandırma yolu yanıta yazılmaz.
     *
     * @param policyId           güncel revizyon; istemci bunu {@code expectedPolicyId} olarak gönderip
     *                           BUILT_IN / CUSTOM_XML / CONFIGURED ile kurtarabilir
     * @param activationEnabled  POST /api/v1/policy/active açık mı
     * @param verificationsFail  {@code true}: henüz hiçbir politika etkin değil, imza doğrulamaları fail-fast;
     *                           {@code false}: (CONFIGURED geri dönüşü) önceki etkin politika korunuyor
     */
    public static PolicyActivationException unavailable(String policyId, boolean activationEnabled,
            boolean verificationsFail) {
        String message = "Sunucu yapılandırmasındaki doğrulama politikası (dss.policy.path) yüklenemedi; ";
        if (!verificationsFail) {
            message += "etkin politika değişmedi.";
        } else if (activationEnabled) {
            message += "yapılandırma düzeltilene veya başka bir politika etkinleştirilene kadar imza doğrulamaları "
                    + "başarısız olur.";
        } else {
            message += "yapılandırma düzeltilene kadar imza doğrulamaları başarısız olur.";
        }
        return new PolicyActivationException(HttpStatus.SERVICE_UNAVAILABLE, UNAVAILABLE, message,
                "Ayrıntı sunucu loglarında", policyId, activationEnabled);
    }

    public HttpStatus getStatus() { return status; }
    public String getError() { return error; }
    public String getDetails() { return details; }
    public String getPolicyId() { return policyId; }
    public Boolean getActivationEnabled() { return activationEnabled; }
}
