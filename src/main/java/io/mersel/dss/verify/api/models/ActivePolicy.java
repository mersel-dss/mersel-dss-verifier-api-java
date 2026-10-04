package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * GET/POST /api/v1/policy/active yanıtı: sunucudaki sonraki tüm imza doğrulamalarının
 * kullandığı doğrulama politikası.
 */
@JsonPropertyOrder({"policyId", "profile", "source", "origin", "name", "sha256", "activatedAt",
        "fallbackApplied", "activationEnabled"})
public class ActivePolicy extends PolicyContext {
    private final String origin;
    private final String activatedAt;
    private final boolean fallbackApplied;
    private final boolean activationEnabled;

    public ActivePolicy(PolicyContext policy, String origin, String activatedAt, boolean fallbackApplied,
            boolean activationEnabled) {
        super(policy.getPolicyId(), policy.getProfile(), policy.getSource(), policy.getName(), policy.getSha256());
        this.origin = origin; this.activatedAt = activatedAt;
        this.fallbackApplied = fallbackApplied; this.activationEnabled = activationEnabled;
    }

    /** {@code CONFIGURATION} (başlangıç yapılandırması) veya {@code API} (arayüzden etkinleştirildi). */
    public String getOrigin() { return origin; }
    /** ISO-8601 an. */
    public String getActivatedAt() { return activatedAt; }
    /** Bilinmeyen {@code dss.policy.profile} nedeniyle varsayılan profile düşüldü mü? */
    public boolean isFallbackApplied() { return fallbackApplied; }
    /** Bu sunucuda POST /api/v1/policy/active açık mı? */
    public boolean isActivationEnabled() { return activationEnabled; }
}
