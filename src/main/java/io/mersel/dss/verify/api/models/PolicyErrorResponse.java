package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * {@code 503 POLICY_UNAVAILABLE} yanıtı: ortak {@link ErrorResponse} alanlarına ek olarak güncel
 * {@code policyId} (kurtarma POST'unun {@code expectedPolicyId}'si) ve {@code activationEnabled}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"error", "message", "details", "policyId", "activationEnabled", "timestamp", "path"})
public class PolicyErrorResponse extends ErrorResponse {
    private final String policyId;
    private final Boolean activationEnabled;

    public PolicyErrorResponse(String error, String message, String details, String policyId,
            Boolean activationEnabled) {
        super(error, message, details);
        this.policyId = policyId;
        this.activationEnabled = activationEnabled;
    }

    public String getPolicyId() { return policyId; }
    public Boolean getActivationEnabled() { return activationEnabled; }
}
