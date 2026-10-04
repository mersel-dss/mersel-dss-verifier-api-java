package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

/** Informational preservation guidance. Never changes the cryptographic validation decision. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class VerificationRecommendation {
    /** Informational preservation guidance. Never changes the cryptographic validation decision. */
    private String code;
    private String title;
    private String description;
    private String severity;


    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
}
