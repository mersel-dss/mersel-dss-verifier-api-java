package io.mersel.dss.verify.api.models;

import java.util.List;

/** Exact trust anchors supplied to this verification, not a claim that the signature is trusted. */
@com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL)
public final class TrustEvidence {
    private final String activeTrustId;
    private final String activatedAt;
    public String getActiveTrustId() { return activeTrustId; }
    public String getActivatedAt() { return activatedAt; }
    private final String mode;
    private final String snapshotSha256;
    private final List<Anchor> anchors;
    private final boolean onlineValidationEnabled;
    public TrustEvidence(String mode, String snapshotSha256, List<Anchor> anchors, boolean onlineValidationEnabled) {
        this(mode, snapshotSha256, anchors, onlineValidationEnabled, null, null);
    }
    public TrustEvidence(String mode, String snapshotSha256, List<Anchor> anchors, boolean onlineValidationEnabled,
                         String activeTrustId, String activatedAt) {
        this.activeTrustId = activeTrustId; this.activatedAt = activatedAt;
        this.mode = mode; this.snapshotSha256 = snapshotSha256;
        this.anchors = java.util.Collections.unmodifiableList(new java.util.ArrayList<>(anchors));
        this.onlineValidationEnabled = onlineValidationEnabled;
    }
    public String getMode() { return mode; }
    public String getSnapshotSha256() { return snapshotSha256; }
    public List<Anchor> getAnchors() { return anchors; }
    public int getCertificateCount() { return anchors.size(); }
    public boolean isOnlineValidationEnabled() { return onlineValidationEnabled; }
    public static final class Anchor {
        private final String sha256, subject, issuer, serialNumber;
        public Anchor(String sha256, String subject, String issuer, String serialNumber) {
            this.sha256 = sha256; this.subject = subject; this.issuer = issuer; this.serialNumber = serialNumber;
        }
        public String getSha256() { return sha256; }
        public String getSubject() { return subject; }
        public String getIssuer() { return issuer; }
        public String getSerialNumber() { return serialNumber; }
    }
}
