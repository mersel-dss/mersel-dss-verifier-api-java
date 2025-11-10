package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

/**
 * Doğrulama detayları modeli
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ValidationDetails {
    private boolean signatureIntact;
    private boolean certificateChainValid;
    private boolean certificateNotExpired;
    private boolean certificateNotRevoked;
    private boolean trustAnchorReached;
    private boolean timestampValid;
    private boolean cryptographicVerificationSuccessful;
    private boolean revocationCheckPerformed;
    private Map<String, String> additionalDetails;

    // Getters and Setters
    public boolean isSignatureIntact() {
        return signatureIntact;
    }

    public void setSignatureIntact(boolean signatureIntact) {
        this.signatureIntact = signatureIntact;
    }

    public boolean isCertificateChainValid() {
        return certificateChainValid;
    }

    public void setCertificateChainValid(boolean certificateChainValid) {
        this.certificateChainValid = certificateChainValid;
    }

    public boolean isCertificateNotExpired() {
        return certificateNotExpired;
    }

    public void setCertificateNotExpired(boolean certificateNotExpired) {
        this.certificateNotExpired = certificateNotExpired;
    }

    public boolean isCertificateNotRevoked() {
        return certificateNotRevoked;
    }

    public void setCertificateNotRevoked(boolean certificateNotRevoked) {
        this.certificateNotRevoked = certificateNotRevoked;
    }

    public boolean isTrustAnchorReached() {
        return trustAnchorReached;
    }

    public void setTrustAnchorReached(boolean trustAnchorReached) {
        this.trustAnchorReached = trustAnchorReached;
    }

    public boolean isTimestampValid() {
        return timestampValid;
    }

    public void setTimestampValid(boolean timestampValid) {
        this.timestampValid = timestampValid;
    }

    public Map<String, String> getAdditionalDetails() {
        return additionalDetails;
    }

    public void setAdditionalDetails(Map<String, String> additionalDetails) {
        this.additionalDetails = additionalDetails;
    }

    public boolean isCryptographicVerificationSuccessful() {
        return cryptographicVerificationSuccessful;
    }

    public void setCryptographicVerificationSuccessful(boolean cryptographicVerificationSuccessful) {
        this.cryptographicVerificationSuccessful = cryptographicVerificationSuccessful;
    }

    public boolean isRevocationCheckPerformed() {
        return revocationCheckPerformed;
    }

    public void setRevocationCheckPerformed(boolean revocationCheckPerformed) {
        this.revocationCheckPerformed = revocationCheckPerformed;
    }
}

