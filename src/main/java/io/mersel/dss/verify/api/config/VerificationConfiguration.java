package io.mersel.dss.verify.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Dogrulama servisi konfigurasyonu
 */
@Configuration
public class VerificationConfiguration {

    @Value("${verification.certstore.path:}")
    private String certStorePath;

    @Value("${verification.certstore.password:}")
    private String certStorePassword;

    @Value("${verification.custom-root-cert-path:}")
    private String customRootCertPath;

    @Value("${verification.online-validation-enabled:true}")
    private boolean onlineValidationEnabled;

    @Value("${verification.trusted-tsa-certificates:}")
    private String trustedTsaCertificates;

    @Value("${VERIFICATION_POLICY:STRICT}")
    private String verificationPolicy;

    @Value("${CERT_CACHE_TTL:3600}")
    private int certCacheTtl;

    @Value("${CRL_CACHE_TTL:3600}")
    private int crlCacheTtl;

    @Value("${verification.strict-mode:true}")
    private boolean strictMode;

    public String getCertStorePath() {
        return certStorePath;
    }

    public String getCertStorePassword() {
        return certStorePassword;
    }

    public String getCustomRootCertPath() {
        return customRootCertPath;
    }

    public boolean isOnlineValidationEnabled() {
        return onlineValidationEnabled;
    }

    public String getTrustedTsaCertificates() {
        return trustedTsaCertificates;
    }

    public String getVerificationPolicy() {
        return verificationPolicy;
    }

    public int getCertCacheTtl() {
        return certCacheTtl;
    }

    public int getCrlCacheTtl() {
        return crlCacheTtl;
    }

    public boolean isStrictMode() {
        return strictMode;
    }

    public void setStrictMode(boolean strictMode) {
        this.strictMode = strictMode;
    }
}

