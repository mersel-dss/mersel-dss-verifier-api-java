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

    // NOT: Eski `VERIFICATION_POLICY=STRICT|RELAXED` property kaldırıldı.
    // Hiçbir karar akışında okunmuyor, sessiz no-op olarak operatörleri
    // yanıltıyordu. DSS validation davranışı artık `dss.policy.profile`
    // (signer-strict|strict) + `dss.policy.path` (custom XML override)
    // üzerinden yönetilir (bkz. AdvancedSignatureVerificationService).
    // Rapor seviyesi katılık için `verification.strict-mode` aşağıda kalır
    // — DSS DiagnosticData üzerinde subIndication/validationErrors gibi
    // sinyalleri "valid mi değil mi" kararına nasıl yansıttığımızı kontrol
    // eder; DSS policy XML'i ile ortogonal bir kavramdır.

    @Value("${CERT_CACHE_TTL:3600}")
    private int certCacheTtl;

    @Value("${CRL_CACHE_TTL:3600}")
    private int crlCacheTtl;

    @Value("${verification.strict-mode:true}")
    private boolean strictMode;

    /**
     * GİB / TÜBİTAK Mali Mühür DER-encoded ECDSA SignatureValue'sini
     * W3C XMLDSig raw r||s formatına dönüştüren preprocessor'ın aktif/pasif kontrolü.
     * Emergency kill-switch: <code>false</code> yapılırsa hiç bir XML dokümanına
     * dokunulmaz (DSS sıkı W3C davranışına geri döner).
     */
    @Value("${verification.ecdsa-der-preprocessor-enabled:true}")
    private boolean ecdsaDerPreprocessorEnabled;

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

    public boolean isEcdsaDerPreprocessorEnabled() {
        return ecdsaDerPreprocessorEnabled;
    }

    public void setEcdsaDerPreprocessorEnabled(boolean ecdsaDerPreprocessorEnabled) {
        this.ecdsaDerPreprocessorEnabled = ecdsaDerPreprocessorEnabled;
    }
}

