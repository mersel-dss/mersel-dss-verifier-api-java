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

    /**
     * <b>Türkiye-özel XAdES SignedProperties Type URI toleransı.</b>
     *
     * <p>Pratik problem: KamuSM / GİB ekosisteminde yaygın bir grup eski
     * imzalama aracı, XAdES Reference Type URI'sini standart dışı yazıyor:</p>
     * <pre>
     *   Yanlış (üreticide görülen):  http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties
     *   Standart (ETSI 101 903):     http://uri.etsi.org/01903#SignedProperties
     * </pre>
     *
     * <p>Eclipse DSS spec'e harfiyen uyduğu için bu imzaları
     * <code>BBB_SAV_ISQPMDOSPP</code> ("ne message-digest ne SignedProperties
     * mevcut") ile reddeder ve <code>INDETERMINATE / SIG_CONSTRAINTS_FAILURE</code>
     * döndürür. Oysa TÜBİTAK İmzager ve KamuSM doğrulama servisleri bu
     * imzaları geçerli kabul ediyor — kriptografik olarak imza ZATEN sağlam,
     * yalnızca <code>Type</code> attribute'unda yazım hatası var.</p>
     *
     * <p><b>Aktifken davranış</b>: Doğrulama sonrası inceleme sırasında
     * şu tüm koşullar aranır:</p>
     * <ol>
     *   <li>Indication = INDETERMINATE</li>
     *   <li>SubIndication = SIG_CONSTRAINTS_FAILURE</li>
     *   <li>DSS DiagnosticData'da
     *       <code>signatureWrapper.isSignatureIntact() == true</code> ve
     *       <code>isSignatureValid() == true</code></li>
     *   <li>BBB SAV'da yalnızca <code>BBB_SAV_ISQPMDOSPP</code> hatası var
     *       (başka SAV constraint'i FAIL etmemiş)</li>
     *   <li>Orijinal XML byte'larında SignedProperties referansının
     *       <code>Type</code> attribute'u <code>01903</code> + ".xsd" + "#SignedProperties"
     *       paterniyle eşleşiyor (yani <em>spesifik</em> üretici hatası)</li>
     * </ol>
     *
     * <p>Bu koşulların TÜMÜ sağlanmazsa imza yine geçersiz raporlanır.
     * Yani <i>jenerik</i> bir SIG_CONSTRAINTS_FAILURE toleransı değildir;
     * sadece bu spesifik Type URI yazım hatasını affeder.</p>
     *
     * <p>Default <b>açık</b>: Mersel DSS Verifier zaten Türkiye ekosistemine
     * özgü bir doğrulayıcı. Operatör eIDAS-QES paralelinde davranmak isterse
     * <code>verification.tr-legacy-xades-tolerance-enabled=false</code> ile
     * kapatabilir.</p>
     */
    @Value("${verification.tr-legacy-xades-tolerance-enabled:true}")
    private boolean trLegacyXadesToleranceEnabled;

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

    public boolean isTrLegacyXadesToleranceEnabled() {
        return trLegacyXadesToleranceEnabled;
    }

    public void setTrLegacyXadesToleranceEnabled(boolean trLegacyXadesToleranceEnabled) {
        this.trLegacyXadesToleranceEnabled = trLegacyXadesToleranceEnabled;
    }
}

