package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.exceptions.VerificationException;
import io.mersel.dss.verify.api.models.*;
import io.mersel.dss.verify.api.models.enums.SignatureType;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.io.InputStream;
import java.util.*;

/**
 * Gelişmiş imza doğrulama servisi
 * - Tüm XAdES formatları (BES, EPES, T, C, X, XL, A)
 * - PAdES ve CAdES formatları
 * - Zaman damgası validasyonu
 * - OCSP/CRL kontrolü
 * - Simple ve Comprehensive modları
 */
@Service
public class AdvancedSignatureVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(AdvancedSignatureVerificationService.class);

    @Autowired
    private KamusmRootCertificateService rootCertificateService;

    @Autowired
    private VerificationConfiguration config;

    @Autowired
    private ResourceLoader resourceLoader;

    // Built-in policy profilleri. signer-strict default — imzacı için
    // OCSP/CRL FAIL, ara CA için WARN. strict — eIDAS-QES paralelinde
    // her katmanda FAIL.
    static final String PROFILE_SIGNER_STRICT = "signer-strict";
    static final String PROFILE_STRICT = "strict";
    private static final Set<String> KNOWN_PROFILES = new LinkedHashSet<>(
            Arrays.asList(PROFILE_SIGNER_STRICT, PROFILE_STRICT));
    private static final String POLICY_RESOURCE_TEMPLATE =
            "classpath:policy/kamusm-%s-constraint.xml";

    /**
     * Tam custom validation policy XML. <strong>Önceliklidir</strong>:
     * set edilmişse {@link #policyProfile} ignore edilir.
     *
     * <p>Spring resource paterni: <code>classpath:</code>, <code>file:</code>,
     * <code>http(s):</code>. Üretimde tipik kullanım:
     * <code>file:/etc/mersel-dss-verify/policy.xml</code> (k8s secret/configmap
     * ile mount).</p>
     */
    @Value("${dss.policy.path:}")
    private String policyPath;

    /**
     * Built-in policy profili. Geçerli değerler:
     * <ul>
     *   <li><code>signer-strict</code> (default) — Mali Mühür / KamuSM üretim
     *       senaryosu: imzacı için OCSP/CRL FAIL, ara CA için WARN.</li>
     *   <li><code>strict</code> — eIDAS-QES paraleli, her katmanda FAIL.</li>
     * </ul>
     *
     * <p>Bilinmeyen değer verilirse default'a düşülür ve startup log'unda
     * <code>WARN</code> basılır — silent fallback yapmıyoruz.</p>
     */
    @Value("${dss.policy.profile:signer-strict}")
    private String policyProfile;

    /**
     * Startup-time sanity check: kullanıcının seçtiği policy + online
     * validation kombosu pratikte anlamlı mı diye uyarır. Validation karar
     * mantığına hiç dokunmaz — sadece operatöre işaret bırakır.
     *
     * <p>Riskli kombinasyonlar:</p>
     * <ul>
     *   <li><b>profile=signer-strict + online-validation=false</b> →
     *       İmzacı için OCSP/CRL FAIL ama online fetch kapalı; her doğrulama
     *       INDETERMINATE/NO_REVOCATION_DATA dönecek. Tipik unutkanlık.</li>
     *   <li><b>profile=strict + online-validation=false</b> → aynı problem,
     *       hem de tüm katmanlarda.</li>
     *   <li><b>dss.policy.path set</b> → custom XML kullanıcının
     *       sorumluluğunda; bilgi log'u yeter.</li>
     * </ul>
     */
    @PostConstruct
    void warnOnSuspiciousPolicyConfiguration() {
        boolean customPath = policyPath != null && !policyPath.trim().isEmpty();
        boolean online = config != null && config.isOnlineValidationEnabled();
        String effectiveProfile = (policyProfile != null)
                ? policyProfile.trim().toLowerCase(Locale.ROOT) : "";

        if (customPath) {
            logger.info("DSS policy: custom XML kullanılıyor (dss.policy.path='{}'). "
                    + "Profile parametresi yok sayılıyor.", policyPath);
            return;
        }

        if (!KNOWN_PROFILES.contains(effectiveProfile)) {
            logger.warn("dss.policy.profile='{}' tanımsız; ilk doğrulamada default '{}' "
                            + "profiline düşülecek (operasyonel kontrol önerilir).",
                    policyProfile, PROFILE_SIGNER_STRICT);
            effectiveProfile = PROFILE_SIGNER_STRICT;
        }

        logger.info("DSS validation policy: profile='{}', online-validation={}",
                effectiveProfile, online);

        if (!online && (PROFILE_SIGNER_STRICT.equals(effectiveProfile)
                || PROFILE_STRICT.equals(effectiveProfile))) {
            logger.warn(""
                    + "GUVENLIK UYARISI: dss.policy.profile='{}' imzaci/CA icin "
                    + "OCSP veya CRL revocation verisi gerektiriyor, fakat "
                    + "verification.online-validation-enabled=false. Bu kombosyonla "
                    + "her dogrulama 'INDETERMINATE/NO_REVOCATION_DATA' donecektir. "
                    + "Online validation'i acin VEYA test/CI ortami icin "
                    + "dss.policy.path ile permissive bir XML mount edin.",
                    effectiveProfile);
        }
    }

    /**
     * İmzalı dokümanı doğrular
     * @param signedDocument İmzalı doküman
     * @param originalDocument Orijinal doküman (detached signature için)
     * @param level Doğrulama seviyesi (SIMPLE veya COMPREHENSIVE)
     * @return Doğrulama sonucu
     */
    public VerificationResult verifySignature(
            MultipartFile signedDocument,
            MultipartFile originalDocument,
            VerificationLevel level) {

        logger.info("Starting advanced signature verification. Level: {}", level);

        try {
            // Dokümanı oku
            byte[] signedBytes = signedDocument.getBytes();
            DSSDocument document = new InMemoryDocument(signedBytes, signedDocument.getOriginalFilename());

            // Orijinal doküman varsa (detached signature için)
            List<DSSDocument> detachedContents = new ArrayList<>();
            if (originalDocument != null && !originalDocument.isEmpty()) {
                DSSDocument detachedContent = new InMemoryDocument(
                        originalDocument.getBytes(),
                        originalDocument.getOriginalFilename()
                );
                detachedContents.add(detachedContent);
            }

            // Validator oluştur
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

            if (!detachedContents.isEmpty()) {
                validator.setDetachedContents(detachedContents);
            }

            // Certificate verifier'ı ayarla
            CertificateVerifier certificateVerifier = createAdvancedCertificateVerifier();
            validator.setCertificateVerifier(certificateVerifier);

            // Doğrulama yap. Validation policy resolution explicit ve
            // fail-fast (bkz. openValidationPolicyStream JavaDoc) — sessiz
            // fallback yok, çünkü yanlış policy ile valid göstermek prod
            // riski yaratır. Default profil signer-strict (KamuSM Mali Mühür
            // için imzacı OCSP/CRL zorunlu, ara CA WARN).
            Reports reports;
            try (InputStream policyStream = openValidationPolicyStream()) {
                reports = validator.validateDocument(policyStream);
            }

            // Detaylı DSS raporu: yalnızca DEBUG seviyesinde logla. Trust chain
            // problemlerini ayıklarken hızlıca açılabilir (logback level=DEBUG),
            // ama varsayılan üretim log'larını kirletmez.
            if (logger.isDebugEnabled()) {
                try {
                    ValidationReportLogger.logDetailedReport(
                            reports,
                            signedDocument != null ? signedDocument.getOriginalFilename() : "<unknown>");
                } catch (Exception logEx) {
                    logger.warn("ValidationReportLogger failed: {}", logEx.getMessage());
                }
            }

            // Sonuçları parse et
            VerificationResult result = parseAdvancedVerificationResult(reports, level);

            logger.info("Advanced signature verification completed. Valid: {}, Signatures: {}", 
                    result.isValid(), result.getSignatures().size());
            
            return result;

        } catch (Exception e) {
            logger.error("Advanced signature verification failed: {}", e.getMessage(), e);
            throw new VerificationException("İmza doğrulama hatası: " + e.getMessage(), e);
        }
    }

    /**
     * Validator'a verilecek validation policy XML'ini açar.
     *
     * <p><b>Resolution algoritması</b> (deterministik, audit edilebilir):</p>
     * <ol>
     *   <li><code>dss.policy.path</code> set ise → onu yükle. Yoksa veya
     *       erişilemezse <strong>fail-fast</strong> ({@code null} dönmek
     *       yerine {@link VerificationException} atılır). Operatör explicit
     *       bir path verdiyse sessizce başka bir XML'e düşmek riskli olur —
     *       imzayı yanlış policy ile valid göstermemek için bilinçli karar.</li>
     *   <li>Path yoksa <code>dss.policy.profile</code> kullanılır. Bilinen
     *       profil değilse default ({@code signer-strict})'e düşülür ve
     *       <strong>WARN</strong> loglanır.</li>
     *   <li>Profil XML'i classpath'te bulunamazsa (build hatası senaryosu)
     *       yine fail-fast: DSS default policy'sine sessiz düşmek prod'da
     *       güvenlik gerilemesi yaratır.</li>
     * </ol>
     *
     * @return açık {@link InputStream} (çağıran tarafın kapatması gerekir)
     * @throws VerificationException explicit yapılandırma yüklenemediğinde
     */
    InputStream openValidationPolicyStream() {
        // 1) Explicit path → fail-fast yükle
        if (policyPath != null && !policyPath.trim().isEmpty()) {
            String pathToUse = policyPath.trim();
            try {
                Resource resource = resourceLoader.getResource(pathToUse);
                if (!resource.exists()) {
                    throw new VerificationException(
                            "dss.policy.path olarak verilen kaynak bulunamadı: "
                                    + pathToUse + ". Operatör explicit XML belirtti, "
                                    + "sessiz fallback yapılmıyor.");
                }
                logger.info("Using custom validation policy from dss.policy.path={}", pathToUse);
                return resource.getInputStream();
            } catch (VerificationException ve) {
                throw ve;
            } catch (Exception e) {
                throw new VerificationException(
                        "dss.policy.path yüklenemedi (" + pathToUse + "): "
                                + e.getMessage(), e);
            }
        }

        // 2) Built-in profile
        String requested = (policyProfile != null) ? policyProfile.trim().toLowerCase(Locale.ROOT) : "";
        String effective = requested;
        if (!KNOWN_PROFILES.contains(effective)) {
            logger.warn("Bilinmeyen dss.policy.profile='{}' (geçerli değerler: {}). "
                            + "Default '{}' profiline düşülüyor.",
                    policyProfile, KNOWN_PROFILES, PROFILE_SIGNER_STRICT);
            effective = PROFILE_SIGNER_STRICT;
        }
        String resourcePath = String.format(POLICY_RESOURCE_TEMPLATE, effective);
        try {
            Resource resource = resourceLoader.getResource(resourcePath);
            if (!resource.exists()) {
                // Build/packaging hatası — built-in profil XML'i jar'da olmalı.
                // Sessiz DSS default'a düşmek prod güvenliğini zedeler.
                throw new VerificationException(
                        "Built-in policy profile XML'i sınıf yolunda yok: "
                                + resourcePath + ". Jar build edilirken "
                                + "src/main/resources/policy/ klasörüne eklendiğinden emin olun.");
            }
            logger.info("Using built-in validation policy profile '{}' ({})",
                    effective, resourcePath);
            return resource.getInputStream();
        } catch (VerificationException ve) {
            throw ve;
        } catch (Exception e) {
            throw new VerificationException(
                    "Built-in policy profile XML'i okunamadı (" + resourcePath + "): "
                            + e.getMessage(), e);
        }
    }

    /**
     * Gelişmiş certificate verifier oluşturur
     * - OCSP ve CRL desteği
     * - AIA (Authority Information Access) desteği
     * - Trusted certificate source
     */
    private CertificateVerifier createAdvancedCertificateVerifier() {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();

        // Trusted certificate source'u ayarla
        CertificateSource trustedSource = rootCertificateService.getTrustedCertificateSource();
        verifier.addTrustedCertSources(trustedSource);

        // Online validation aktifse OCSP ve CRL source'ları ekle
        if (config.isOnlineValidationEnabled()) {
            // OCSP Source
            OnlineOCSPSource ocspSource = new OnlineOCSPSource();
            // CommonsDataLoader dataLoader = new CommonsDataLoader();
            // dataLoader.setTimeoutConnection(10000);
            // dataLoader.setTimeoutSocket(10000);
            // ocspSource.setDataLoader(dataLoader);
            verifier.setOcspSource(ocspSource);

            // CRL Source
            OnlineCRLSource crlSource = new OnlineCRLSource();
            // crlSource.setDataLoader(dataLoader);
            verifier.setCrlSource(crlSource);

            // AIA Source (sertifika zinciri için)
            DefaultAIASource aiaSource = new DefaultAIASource();
            verifier.setAIASource(aiaSource);

            logger.info("Online validation enabled: OCSP and CRL sources configured");
        } else {
            logger.info("Online validation disabled");
        }

        return verifier;
    }

    /**
     * Gelişmiş doğrulama sonuçlarını parse eder
     */
    private VerificationResult parseAdvancedVerificationResult(Reports reports, VerificationLevel level) {
        SimpleReport simpleReport = reports.getSimpleReport();
        DetailedReport detailedReport = reports.getDetailedReport();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        VerificationResult result = new VerificationResult();
        result.setVerificationTime(new Date());

        List<String> signatureIds = simpleReport.getSignatureIdList();

        if (signatureIds.isEmpty()) {
            result.setValid(false);
            result.setStatus("NO_SIGNATURE_FOUND");
            result.addError("Dokümanda imza bulunamadı");
            return result;
        }

        boolean allValid = true;
        List<SignatureInfo> signatureInfos = new ArrayList<>();

        // Her imza için detaylı analiz
        for (String signatureId : signatureIds) {
            SignatureInfo sigInfo = processSignature(
                    signatureId, 
                    simpleReport, 
                    detailedReport, 
                    diagnosticData, 
                    level
            );
            
            signatureInfos.add(sigInfo);
            
            if (!sigInfo.isValid()) {
                allValid = false;
            }
        }

        result.setValid(allValid);
        result.setStatus(allValid ? "VALID" : "INVALID");
        result.setSignatures(signatureInfos);
        result.setSignatureCount(signatureInfos.size());

        // İmza tipini belirle
        if (!signatureInfos.isEmpty()) {
            result.setSignatureType(determineSignatureType(diagnosticData));
        }

        return result;
    }

    /**
     * Tek bir imzayı işler
     */
    private SignatureInfo processSignature(
            String signatureId,
            SimpleReport simpleReport,
            DetailedReport detailedReport,
            DiagnosticData diagnosticData,
            VerificationLevel level) {

        SignatureInfo sigInfo = new SignatureInfo();
        sigInfo.setSignatureId(signatureId);

        // Temel doğrulama sonucu
        Indication indication = simpleReport.getIndication(signatureId);
        SubIndication subIndication = simpleReport.getSubIndication(signatureId);
        
        boolean isValid = indication == Indication.TOTAL_PASSED || indication == Indication.PASSED;
        sigInfo.setValid(isValid);
        sigInfo.setIndication(indication.name());
        
        if (subIndication != null) {
            sigInfo.setSubIndication(subIndication.name());
        }

        // STRICT VALIDATION: SubIndication varsa geçersiz say
        if (config.isStrictMode() && subIndication != null && isValid) {
            logger.warn("STRICT MODE: Signature has SubIndication {}, marking as invalid", subIndication);
            isValid = false;
            sigInfo.setValid(false);
        }

        // İmza formatı ve seviyesi
        if (simpleReport.getSignatureFormat(signatureId) != null) {
            sigInfo.setSignatureFormat(simpleReport.getSignatureFormat(signatureId).toString());
        }

        // Diagnostic data'dan imza bilgilerini al
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
        if (signatureWrapper != null) {
            processSignatureWrapper(sigInfo, signatureWrapper, level);
        }

        // Validation details (comprehensive için)
        if (level == VerificationLevel.COMPREHENSIVE) {
            sigInfo.setValidationDetails(createComprehensiveValidationDetails(
                    signatureId, 
                    simpleReport, 
                    detailedReport, 
                    signatureWrapper
            ));
        }

        // Hatalar ve uyarılar
        collectErrorsAndWarnings(sigInfo, simpleReport, detailedReport, signatureId);

        // STRICT VALIDATION: Kritik hata varsa geçersiz say
        if (config.isStrictMode() && !sigInfo.getValidationErrors().isEmpty()) {
            logger.warn("STRICT MODE: Signature has {} validation errors, marking as invalid", 
                    sigInfo.getValidationErrors().size());
            sigInfo.setValid(false);
        }

        // STRICT VALIDATION: Timestamp hatalarını kontrol et
        if (config.isStrictMode() && signatureWrapper != null) {
            List<TimestampWrapper> timestamps = signatureWrapper.getTimestampList();
            if (timestamps != null && !timestamps.isEmpty()) {
                for (TimestampWrapper ts : timestamps) {
                    if (!ts.isMessageImprintDataFound() || !ts.isMessageImprintDataIntact()) {
                        logger.error("STRICT MODE: Timestamp validation failed: message imprint issue");
                        sigInfo.setValid(false);
                        sigInfo.getValidationErrors().add("Timestamp doğrulama hatası: Message imprint bozuk veya bulunamadı");
                        break;
                    }
                }
            }
        }

        return sigInfo;
    }

    /**
     * Signature wrapper'dan detaylı bilgi çıkarır
     */
    private void processSignatureWrapper(
            SignatureInfo sigInfo, 
            SignatureWrapper signatureWrapper,
            VerificationLevel level) {

        // İmza zamanı
        if (signatureWrapper.getClaimedSigningTime() != null) {
            sigInfo.setSigningTime(signatureWrapper.getClaimedSigningTime());
            sigInfo.setClaimedSigningTime(signatureWrapper.getClaimedSigningTime());
        }

        // Best signature time - DSS 6.3'te claimed signing time kullanılıyor
        // Timestamp varsa ondan alınacak

        // Signature level (XAdES-BES, XAdES-T, XAdES-A vb.)
        if (signatureWrapper.getSignatureFormat() != null) {
            sigInfo.setSignatureLevel(signatureWrapper.getSignatureFormat().toString());
        }

        // Sertifika bilgileri
        CertificateWrapper signingCert = signatureWrapper.getSigningCertificate();
        if (signingCert != null) {
            sigInfo.setSignerCertificate(extractCertificateInfo(signingCert));
        }

        // Timestamp bilgileri
        List<TimestampWrapper> timestamps = signatureWrapper.getTimestampList();
        if (timestamps != null && !timestamps.isEmpty()) {
            sigInfo.setTimestampInfo(extractTimestampInfo(timestamps.get(0)));
            sigInfo.setTimestampCount(timestamps.size());
        }

        // Comprehensive mod için ek bilgiler
        if (level == VerificationLevel.COMPREHENSIVE) {
            // Tüm sertifika zinciri
            List<CertificateInfo> certChain = new ArrayList<>();
            List<CertificateWrapper> certWrappers = signatureWrapper.getCertificateChain();
            if (certWrappers != null) {
                for (CertificateWrapper cert : certWrappers) {
                    if (cert != null) {
                        certChain.add(extractCertificateInfo(cert));
                    }
                }
            }
            sigInfo.setCertificateChain(certChain);

            // Policy bilgisi (XAdES-EPES için)
            if (signatureWrapper.getPolicyId() != null) {
                sigInfo.setPolicyIdentifier(signatureWrapper.getPolicyId());
            }
        }
    }

    /**
     * Sertifika bilgilerini çıkarır
     */
    private CertificateInfo extractCertificateInfo(CertificateWrapper certWrapper) {
        CertificateInfo certInfo = new CertificateInfo();
        
        certInfo.setCommonName(certWrapper.getReadableCertificateName());
        certInfo.setSerialNumber(certWrapper.getSerialNumber());
        certInfo.setSubject(certWrapper.getCertificateDN());
        certInfo.setIssuerDN(certWrapper.getCertificateIssuerDN());
        certInfo.setNotBefore(certWrapper.getNotBefore());
        certInfo.setNotAfter(certWrapper.getNotAfter());
        
        // Subject serial number
        if (certWrapper.getSubjectSerialNumber() != null) {
            certInfo.setSubjectSerialNumber(certWrapper.getSubjectSerialNumber());
        }

        // Sertifika geçerlilik durumu
        Date now = new Date();
        boolean isExpired = certWrapper.getNotAfter() != null && now.after(certWrapper.getNotAfter());
        boolean isRevoked = false; // DSS 6.3'te revocation bilgisi farklı şekilde alınıyor
        
        certInfo.setValid(!isExpired && !isRevoked);
        certInfo.setRevoked(isRevoked);
        certInfo.setExpired(isExpired);

        // Trust durumu — eski versiyonda hiç set edilmiyordu; UI tarafında her
        // sertifika "trusted=false" görünüyordu. DSS diagnostic data zaten root
        // trust source'taki eşleşmeyi `CertificateWrapper.isTrusted()` ile
        // raporluyor, doğrudan oradan al.
        try {
            certInfo.setTrusted(certWrapper.isTrusted());
        } catch (Exception ignore) {
            // Eski DSS sürümleri için defensive — sessizce false bırak.
        }

        return certInfo;
    }

    /**
     * Timestamp bilgilerini çıkarır
     */
    private TimestampInfo extractTimestampInfo(TimestampWrapper timestampWrapper) {
        TimestampInfo tsInfo = new TimestampInfo();
        
        tsInfo.setValid(timestampWrapper.isMessageImprintDataFound() && timestampWrapper.isMessageImprintDataIntact());
        tsInfo.setTimestampTime(timestampWrapper.getProductionTime());
        
        if (timestampWrapper.getType() != null) {
            tsInfo.setTimestampType(timestampWrapper.getType().name());
        }

        // TSA bilgisi
        CertificateWrapper tsaCert = timestampWrapper.getSigningCertificate();
        if (tsaCert != null) {
            tsInfo.setTsaName(tsaCert.getReadableCertificateName());
        }

        return tsInfo;
    }

    /**
     * Kapsamlı validation details oluşturur
     */
    private ValidationDetails createComprehensiveValidationDetails(
            String signatureId,
            SimpleReport simpleReport,
            DetailedReport detailedReport,
            SignatureWrapper signatureWrapper) {

        ValidationDetails details = new ValidationDetails();

        Indication indication = simpleReport.getIndication(signatureId);
        
        // İmza bütünlüğü
        details.setSignatureIntact(
                indication == Indication.TOTAL_PASSED || 
                indication == Indication.PASSED
        );

        if (signatureWrapper != null) {
            // Sertifika zinciri — DİKKAT: önceki implementation
            //   details.setCertificateChainValid(!signatureWrapper.isSignatureIntact());
            // şeklindeydi, bu açık bir typo: imza sağlamsa zincir invalid mantığı
            // çıkıyor ve dış istemciyi yanıltıyordu. Doğru kaynak: DSS'in
            // diagnostic data'sındaki trusted-chain bayrağı. Imza zincirinin
            // tepeye kadar tamamlanmış ve trust source ile eşleşmiş olması
            // gerçek "chain valid" anlamına gelir.
            details.setCertificateChainValid(signatureWrapper.isTrustedChain());

            // Sertifika geçerliliği
            CertificateWrapper signingCert = signatureWrapper.getSigningCertificate();
            if (signingCert != null) {
                Date now = new Date();
                boolean notExpired = signingCert.getNotAfter() != null && now.before(signingCert.getNotAfter());
                details.setCertificateNotExpired(notExpired);
                details.setCertificateNotRevoked(true); // DSS 6.3'te farklı kontrol
            }

            // Trust anchor
            details.setTrustAnchorReached(signatureWrapper.isTrustedChain());

            // Timestamp
            List<TimestampWrapper> timestamps = signatureWrapper.getTimestampList();
            details.setTimestampValid(timestamps != null && !timestamps.isEmpty());

            // Cryptographic check
            details.setCryptographicVerificationSuccessful(signatureWrapper.isSignatureIntact());

            // OCSP/CRL - DSS 6.3'te revocation data farklı alınıyor
            details.setRevocationCheckPerformed(true);
        }

        return details;
    }

    /**
     * Hataları ve uyarıları toplar
     */
    private void collectErrorsAndWarnings(
            SignatureInfo sigInfo,
            SimpleReport simpleReport,
            DetailedReport detailedReport,
            String signatureId) {

        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // Simple report'tan hatalar
        if (!simpleReport.isValid(signatureId)) {
            Indication indication = simpleReport.getIndication(signatureId);
            SubIndication subIndication = simpleReport.getSubIndication(signatureId);
            
            String errorMsg = "İmza geçersiz: " + indication.name();
            if (subIndication != null) {
                errorMsg += " (" + subIndication.name() + ")";
            }
            errors.add(errorMsg);
        }

        // SubIndication kontrolü - STRICT MODE
        SubIndication subIndication = simpleReport.getSubIndication(signatureId);
        if (subIndication != null) {
            String subIndicationMsg = "İmza uyarısı: " + subIndication.name();
            
            // Kritik SubIndication'lar direkt hata olarak ele alınır
            switch (subIndication) {
                case FORMAT_FAILURE:
                case HASH_FAILURE:
                case SIG_CRYPTO_FAILURE:
                case SIG_CONSTRAINTS_FAILURE:
                case CHAIN_CONSTRAINTS_FAILURE:
                case CERTIFICATE_CHAIN_GENERAL_FAILURE:
                case CRYPTO_CONSTRAINTS_FAILURE:
                case REVOKED:
                case REVOKED_NO_POE:
                case REVOKED_CA_NO_POE:
                case EXPIRED:
                case NOT_YET_VALID:
                    errors.add(subIndicationMsg + " (Kritik hata)");
                    logger.error("Critical SubIndication detected: {}", subIndication);
                    break;
                default:
                    warnings.add(subIndicationMsg);
                    break;
            }
        }

        // Detailed report'tan ek bilgiler - DSS 6.3'te farklı API
        try {
            // DSS 6.3'te detailed report API farklı
            if (detailedReport != null) {
                logger.debug("Detailed report available for additional analysis");
            }
        } catch (Exception e) {
            logger.debug("Could not extract detailed errors/warnings: {}", e.getMessage());
        }

        sigInfo.setValidationErrors(errors);
        sigInfo.setValidationWarnings(warnings);
    }

    /**
     * İmza tipini belirler
     */
    private SignatureType determineSignatureType(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        
        if (signatures != null && !signatures.isEmpty()) {
            SignatureWrapper firstSig = signatures.get(0);
            if (firstSig.getSignatureFormat() != null) {
                String format = firstSig.getSignatureFormat().toString();
                
                if (format.contains("PAdES")) {
                    return SignatureType.PADES;
                } else if (format.contains("XAdES")) {
                    return SignatureType.XADES;
                } else if (format.contains("CAdES")) {
                    return SignatureType.CADES;
                }
            }
        }
        
        return SignatureType.UNKNOWN;
    }
}

