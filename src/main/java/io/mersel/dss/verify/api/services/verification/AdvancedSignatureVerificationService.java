package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
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
import eu.europa.esig.dss.spi.x509.aia.AIASource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.exceptions.VerificationException;
import io.mersel.dss.verify.api.models.*;
import io.mersel.dss.verify.api.models.enums.SignaturePackaging;
import io.mersel.dss.verify.api.models.enums.SignatureType;
import io.mersel.dss.verify.api.models.enums.SuppressionCode;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import io.mersel.dss.verify.api.services.util.EcdsaXmlSignaturePreprocessor;
import io.mersel.dss.verify.api.services.util.LegacyTurkishXadesTypeUriDetector;
import io.mersel.dss.verify.api.services.util.RevocationInfoExtractor;
import io.mersel.dss.verify.api.services.util.XadesSignaturePackagingDetector;
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

    @Autowired
    private EcdsaXmlSignaturePreprocessor ecdsaXmlSignaturePreprocessor;

    @Autowired
    private LegacyTurkishXadesTypeUriDetector legacyTrXadesDetector;

    @Autowired
    private XadesSignaturePackagingDetector xadesPackagingDetector;

    @Autowired
    private RevocationInfoExtractor revocationInfoExtractor;

    /**
     * Cache + logging sarmalli OCSP source. Spring bean'i
     * {@link io.mersel.dss.verify.api.config.RevocationServicesConfiguration}
     * tarafindan kosullu olarak yaratilir; <code>verification.online-validation-enabled=false</code>
     * iken context'te bulunmaz. {@code required=false} ile inject ediyoruz ki
     * offline modda servis bootstrap'i bozulmasin.
     */
    @Autowired(required = false)
    private OCSPSource cachedOcspSource;

    /**
     * Cache + logging sarmalli CRL source. {@link #cachedOcspSource} ile ayni
     * yasam dongusu kurallari.
     */
    @Autowired(required = false)
    private CRLSource cachedCrlSource;

    /**
     * AIA source (Authority Information Access) — sertifika zinciri eksik
     * geldiginde ara CA fetch icin. Yine online validation ile gate'lenmis.
     */
    @Autowired(required = false)
    private AIASource cachedAiaSource;

    /**
     * Mesaj anahtarı: DSS BBB SAV içinde "ne message-digest ne SignedProperties
     * mevcut" hatasının resmi adı. KamuSM/GİB üreticisinin Type URI yazım
     * hatasında DSS yalnızca bu constraint'i FAIL eder; başka SAV check'i
     * patlıyorsa imza gerçekten kırıktır ve toleransı UYGULAMAYIZ.
     *
     * <p>Kaynak: dss-validation jar →
     * <code>BBB_SAV_ISQPMDOSPP</code>
     * (Information Signed Qualifying Properties Message-Digest Or Signed
     * Properties Present).</p>
     */
    static final String BBB_SAV_ISQPMDOSPP_KEY = "BBB_SAV_ISQPMDOSPP";

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

            // GİB/TÜBİTAK Mali Mühür ECDSA imzaları (DER-encoded) için W3C XMLDSig
            // uyumluluğunu sağla: SignatureValue içindeki ASN.1 DER SEQUENCE'i raw r||s'e çevir.
            // Preprocessor sertifika EC değilse veya gerekli koşullar sağlanmazsa no-op döner.
            if (config.isEcdsaDerPreprocessorEnabled()) {
                signedBytes = ecdsaXmlSignaturePreprocessor.preprocess(signedBytes);
            }

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

            // XAdES paketleme (ENVELOPED/ENVELOPING/DETACHED) tipini DSS
            // diagnostic'te bulamıyoruz — DSS bu bilgiyi yalnızca imza
            // ÜRETİRKEN parametre alıyor, verification'da raporlamıyor.
            // İmza başına AdvancedSignature.getSignatureElement() DOM'u
            // üzerinden hesaplayıp signatureId -> packaging map'i kuruyoruz.
            // CAdES/PAdES için map boş kalır; XAdES dışı imzalarda alan
            // JSON'a hiç düşmez (SignatureInfo NON_NULL).
            Map<String, SignaturePackaging> packagingBySignatureId = computeXadesPackaging(validator);

            // Sonuçları parse et. Orijinal XML byte'larını da geçiyoruz: TR-özel
            // legacy XAdES Type URI tespitinde detector imzanın gerçekten "yanlış
            // yazılmış Type URI'li ama kriptografik olarak sağlam" olduğunu DSS
            // diagnostic'ten ayrı bir kanıtla doğrulayabilsin diye.
            VerificationResult result = parseAdvancedVerificationResult(
                    reports, level, signedBytes, packagingBySignatureId);

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
     * Gelişmiş certificate verifier oluşturur.
     *
     * <p>Revocation source'lari (OCSP/CRL/AIA) Spring tarafindan
     * {@link io.mersel.dss.verify.api.config.RevocationServicesConfiguration}
     * uzerinden saglanir; bu sayede:</p>
     * <ul>
     *   <li>Caffeine cache uygulamanin yasam dongusunce paylasilir
     *       (her doğrulamada sifirlanmaz),</li>
     *   <li>HTTP timeout'lari merkezi olarak konfigure edilir,</li>
     *   <li>OCSP/CRL HTTP istegi atildigi anda INFO seviyesinde
     *       audit log dusulur.</li>
     * </ul>
     *
     * <p><strong>Online validation devre disi</strong> ({@code verification.online-validation-enabled=false})
     * iken bean'ler context'te yoktur; verifier sadece kriptografik butunluk
     * ve trusted chain kontrolu yapar — revocation tabakasi devre disi.</p>
     */
    private CertificateVerifier createAdvancedCertificateVerifier() {
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();

        CertificateSource trustedSource = rootCertificateService.getTrustedCertificateSource();
        verifier.addTrustedCertSources(trustedSource);

        if (config.isOnlineValidationEnabled()) {
            if (cachedOcspSource != null) {
                verifier.setOcspSource(cachedOcspSource);
            } else {
                logger.warn("verification.online-validation-enabled=true fakat OCSPSource bean'i bulunamadi; "
                        + "OCSP kontrolu yapilamayacak");
            }
            if (cachedCrlSource != null) {
                verifier.setCrlSource(cachedCrlSource);
            } else {
                logger.warn("verification.online-validation-enabled=true fakat CRLSource bean'i bulunamadi; "
                        + "CRL kontrolu yapilamayacak");
            }
            if (cachedAiaSource != null) {
                verifier.setAIASource(cachedAiaSource);
            } else {
                logger.warn("verification.online-validation-enabled=true fakat AIASource bean'i bulunamadi; "
                        + "AIA chain fetch yapilamayacak");
            }
            logger.debug("CertificateVerifier built with online revocation sources (cache + logging)");
        } else {
            logger.info("Online validation disabled — OCSP/CRL/AIA source'lari verifier'a baglanmiyor "
                    + "(yalniz kriptografik butunluk ve trusted chain kontrolu yapilacak)");
        }

        return verifier;
    }

    /**
     * Her XAdES imzası için paketleme tipini (ENVELOPED / ENVELOPING /
     * DETACHED) {@code signatureId -> packaging} map'i olarak hesaplar.
     *
     * <p>DSS bu bilgiyi verification akışında hiçbir reports/diagnostic
     * alanında expose etmiyor; tek yol {@code SignedDocumentValidator}'dan
     * {@link AdvancedSignature} listesini alıp DOM seviyesinde
     * {@code ds:SignedInfo/ds:Reference} yapısını okumak.</p>
     *
     * <p>CAdES/PAdES imzaları için detector {@code null} döner — bu sayede
     * map'e hiç girmezler ve {@code SignatureInfo.signaturePackaging} alanı
     * onlar için JSON'da görünmez ({@code NON_NULL}).</p>
     *
     * @param validator çalıştırılmış (validateDocument sonrası) DSS validator
     * @return signatureId -> {@link SignaturePackaging} map'i; başarısızlık
     *         durumunda boş map (doğrulama akışını bozmaz)
     */
    private Map<String, SignaturePackaging> computeXadesPackaging(SignedDocumentValidator validator) {
        Map<String, SignaturePackaging> result = new HashMap<>();
        try {
            List<AdvancedSignature> sigs = validator.getSignatures();
            if (sigs == null || sigs.isEmpty()) {
                return result;
            }
            for (AdvancedSignature sig : sigs) {
                SignaturePackaging packaging = xadesPackagingDetector.detect(sig);
                if (packaging != null) {
                    result.put(sig.getId(), packaging);
                }
            }
        } catch (Exception e) {
            // Paketleme tespiti best-effort'tür; başarısızlık doğrulamayı
            // bloklamamalı. WARN ile not düşüp boş map dönüyoruz.
            logger.warn("XAdES packaging detection failed: {}", e.getMessage());
        }
        return result;
    }

    /**
     * Gelişmiş doğrulama sonuçlarını parse eder
     */
    private VerificationResult parseAdvancedVerificationResult(
            Reports reports,
            VerificationLevel level,
            byte[] originalXmlBytes,
            Map<String, SignaturePackaging> packagingBySignatureId) {
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
                    level,
                    originalXmlBytes,
                    packagingBySignatureId
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
            VerificationLevel level,
            byte[] originalXmlBytes,
            Map<String, SignaturePackaging> packagingBySignatureId) {

        SignatureInfo sigInfo = new SignatureInfo();
        sigInfo.setSignatureId(signatureId);

        // XAdES paketleme tipini (ENVELOPED/ENVELOPING/DETACHED) set et.
        // Map'te yoksa (XAdES değilse veya DOM tespiti başarısızsa) null kalır
        // ve SignatureInfo @JsonInclude(NON_NULL) sayesinde JSON'a düşmez.
        if (packagingBySignatureId != null) {
            sigInfo.setSignaturePackaging(packagingBySignatureId.get(signatureId));
        }

        // Temel doğrulama sonucu
        Indication indication = simpleReport.getIndication(signatureId);
        SubIndication subIndication = simpleReport.getSubIndication(signatureId);

        // TR-özel tolerans değerlendirmesi: KamuSM/GİB üreticisi XAdES Type URI
        // yazım hatasını tespit edip override edebilir miyiz? Karar tek noktada
        // alınır; suppression objesi başarıysa null değildir ve audit kanalına
        // (sigInfo.appliedSuppressions) eklenir.
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
        AppliedSuppression trSuppression = evaluateTrLegacyXadesTolerance(
                signatureId, indication, subIndication, signatureWrapper,
                detailedReport, originalXmlBytes);
        boolean trToleranceApplied = trSuppression != null;

        if (trToleranceApplied) {
            // İmzayı PASSED'a yükselttik. SubIndication artık anlamsız —
            // istemciyi yanıltmamak için temizliyoruz. Audit kanıtı
            // appliedSuppressions altına yazılıyor.
            sigInfo.setAppliedSuppressions(
                    new ArrayList<>(java.util.Collections.singletonList(trSuppression)));
            indication = Indication.TOTAL_PASSED;
            subIndication = null;
        }

        boolean isValid = indication == Indication.TOTAL_PASSED || indication == Indication.PASSED;
        sigInfo.setValid(isValid);
        sigInfo.setIndication(indication.name());

        if (subIndication != null) {
            sigInfo.setSubIndication(subIndication.name());
        }

        // STRICT VALIDATION: SubIndication varsa geçersiz say. Tolerance
        // uygulandıysa subIndication==null olduğu için bu blok zaten skip'lenir.
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
        if (signatureWrapper != null) {
            processSignatureWrapper(sigInfo, signatureWrapper, level);
        }

        // Validation details (comprehensive için). Tolerance uygulandıysa
        // signatureIntact'i true'ya çekiyoruz — istemcinin "kriptografi sağlam"
        // bilgisiyle "doğrulama bütünüyle geçti" bilgisi tutarlı olsun.
        if (level == VerificationLevel.COMPREHENSIVE) {
            ValidationDetails details = createComprehensiveValidationDetails(
                    signatureId,
                    simpleReport,
                    detailedReport,
                    signatureWrapper
            );
            if (trToleranceApplied) {
                details.setSignatureIntact(true);
            }
            sigInfo.setValidationDetails(details);
        }

        // Hatalar ve uyarılar
        collectErrorsAndWarnings(sigInfo, simpleReport, detailedReport, signatureId,
                trToleranceApplied);

        // STRICT VALIDATION: Kritik hata varsa geçersiz say. Tolerance varken
        // collectErrorsAndWarnings hata yerine warning ekler, dolayısıyla bu
        // blok signal yaratmaz.
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
     * KamuSM / GİB üreticisinin XAdES <code>Reference Type</code> URI yazım
     * hatasını tespit edip imzanın geçerli sayılıp sayılamayacağını
     * değerlendirir.
     *
     * <p><b>Tolerans tüm şu koşullar sağlandığında devreye girer:</b></p>
     * <ol>
     *   <li>Operatör tolerance'ı kapatmamış
     *       (<code>verification.tr-legacy-xades-tolerance-enabled=true</code>).</li>
     *   <li>DSS indication = INDETERMINATE.</li>
     *   <li>DSS subIndication = SIG_CONSTRAINTS_FAILURE.</li>
     *   <li>DSS DiagnosticData'da imza kriptografik olarak sağlam:
     *       <code>signatureIntact && signatureValid</code>.</li>
     *   <li>BBB SAV içinde <em>tek</em> FAIL'lı constraint
     *       <code>BBB_SAV_ISQPMDOSPP</code> — başka SAV constraint'i de
     *       FAIL ediyorsa imza gerçekten kırıktır, ELLEMEYİZ.</li>
     *   <li>Orijinal XML byte'larında detector,
     *       <code>01903 .* XAdES.xsd .* #SignedProperties</code> paterniyle
     *       eşleşen Type URI buluyor.</li>
     * </ol>
     *
     * @return tolerans uygulanacaksa audit kanalına yazılacak
     *         {@link AppliedSuppression} objesi; aksi halde <code>null</code>
     *         (DSS kararı aynen kullanılmalı).
     */
    private AppliedSuppression evaluateTrLegacyXadesTolerance(
            String signatureId,
            Indication indication,
            SubIndication subIndication,
            SignatureWrapper signatureWrapper,
            DetailedReport detailedReport,
            byte[] originalXmlBytes) {

        if (!config.isTrLegacyXadesToleranceEnabled()) {
            return null;
        }
        if (indication != Indication.INDETERMINATE) {
            return null;
        }
        if (subIndication != SubIndication.SIG_CONSTRAINTS_FAILURE) {
            return null;
        }
        if (signatureWrapper == null) {
            return null;
        }
        if (!signatureWrapper.isSignatureIntact() || !signatureWrapper.isSignatureValid()) {
            return null;
        }
        if (!isOnlyBbbSavFailureMessageDigestOrSignedProperties(detailedReport, signatureId)) {
            return null;
        }
        if (originalXmlBytes == null || legacyTrXadesDetector == null) {
            return null;
        }
        String hit = legacyTrXadesDetector.detect(originalXmlBytes);
        if (hit == null) {
            return null;
        }
        logger.info("TR legacy XAdES toleransı uygulandı (signatureId={}, code={}). DSS "
                        + "INDETERMINATE/SIG_CONSTRAINTS_FAILURE iken imza kriptografik "
                        + "olarak sağlam ve tek hata BBB_SAV_ISQPMDOSPP. Üretici Type URI: '{}'",
                signatureId, SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getCode(), hit);

        SuppressionCode sc = SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI;
        java.util.Map<String, Object> evidence = new java.util.LinkedHashMap<>();
        evidence.put("detectedTypeUri", hit);
        evidence.put("expectedTypeUri", "http://uri.etsi.org/01903#SignedProperties");
        evidence.put("dssBbbConstraint", BBB_SAV_ISQPMDOSPP_KEY);

        return new AppliedSuppression(
                sc.getCode(),
                sc.getTitle(),
                sc.getDefaultReason() + " Üretici Type URI: \"" + hit + "\".",
                sc.getSeverity(),
                indication.name(),
                subIndication.name(),
                evidence,
                sc.getDocsUrl());
    }

    /**
     * BBB SAV blok içinde başka FAIL constraint'i olup olmadığını kontrol eder.
     * <code>BBB_SAV_ISQPMDOSPP</code> dışında bir FAIL varsa imzayı affetmek
     * tehlikelidir; örneğin <code>BBB_SAV_ISCDC</code> (cryptographic
     * constraint) FAIL ise zayıf algoritma demektir, override etmemeliyiz.
     *
     * <p>DSS DetailedReport JAXB modelini gezerek BBB içindeki SAV
     * constraint listesini inceler. JAXB API'ları reflection-friendly olduğu
     * için defansif try/catch ile sarıyoruz; herhangi bir aksilikte güvenli
     * tarafta kalıp <code>false</code> döneriz.</p>
     */
    private boolean isOnlyBbbSavFailureMessageDigestOrSignedProperties(
            DetailedReport detailedReport, String signatureId) {
        if (detailedReport == null) {
            return false;
        }
        try {
            for (XmlBasicBuildingBlocks bbb :
                    detailedReport.getJAXBModel().getBasicBuildingBlocks()) {
                if (!signatureId.equals(bbb.getId())) {
                    continue;
                }
                XmlSAV sav = bbb.getSAV();
                if (sav == null || sav.getConstraint() == null) {
                    return false;
                }
                boolean expectedFailureSeen = false;
                for (XmlConstraint c : sav.getConstraint()) {
                    if (c.getStatus() == null) {
                        continue;
                    }
                    if (c.getStatus() != XmlStatus.NOT_OK
                            && c.getStatus() != XmlStatus.WARNING) {
                        // OK / IGNORED / INFORMATION — hata değil, atla
                        continue;
                    }
                    if (c.getStatus() == XmlStatus.WARNING) {
                        // SAV warning'leri toleransı bozmaz
                        continue;
                    }
                    String key = c.getName() != null ? c.getName().getKey() : null;
                    if (BBB_SAV_ISQPMDOSPP_KEY.equals(key)) {
                        expectedFailureSeen = true;
                    } else {
                        // Başka bir SAV constraint FAIL — toleransı uygulamayız
                        logger.debug("TR XAdES toleransı uygulanmadı: BBB SAV ek "
                                + "FAIL constraint mevcut: key={}, status={}", key, c.getStatus());
                        return false;
                    }
                }
                return expectedFailureSeen;
            }
        } catch (Exception e) {
            logger.debug("TR XAdES toleransı: BBB SAV inspection hatası: {}", e.getMessage());
        }
        return false;
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

        // Sertifika zincirinin revocation durumu — SIMPLE/COMPREHENSIVE fark
        // etmeksizin hesaplanir. SIMPLE modda kullanici zincirin tam detayini
        // (certificateChain[]) gormez, ancak bu kompakt enum sayesinde
        // "leaf GOOD ama bir CA REVOKED" gibi durumlari tek bakista anlar.
        // Detay icin COMPREHENSIVE'a gecmesi gerekir.
        List<CertificateWrapper> chainForStatus = signatureWrapper.getCertificateChain();
        sigInfo.setChainRevocationStatus(revocationInfoExtractor.computeChainStatus(chainForStatus));

        // Comprehensive mod için ek bilgiler
        if (level == VerificationLevel.COMPREHENSIVE) {
            // Tüm sertifika zinciri
            List<CertificateInfo> certChain = new ArrayList<>();
            if (chainForStatus != null) {
                for (CertificateWrapper cert : chainForStatus) {
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

        // Revocation bilgisini DSS DiagnosticData üzerinden zengin biçimde
        // doldur. ÖNCEKİ DURUM: `isRevoked = false` hardcoded'tu ve
        // `revocation*` alanları hiç set edilmiyordu — REVOKED bir sertifika
        // bile response'da "revoked: false" görünüyordu. Şimdi zincirdeki her
        // sertifika için OCSP/CRL kaynaklı en uygun revocation token'ı seçip
        // hem geriye dönük field'ları (revoked, revocationReason,
        // revocationDate, revocationTime) hem de zengin `revocation` alt
        // nesnesini populate ediyoruz.
        RevocationInfo revocation = revocationInfoExtractor.extractFor(certWrapper);
        boolean isRevoked = revocation != null && "REVOKED".equals(revocation.getStatus());
        if (revocation != null) {
            certInfo.setRevocation(revocation);
            certInfo.setRevocationReason(revocation.getRevocationReason());
            certInfo.setRevocationDate(revocation.getRevocationDate());
            // `revocationTime` legacy alan; tarihsel API uyumluluğu için
            // `revocationDate` ile aynı değeri taşır.
            certInfo.setRevocationTime(revocation.getRevocationDate());
        }

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

                // ÖNCEDEN: `setCertificateNotRevoked(true)` hardcoded'tu — REVOKED
                // imzacı sertifika için bile response'da
                // `certificateNotRevoked: true` görünüyordu. DSS DiagnosticData
                // üzerinden gerçek iptal durumunu okuyoruz. Revocation verisi
                // yoksa (örn. çevrimdışı mod) `true` döneriz; bu, "iptal
                // olduğuna dair bir kanıt yok" anlamına gelir — politika
                // strict moddaysa imzanın `valid` field'ı DSS tarafından
                // FAIL'lenmiş olur, dolayısıyla bu varsayım güvenli.
                details.setCertificateNotRevoked(revocationInfoExtractor.isNotRevoked(signingCert));
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
     * Hataları ve uyarıları toplar.
     *
     * @param trToleranceApplied TR-özel XAdES Type URI tolerance bu imzaya
     *        uygulandıysa <code>true</code>. Bu durumda DSS'in raporladığı
     *        SIG_CONSTRAINTS_FAILURE artık <em>hata</em> değil, açıklayıcı bir
     *        uyarıdır — istemciyi yanıltmamak için validationErrors yerine
     *        validationWarnings'e taşırız.
     */
    private void collectErrorsAndWarnings(
            SignatureInfo sigInfo,
            SimpleReport simpleReport,
            DetailedReport detailedReport,
            String signatureId,
            boolean trToleranceApplied) {

        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        // Simple report'tan hatalar. Tolerance varsa DSS bizden bağımsız
        // INVALID raporluyor — ama biz override ettik, error LIST'ine eklemeyiz.
        if (!simpleReport.isValid(signatureId) && !trToleranceApplied) {
            Indication indication = simpleReport.getIndication(signatureId);
            SubIndication subIndication = simpleReport.getSubIndication(signatureId);

            String errorMsg = "İmza geçersiz: " + indication.name();
            if (subIndication != null) {
                errorMsg += " (" + subIndication.name() + ")";
            }
            errors.add(errorMsg);
        }

        // SubIndication kontrolü
        SubIndication subIndication = simpleReport.getSubIndication(signatureId);
        if (subIndication != null) {
            if (trToleranceApplied && subIndication == SubIndication.SIG_CONSTRAINTS_FAILURE) {
                // TR-özel tolerans devrede: DSS'in SIG_CONSTRAINTS_FAILURE'ı
                // jenerik bir kriptografik hata değil, sadece XAdES Type URI
                // yazım hatası kaynaklı. Operatör/istemci için anlaşılır
                // bir uyarıya çevir; tam audit detayı sigInfo.appliedSuppressions
                // altında. Kodu warning metnine de ekliyoruz ki operatör
                // log/grep ile hızlıca tarayabilsin.
                warnings.add("[" + SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getCode()
                        + "] İmza, KamuSM/GİB ekosistemine özgü XAdES "
                        + "SignedProperties Type URI yazım hatası içeriyor "
                        + "(\"…/v1.3.2/XAdES.xsd#SignedProperties\"). "
                        + "Kriptografik bütünlük doğrulandı; tolerans uygulandı.");
            } else {
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

