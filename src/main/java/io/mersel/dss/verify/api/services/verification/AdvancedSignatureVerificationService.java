package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraint;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConstraintsConclusion;
import eu.europa.esig.dss.detailedreport.jaxb.XmlMessage;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSAV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlStatus;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.detailedreport.jaxb.XmlXCV;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
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
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import io.mersel.dss.verify.api.models.enums.SuppressionCode;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import io.mersel.dss.verify.api.services.notification.InvalidSignatureNotifier;
import io.mersel.dss.verify.api.services.util.EcdsaXmlSignaturePreprocessor;
import io.mersel.dss.verify.api.services.util.LegacyTurkishXadesAnomaly;
import io.mersel.dss.verify.api.services.util.LegacyTurkishXadesTypeUriDetector;
import io.mersel.dss.verify.api.services.util.RevocationInfoExtractor;
import io.mersel.dss.verify.api.services.util.XadesSignaturePackagingDetector;
import io.micrometer.core.instrument.MeterRegistry;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
     * DSS validation pipeline locale'i — her doğrulama akışında
     * {@code SignedDocumentValidator.setLocale(...)} ile pipeline'a
     * geçirilir. Tek-doğruluk-kaynağı bean olarak
     * {@link io.mersel.dss.verify.api.config.I18nProviderConfiguration#dssValidationLocale()}
     * tarafından expose edilir; default <code>tr</code>.
     *
     * <p>Bu Locale tüm BBB constraint mesajlarının
     * (<code>BBB_XCV_ISCGKU</code>, <code>TRUSTED_SERVICE_STATUS</code>, vb.)
     * <code>XmlConstraint.error.value</code> alanına hangi dilde yazılacağını
     * belirler. {@link #collectFailingBbbConstraintMessages} bu mesajları
     * <code>validationErrors</code> listesine zenginleştirirken seçilen
     * locale'in çıktısını okur.</p>
     */
    @Autowired
    private Locale dssValidationLocale;

    /**
     * INVALID imza tespit edildiğinde generic webhook ve/veya Slack
     * incoming webhook'una <em>best-effort</em> bildirim gönderir.
     * Feature default açık ama URL set edilmediği sürece no-op; ekstra
     * heap/IO maliyeti sıfırdır. Aktif ise OkHttp {@code enqueue()} ile
     * async POST atar — verifier thread'i HTTP'yi beklemez.
     *
     * <p>{@code required = false}: testlerde / minimal context'lerde
     * notifier bean'i olmayabilir — verifier bootstrap bozulmasın.</p>
     */
    @Autowired(required = false)
    private InvalidSignatureNotifier invalidSignatureNotifier;

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
     *
     * <p><b>Tolerance gate v2.2 allow-list-only mantığı:</b></p>
     * <ol>
     *   <li><b>SubIndication allow-list</b> ({@link #ALLOWED_TOLERANCE_SUB_INDICATIONS}):
     *       Yalnız {@code SIG_CONSTRAINTS_FAILURE} bypass adayı; başka
     *       SubIndication'lar (HASH_FAILURE, FORMAT_FAILURE, vb.)
     *       içerik manipülasyonu veya kriptografik kırılma demek olabilir.</li>
     *   <li><b>Universal failure allow-list</b> ({@link #collectAllBbbFailureKeys}):
     *       Tüm BBB bloklarındaki (FC/ISC/VCI/CV/SAV/XCV-top/SubXCV/PSV)
     *       NOT_OK constraint key'leri toplanır; bu set
     *       {@link #ALLOWED_TOLERANCE_FAILURE_KEYS}'in alt-kümesi
     *       olmalıdır. Tek izinli key:
     *       <code>BBB_SAV_ISQPMDOSPP</code>. Diğer her şey gate'i kapatır
     *       (KeyUsage, hash mismatch, duplicate signature, ICS mismatch,
     *       PSV failure, revocation freshness, …).</li>
     * </ol>
     *
     * <p>v2.0/v2.1'de buraya bir "cryptographic re-validation" katmanı
     * eklenmişti; Type URI imza kapsamında olduğu için bu yaklaşım
     * tasarım hatasıydı ve gerçek vakalarda her zaman patladığı için
     * v2.2'de kaldırıldı (detay için
     * {@link #evaluateTrLegacyXadesTolerance} JavaDoc).</p>
     */
    static final String BBB_SAV_ISQPMDOSPP_KEY = "BBB_SAV_ISQPMDOSPP";

    /**
     * <strong>Tolerance gate'inin kabul ettiği TEK izinli FAIL constraint
     * key set'i</strong>. Bu set DIŞINDA herhangi bir BBB bloğunda
     * (FC/ISC/VCI/CV/SAV/XCV/PSV) NOT_OK constraint varsa toleransı
     * <em>uygulamayız</em>.
     *
     * <p>Whitelist mentality — explicit allow. Yeni bir FAIL kategorisi
     * eklenirse default güvenli tarafta kalır (reddedilir); operatör
     * explicit olarak bu set'i genişletmelidir.</p>
     *
     * <p><b>Niçin sadece bu key?</b> {@code BBB_SAV_ISQPMDOSPP}, ETSI EN
     * 319 132-1 sözleşmesinde "SignedProperties veya message-digest
     * yok" hatasıdır. Üretici yanlış-yazılmış Type URI gönderdiğinde
     * DSS reference'ı tanıyamaz ve bu constraint FAIL'lenir. Kriptografi
     * sağlamsa (signatureWrapper.isSignatureValid() + isSignatureIntact())
     * ve başka FAIL yoksa, hata gerçekten yalnız etiket-bazlı bir hatadır.</p>
     */
    static final Set<String> ALLOWED_TOLERANCE_FAILURE_KEYS =
            Collections.unmodifiableSet(new LinkedHashSet<>(
                    Collections.singletonList(BBB_SAV_ISQPMDOSPP_KEY)));

    /**
     * <strong>Tolerance gate'inin kabul ettiği TEK izinli SubIndication
     * set'i</strong>. DSS SubIndication taxonomi'sinde yalnız
     * {@code SIG_CONSTRAINTS_FAILURE} legacy-TR XAdES Type URI yazım
     * hatası ile tutarlıdır.
     *
     * <p>Açık olarak <em>içerdiğimiz</em> diğer SubIndication'lar
     * <strong>asla</strong> tolere edilmez:</p>
     * <ul>
     *   <li>{@code HASH_FAILURE} — CV blok; içerik değiştirilmiş.</li>
     *   <li>{@code FORMAT_FAILURE} — FC blok; XML yapısı bozuk.</li>
     *   <li>{@code CHAIN_CONSTRAINTS_FAILURE} — XCV blok; sertifika
     *       sorunu (KeyUsage, expiry, vb.).</li>
     *   <li>{@code CRYPTO_CONSTRAINTS_FAILURE} — zayıf algoritma.</li>
     *   <li>{@code EXPIRED} / {@code REVOKED} — sertifika geçersiz.</li>
     *   <li>{@code NO_POE} — LTV için PoE yok.</li>
     * </ul>
     *
     * <p>{@link EnumSet} kullanımı DSS taxonomi değişimine karşı
     * dirençli kılar — DSS yarın yeni bir SubIndication eklerse default
     * tolere edilmez; explicit olarak set'e eklenmesi gerekir.</p>
     */
    static final Set<SubIndication> ALLOWED_TOLERANCE_SUB_INDICATIONS =
            Collections.unmodifiableSet(EnumSet.of(SubIndication.SIG_CONSTRAINTS_FAILURE));

    /**
     * Tolerance gate'inin mevcut sürüm kodu. Her karar bu sürümle
     * birlikte {@link AppliedSuppression#getGateVersion() audit kanıtına}
     * yazılır. Pipeline mantığı değiştikçe artırılır; eski kayıtlar
     * tarihsel forensic için orijinal sürümleriyle korunur.
     *
     * <ul>
     *   <li>{@code v1.x} — SAV white-list + XCV defense-in-depth
     *       (legacy gate; FC/ISC/VCI/CV/PSV blokları kontrol edilmiyordu,
     *       güvenlik açığı içeriyordu).</li>
     *   <li>{@code v2.0} — Universal Allow-List + SubIndication EnumSet +
     *       Cryptographic re-validation (Layer 3). Re-validation ERROR
     *       durumunda fail-open (konservatif tolerate).</li>
     *   <li>{@code v2.1} — Re-validation ERROR davranışı fail-closed'a
     *       alındı (safe-by-default).</li>
     *   <li>{@code v2.2} (mevcut sürüm) — <strong>Re-validation katmanı
     *       kaldırıldı</strong> (tasarım hatası: Type URI imza
     *       kapsamında, byte stream'inde değiştirmek SignatureValue'yi
     *       her zaman geçersizleştirir; gerçek P1/P2 vakalarda layer her
     *       zaman patlardı). Gate <strong>allow-list-only</strong>:
     *       8 katmanlı süzgeç (config + indication + subIndication +
     *       signatureIntact + signatureValid + observedFailureKeys ⊆
     *       allow-list + pattern eşleşmesi + kind eşleşmesi) tek başına
     *       yeterli güveni sağlar. KeyUsage / chain / revocation /
     *       policy hash gibi diğer FAIL key'leri allow-list dışında
     *       olduğu için gate'i kapatır.</li>
     * </ul>
     */
    static final String TOLERANCE_GATE_VERSION = "v2.2";

    /**
     * Allow-list süzgecinden geçip suppress edilen kayıtlar için
     * Prometheus counter ailesi. Label'lar:
     * <ul>
     *   <li>{@code code} — uygulanan SuppressionCode (örn.
     *       <code>MDSS-XADES-LEGACY-TR-TYPE-URI</code>).</li>
     *   <li>{@code gate_version} — {@link #TOLERANCE_GATE_VERSION}.</li>
     * </ul>
     */
    private static final String METRIC_TOLERANCE_APPLIED =
            "mdss_tolerance_applied_total";

    /**
     * Tolerance reddedildiği her vaka için counter. Label:
     * <ul>
     *   <li>{@code code} — aday SuppressionCode (örn.
     *       <code>MDSS-XADES-LEGACY-TR-TYPE-URI</code>).</li>
     *   <li>{@code gate_version} — {@link #TOLERANCE_GATE_VERSION}.</li>
     *   <li>{@code reason} — reddetme nedeni (
     *       <code>indication_not_indeterminate</code>,
     *       <code>sub_indication_not_allowed</code>,
     *       <code>signature_not_intact</code>,
     *       <code>signature_not_valid</code>,
     *       <code>unallowed_failure_key</code>,
     *       <code>no_failure_observed</code>,
     *       <code>pattern_no_match</code>,
     *       <code>config_disabled</code>).</li>
     * </ul>
     */
    private static final String METRIC_TOLERANCE_REJECTED =
            "mdss_tolerance_rejected_total";

    /**
     * Micrometer registry — Spring Boot Actuator + micrometer-prometheus
     * registry tarafından sağlanır. Test/CI ortamında ya da minimum
     * Spring context'inde bulunmayabilir, dolayısıyla
     * {@code required=false}; null ise metric kayıtları sessizce no-op
     * olur (doğrulama akışı etkilenmez).
     */
    @Autowired(required = false)
    private MeterRegistry meterRegistry;

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
     * İmzalı dokümanı doğrular — eski API, geriye uyumluluk için sarmalayıcı.
     * DSS DetailedReport XML'i response'a eklenmez.
     *
     * @param signedDocument İmzalı doküman
     * @param originalDocument Orijinal doküman (detached signature için)
     * @param level Doğrulama seviyesi (SIMPLE veya COMPREHENSIVE)
     * @return Doğrulama sonucu (her imzada yalnız {@code rootCause}; detaylı
     *         {@code failedConstraints} listesi dolmaz)
     */
    public VerificationResult verifySignature(
            MultipartFile signedDocument,
            MultipartFile originalDocument,
            VerificationLevel level) {
        return verifySignature(signedDocument, originalDocument, level, false);
    }

    /**
     * İmzalı dokümanı doğrular — kategorize {@code failedConstraints} opt-in ile.
     *
     * @param signedDocument İmzalı doküman
     * @param originalDocument Orijinal doküman (detached signature için)
     * @param level Doğrulama seviyesi (SIMPLE veya COMPREHENSIVE)
     * @param includeFailedConstraints <code>true</code> ise her imzaya
     *                               {@link SignatureInfo#getFailedConstraints()
     *                               failedConstraints} alanı olarak tüm BBB
     *                               FAIL constraint'leri ({@code ROOT_CAUSE} +
     *                               {@code DERIVED} + {@code CASCADE}) eklenir —
     *                               audit/forensic için. Default <code>false</code>
     *                               — alan <code>null</code> kalır, JSON'a
     *                               yazılmaz; operatör yalnız {@code rootCause}
     *                               görür.
     * @return Doğrulama sonucu
     */
    public VerificationResult verifySignature(
            MultipartFile signedDocument,
            MultipartFile originalDocument,
            VerificationLevel level,
            boolean includeFailedConstraints) {

        logger.info("Starting advanced signature verification. Level: {}, includeFailedConstraints: {}",
                level, includeFailedConstraints);

        // Dosya metadatasını ve byte içeriklerini ÖNDEN oku. Doğrulayıcı (DSS)
        // tarafında parse hatası (örn. bozuk/namespace eksik XML) atılırsa
        // ana try/catch'in sonunda bu değerlerle Slack/webhook bildirimini
        // hâlâ gönderebilelim diye method-scope'a alıyoruz. Önceki davranışta
        // bytes ve fileName ana try'in içinde okunuyordu; o yüzden parse
        // exception'ı sonrası catch bloğunun bildirim için elinde hiçbir
        // bağlam kalmıyordu (Slack mesajı hiç düşmüyordu).
        String signedFileName = signedDocument != null ? signedDocument.getOriginalFilename() : null;
        String signedContentType = signedDocument != null ? signedDocument.getContentType() : null;
        String originalFileName = (originalDocument != null && !originalDocument.isEmpty())
                ? originalDocument.getOriginalFilename() : null;
        byte[] signedBytes = null;
        byte[] originalBytes = null;

        try {
            signedBytes = signedDocument.getBytes();

            // GİB/TÜBİTAK Mali Mühür ECDSA imzaları (DER-encoded) için W3C XMLDSig
            // uyumluluğunu sağla: SignatureValue içindeki ASN.1 DER SEQUENCE'i raw r||s'e çevir.
            // Preprocessor sertifika EC değilse veya gerekli koşullar sağlanmazsa no-op döner.
            if (config.isEcdsaDerPreprocessorEnabled()) {
                signedBytes = ecdsaXmlSignaturePreprocessor.preprocess(signedBytes);
            }

            DSSDocument document = new InMemoryDocument(signedBytes, signedFileName);

            // Orijinal doküman varsa (detached signature için). Byte'ları
            // method-scope'a kaydediyoruz: hem DSS detached content olarak
            // kullanıyoruz hem de bildirim akışına aktarıyoruz (parse hatası
            // sonrası catch bloğu da görsün).
            List<DSSDocument> detachedContents = new ArrayList<>();
            if (originalDocument != null && !originalDocument.isEmpty()) {
                originalBytes = originalDocument.getBytes();
                DSSDocument detachedContent = new InMemoryDocument(
                        originalBytes,
                        originalFileName
                );
                detachedContents.add(detachedContent);
            }

            // Validator oluştur
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

            // DSS i18n locale'i pipeline'a inject et — bu çağrı
            // I18nProvider'ı configured locale ile kurar ve tüm BBB
            // constraint mesajlarının (BBB_XCV_ISCGKU,
            // TRUSTED_SERVICE_STATUS, vb.) XmlConstraint.error.value
            // alanına seçilen dilde (default tr) doldurulmasını sağlar.
            // Eksik anahtarlar otomatik dss-messages.properties (English)
            // ile fallback eder.
            validator.setLocale(dssValidationLocale);

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
                    reports, level, signedBytes, packagingBySignatureId,
                    includeFailedConstraints);

            logger.info("Advanced signature verification completed. Valid: {}, Signatures: {}",
                    result.isValid(), result.getSignatures().size());

            // INVALID ise konfigüre edilmiş webhook/Slack kanallarına async
            // bildirim gönder. Best-effort: notifier kapalıysa veya URL set
            // edilmemişse no-op; exception atarsa doğrulama akışı
            // etkilenmeden devam eder. signedBytes parametresi ECDSA
            // preprocessor sonrası halini taşıdığı için imza üreticisinin
            // gönderdiği orijinalle birebir eşleşmeyebilir; receiver içerik
            // forensik analizi için sha256Hex + size üzerinden de eşleştirme
            // yapabilir.
            //
            // ÜÇ KATMAN DEFENSE: (1) notifier'ın kendi içindeki outer
            // try/catch, (2) burada notifyIfInvalid() çağrısının try/catch'i,
            // (3) originalDocument.getBytes() ayrı try/catch'te. Birinci ve
            // ikinci katman fonksiyonel olarak aynı kontratı koruyor ama
            // şu farkla: notifier bean'i refactor sırasında değişirse (örn.
            // birisi outer catch'i yanlışlıkla kaldırırsa) buradaki ikinci
            // katman yine güvenli tarafta kalır. Üçüncü katman MultipartFile
            // implementasyonunun temp-file based olduğu senaryolarda IO
            // hatasını izole eder — orijinal byte'lar okunamasa da
            // signedBytes'la bildirim yine gider.
            try {
                if (invalidSignatureNotifier != null) {
                    invalidSignatureNotifier.notifyIfInvalid(
                            result,
                            signedBytes,
                            signedFileName,
                            signedContentType,
                            originalBytes,
                            originalFileName);
                }
            } catch (Throwable notifyEx) {
                // Throwable yakalıyoruz — bu satır verifier akışının son
                // perdesi; bildirim adına HİÇBİR ŞEY response'u kıramamalı.
                logger.warn("Invalid signature notification dispatch failed (yok sayıldı): {}",
                        notifyEx.toString());
            }

            return result;

        } catch (Exception e) {
            logger.error("Advanced signature verification failed: {}", e.getMessage(), e);

            // ÖNEMLİ: Doğrulama exception'ı (örn. bozuk XML, eksik
            // namespace, parse hatası) atıldığında Slack/webhook bildirimi
            // ESKİDEN HİÇ DÜŞMÜYORDU çünkü notify çağrısı try bloğunun
            // success-path'ine gömülüydü. Şimdi sentetik bir
            // VerificationResult ({@code valid=false},
            // {@code status="VERIFICATION_ERROR"}, hata mesajı + cause
            // zinciri errors[]'da) üretip aynı dispatch yolundan
            // gönderiyoruz: dosya adı, boyut, sha256, base64 içerik,
            // x-log-* korelasyon header'ları — operatörün sahip olduğu tüm
            // bağlam Slack/webhook'a ulaşır. Bildirim hatası akışı bozmaz;
            // notifyVerificationFailure kendi içinde Throwable yutar.
            notifyVerificationFailure(e, signedBytes, signedFileName, signedContentType,
                    originalBytes, originalFileName);

            throw new VerificationException("İmza doğrulama hatası: " + e.getMessage(), e);
        }
    }

    /**
     * Doğrulama akışı bir exception ile patladığında (örn. bozuk XML, eksik
     * namespace, ECDSA preprocessor hatası, multipart IO hatası), Slack/
     * webhook kanalına yine de bildirim gider — operatör başarısız
     * doğrulama isteklerini de chat'te canlı görsün diye.
     *
     * <p>Bu metod sentetik bir {@link VerificationResult} üretir
     * ({@code valid=false}, {@code status="VERIFICATION_ERROR"}) ve
     * exception cause zincirini {@code errors} listesine yazar; ardından
     * mevcut {@link InvalidSignatureNotifier#notifyIfInvalid} dispatch
     * yolunu çağırır. Notifier'ın <em>tüm</em> kanal mantığı (generic
     * webhook + HMAC, Slack incoming webhook, Slack bot file upload,
     * x-log-* korelasyon header snapshot'ı) hiç değişmeden re-use edilir;
     * bu sayede başarısız doğrulamalar başarılı INVALID akışıyla bire-bir
     * aynı şema, aynı kanallar, aynı boyut sınırları içinde raporlanır.</p>
     *
     * <p>Best-effort kontratı: bildirim üretimi/dispatch'i sırasında
     * herhangi bir Throwable atılırsa yutulur; verifier akışı (re-throw
     * yapılacak {@link VerificationException}) etkilenmez.</p>
     *
     * @param failure         doğrulamayı bozan exception (cause zinciri ile).
     * @param signedBytes     varsa imzalı doküman byte'ları (hash + içerik için).
     *                        {@code null} olabilir (örn. multipart read hatası).
     * @param signedFileName  imzalı doküman adı; {@code null} olabilir.
     * @param signedContentType imzalı doküman MIME tipi; {@code null} olabilir.
     * @param originalBytes   varsa detached orijinal doküman byte'ları.
     * @param originalFileName detached orijinal doküman adı.
     */
    private void notifyVerificationFailure(
            Throwable failure,
            byte[] signedBytes,
            String signedFileName,
            String signedContentType,
            byte[] originalBytes,
            String originalFileName) {

        if (invalidSignatureNotifier == null) {
            return;
        }

        try {
            VerificationResult syntheticResult = new VerificationResult();
            syntheticResult.setValid(false);
            // Yeni status kodu — "INVALID"den ayrı tutuyoruz: receiver
            // "imza bozuk" ile "doğrulama hiç çalıştırılamadı (parse/IO
            // hatası)" arasını ayırt edebilsin. Slack mesajının özet
            // bloğunda bu değer code-format'lı olarak görünür.
            syntheticResult.setStatus("VERIFICATION_ERROR");
            syntheticResult.setVerificationTime(new Date());
            syntheticResult.setSignatureCount(0);

            List<String> errors = new ArrayList<>();
            // Cause zincirini ilk 5 seviyeye kadar takip et (sonsuz döngü
            // koruması: cause kendisini referanslıyorsa kır). Receiver'a
            // exception nedeni hakkında olabildiğince zengin bağlam veririz
            // ama Slack 3000-char/section limitini de patlatmayız.
            Throwable cur = failure;
            int depth = 0;
            while (cur != null && depth < 5) {
                String msg = cur.getMessage();
                if (msg == null || msg.trim().isEmpty()) {
                    msg = cur.getClass().getSimpleName();
                }
                errors.add((depth == 0 ? "İmza doğrulama hatası: " : "Caused by: ") + msg);
                Throwable next = cur.getCause();
                if (next == null || next == cur) {
                    break;
                }
                cur = next;
                depth++;
            }
            syntheticResult.setErrors(errors);

            invalidSignatureNotifier.notifyIfInvalid(
                    syntheticResult,
                    signedBytes,
                    signedFileName,
                    signedContentType,
                    originalBytes,
                    originalFileName);
        } catch (Throwable t) {
            // Bildirim verifier akışını ASLA bozmaz — Throwable yakalıyoruz
            // (NoClassDefFoundError vb. dahil). WARN yetiyor; verifier zaten
            // VerificationException ile yukarıya bilgi taşıyor.
            logger.warn("Verification failure notification dispatch failed (yok sayıldı): {}",
                    t.toString());
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
     * Gelişmiş doğrulama sonuçlarını parse eder.
     *
     * @param includeFailedConstraints <code>true</code> ise her imzaya
     *        {@link SignatureInfo#getFailedConstraints() failedConstraints}
     *        alanı olarak tüm BBB FAIL constraint'leri ({@code ROOT_CAUSE} +
     *        {@code DERIVED} + {@code CASCADE}) eklenir. Default
     *        <code>false</code> — alan <code>null</code> kalır, JSON'a yazılmaz.
     */
    private VerificationResult parseAdvancedVerificationResult(
            Reports reports,
            VerificationLevel level,
            byte[] originalXmlBytes,
            Map<String, SignaturePackaging> packagingBySignatureId,
            boolean includeFailedConstraints) {
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
                    packagingBySignatureId,
                    includeFailedConstraints
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
     * Tek bir imzayı işler.
     *
     * @param includeFailedConstraints <code>true</code> ise sonuca tüm
     *        kategorize BBB FAIL constraint'leri eklenir
     *        ({@link SignatureInfo#getFailedConstraints()}).
     */
    private SignatureInfo processSignature(
            String signatureId,
            SimpleReport simpleReport,
            DetailedReport detailedReport,
            DiagnosticData diagnosticData,
            VerificationLevel level,
            byte[] originalXmlBytes,
            Map<String, SignaturePackaging> packagingBySignatureId,
            boolean includeFailedConstraints) {

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

        // TR-özel XAdES patoloji değerlendirmesi. İki ayrı yol var:
        //   1) SUPPRESSION: DSS INVALID → biz VALID (override). Şu an
        //      yalnızca TYPE_URI_VARIANT için. sigInfo.appliedSuppressions'a yazılır.
        //   2) REJECTION:  DSS INVALID → biz de INVALID (destek), ama
        //      "neden" sorusuna Türkiye-spesifik tanı koduyla cevap veririz.
        //      MISSING_SP_REFERENCE için. sigInfo.appliedRejections'a yazılır;
        //      verdict değişmez.
        // Gate ve detector tek bir noktada çalışır; sonuç (anomaly) iki
        // değerlendirici metoda da aynı obje olarak geçer — XML byte'ları
        // ikinci kez parse edilmez.
        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(signatureId);
        LegacyTurkishXadesAnomaly trAnomaly = null;
        // Gözlenen FAIL key set'ini bir kez topla — hem gate kararı için
        // hem de tolerance uygulanırsa audit kanıtı için. Gate'i geçen
        // imzalar dışında set kullanılmaz (null kalır).
        Set<String> observedFailureKeys = null;
        if (matchesTrLegacyXadesGate(indication, subIndication, signatureWrapper,
                detailedReport, signatureId, originalXmlBytes)) {
            trAnomaly = legacyTrXadesDetector.detectAnomaly(originalXmlBytes);
            observedFailureKeys = collectAllBbbFailureKeys(detailedReport, signatureId);
        }

        AppliedSuppression trSuppression =
                (trAnomaly != null && trAnomaly.getKind() == LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT)
                        ? evaluateTrLegacyXadesTolerance(
                                signatureId, indication, subIndication, trAnomaly,
                                observedFailureKeys, originalXmlBytes)
                        : null;
        AppliedRejection trRejection =
                (trSuppression == null
                        && trAnomaly != null
                        && trAnomaly.getKind() == LegacyTurkishXadesAnomaly.Kind.MISSING_SP_REFERENCE)
                        ? evaluateTrLegacyXadesRejection(
                                signatureId, indication, subIndication, trAnomaly)
                        : null;
        boolean trToleranceApplied = trSuppression != null;
        boolean trRejectionApplied = trRejection != null;

        if (trToleranceApplied) {
            // İmzayı PASSED'a yükselttik. SubIndication artık anlamsız —
            // istemciyi yanıltmamak için temizliyoruz. Audit kanıtı
            // appliedSuppressions altına yazılıyor.
            sigInfo.setAppliedSuppressions(
                    new ArrayList<>(java.util.Collections.singletonList(trSuppression)));
            indication = Indication.TOTAL_PASSED;
            subIndication = null;
        } else if (trRejectionApplied) {
            // Verdict'i değiştirmiyoruz; sadece neden reddedildiğini Mersel
            // tanı koduyla zenginleştiriyoruz. DSS'in INDETERMINATE/SIG_CONSTRAINTS_FAILURE
            // çıktısı korunur.
            sigInfo.setAppliedRejections(
                    new ArrayList<>(java.util.Collections.singletonList(trRejection)));
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
            processSignatureWrapper(sigInfo, signatureWrapper, level,
                    detailedReport, includeFailedConstraints);
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
                trToleranceApplied, trSuppression, trRejection, includeFailedConstraints);

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
     * KamuSM / GİB üreticilerinin XAdES Type URI yazım hatasını
     * <strong>suppression</strong> yoluyla işler: gate v2.2'nin allow-list
     * süzgeci geçildiyse DSS'in INVALID verdict'i VALID'e yükseltilir;
     * üretici Type URI'si + forensic audit kanıtı kayıt altına alınır.
     *
     * <p>Çağırıcı (processSignature) bu noktada
     * {@link #matchesTrLegacyXadesGate} kontrolünü geçmiş ve detector'dan
     * {@link LegacyTurkishXadesAnomaly.Kind#TYPE_URI_VARIANT} anomaly'sini
     * çıkarmış olmalıdır.</p>
     *
     * <h3>Tasarım notu — neden re-validation katmanı yok?</h3>
     * <p>v2.0/v2.1'de bu noktada "cryptographic re-validation" katmanı
     * vardı: detector Type URI'yi standart varyantla byte stream üzerinde
     * değiştirip DSS'i yeniden çalıştırırdı; <code>TOTAL_PASSED</code>
     * dönerse tolerance kanıtlı kabul edilirdi. <strong>Tasarım
     * hatasıydı.</strong> <code>&lt;ds:Reference Type="..."&gt;</code>
     * attribute değeri SignedInfo bloğunun içinde yer aldığı için imza
     * kapsamındadır; byte stream'inde değiştirmek canonical SignedInfo'yu
     * değiştirir, dolayısıyla <code>SignatureValue</code> artık geçersiz
     * olur ({@code SIG_CRYPTO_FAILURE}). Gerçek P1/P2 vakalarda
     * re-validation <em>her zaman</em> patladığı için katman tamamen
     * kaldırıldı. Birim testlerde <code>"PASSED"</code> senaryosu mock
     * üzerinden kurulabiliyordu, ama gerçek dünyada o senaryo asla
     * oluşamaz.</p>
     *
     * <p>Gate v2.2 (mevcut sürüm) <strong>allow-list-only</strong> mantığa
     * dayanır: 8 katmanlı süzgeç (config + indication + subIndication +
     * signatureIntact + signatureValid + observedFailureKeys ⊆ allow-list +
     * pattern eşleşmesi + kind eşleşmesi) <em>tek başına</em> yeterince
     * güçlü güveni sağlar. KeyUsage / chain / revocation / policy hash
     * gibi tüm diğer FAIL key'leri allow-list dışında olduğu için
     * gate'i kapatır.</p>
     *
     * @param anomaly çağırıcı tarafından tespit edilmiş Type URI varyantı
     *                (kind = TYPE_URI_VARIANT garantili)
     * @param observedFailureKeys allow-list süzgecinden geçen, DSS
     *                bbb'lerinde gözlenen NOT_OK constraint key set'i
     *                (audit kayıdı için)
     * @param originalXmlBytes orijinal XML byte'ları — audit kayıdına
     *                yazılacak SHA-256 + size hesaplaması için
     * @return tolerans uygulanacaksa audit kanalına yazılacak
     *         {@link AppliedSuppression}; flag kapalı ise <code>null</code>
     *         (DSS kararı aynen kullanılmalı).
     */
    private AppliedSuppression evaluateTrLegacyXadesTolerance(
            String signatureId,
            Indication indication,
            SubIndication subIndication,
            LegacyTurkishXadesAnomaly anomaly,
            Set<String> observedFailureKeys,
            byte[] originalXmlBytes) {

        if (!config.isTrLegacyXadesToleranceEnabled()) {
            logger.debug("TR XAdES Type URI patolojisi tespit edildi ama tolerance "
                    + "kapalı (signatureId={}); DSS kararı korunuyor.", signatureId);
            bumpToleranceRejected("config_disabled");
            return null;
        }

        String hit = anomaly.getEvidence();

        logger.info("TR legacy XAdES toleransı uygulandı (signatureId={}, code={}, "
                        + "kind=TYPE_URI_VARIANT, gateVersion={}). DSS "
                        + "INDETERMINATE/SIG_CONSTRAINTS_FAILURE iken imza kriptografik "
                        + "olarak sağlam ve tek hata BBB_SAV_ISQPMDOSPP. Üretici Type URI: '{}'",
                signatureId, SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getCode(),
                TOLERANCE_GATE_VERSION, hit);
        bumpToleranceApplied();

        SuppressionCode sc = SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI;
        java.util.Map<String, Object> evidence = new java.util.LinkedHashMap<>();
        evidence.put("detectedTypeUri", hit);
        evidence.put("dssBbbConstraint", BBB_SAV_ISQPMDOSPP_KEY);

        String sha256 = sha256Hex(originalXmlBytes);
        Long sizeBytes = originalXmlBytes != null ? (long) originalXmlBytes.length : null;

        return new AppliedSuppression(
                sc.getCode(),
                sc.getTitle(),
                sc.getDefaultReason() + " Üretici Type URI: \"" + hit + "\".",
                sc.getSeverity(),
                indication.name(),
                subIndication.name(),
                evidence,
                sc.getDocsUrl(),
                TOLERANCE_GATE_VERSION,
                ALLOWED_TOLERANCE_FAILURE_KEYS,
                observedFailureKeys,
                sha256,
                sizeBytes);
    }

    /**
     * Forensic için imzalı doküman byte'larının SHA-256 hex değeri.
     * MessageDigest patlarsa null döner (audit kanıtı bu durumda eksik
     * gelir ama suppression akışı bozulmaz).
     */
    private static String sha256Hex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    /**
     * XAdES tek-referanslı imza patolojisi için <strong>rejection
     * enrichment</strong>: DSS'in INVALID verdict'i aynen korunur, "neden
     * invalid" sorusuna Mersel'e özel kataloglu tanı koduyla cevap verilir.
     *
     * <p>Bu varyantta ikinci <code>&lt;ds:Reference&gt;</code> hiç
     * üretilmediği için <code>SignedProperties</code> (içindeki
     * <code>SigningTime</code>, <code>SigningCertificate</code> digest,
     * <code>SignaturePolicyIdentifier</code> vs.) imza kapsamı dışında
     * kalır; bu alanlar post-signing modifiye edilebilir ve imza yine
     * matematik olarak doğrulanır. Yapısal hata imzayı üreten yazılımda;
     * iki referans (biri body, biri SignedProperties) üretilmelidir.
     * Verdict her zaman INVALID; rejection objesi yalnızca tanı kanalıdır
     * — operatör hangi spesifik patolojinin tetiklediğini Mersel kodundan
     * teşhis eder.</p>
     *
     * <p>Çağırıcı (processSignature) bu noktada
     * {@link #matchesTrLegacyXadesGate} kontrolünü geçmiş ve detector'dan
     * {@link LegacyTurkishXadesAnomaly.Kind#MISSING_SP_REFERENCE}
     * anomaly'sini çıkarmış olmalıdır.</p>
     *
     * <p>Config gate: {@code verification.tr-legacy-xades-rejection-enrichment-enabled}.
     * Default açık; kapalıyken patoloji tespit edilse bile rejection
     * objesi üretilmez ve DSS'in jenerik SIG_CONSTRAINTS_FAILURE'ı tek
     * başına raporlanır.</p>
     *
     * @return rejection uygulanacaksa audit kanalına yazılacak
     *         {@link AppliedRejection}; flag kapalıysa <code>null</code>.
     */
    private AppliedRejection evaluateTrLegacyXadesRejection(
            String signatureId,
            Indication indication,
            SubIndication subIndication,
            LegacyTurkishXadesAnomaly anomaly) {

        if (!config.isTrLegacyXadesRejectionEnrichmentEnabled()) {
            logger.debug("TR XAdES missing-SP-reference patolojisi tespit edildi ama "
                    + "rejection enrichment kapalı (signatureId={}); DSS'in jenerik "
                    + "SIG_CONSTRAINTS_FAILURE'ı tek başına raporlanacak.", signatureId);
            return null;
        }

        String signedPropertiesId = anomaly.getEvidence();
        RejectionCode rc = RejectionCode.MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE;

        logger.warn("TR legacy XAdES rejection raporlandı (signatureId={}, code={}). "
                        + "DSS INDETERMINATE/SIG_CONSTRAINTS_FAILURE; imza kriptografik "
                        + "olarak sağlam fakat SignedProperties Id='{}' hiçbir Reference "
                        + "tarafından bağlanmamış. İmza reddedildi; SigningTime ve "
                        + "SigningCertificate kriptografik olarak korunmuyor.",
                signatureId, rc.getCode(), signedPropertiesId);

        java.util.Map<String, Object> evidence = new java.util.LinkedHashMap<>();
        evidence.put("signedPropertiesId", signedPropertiesId);
        evidence.put("dssBbbConstraint", BBB_SAV_ISQPMDOSPP_KEY);
        evidence.put("missingProtection",
                "SigningTime, SigningCertificateV2, SignaturePolicyIdentifier, "
                        + "SignerRole, CommitmentTypeIndication");
        evidence.put("standardReference", "ETSI EN 319 132-1 (XAdES-BES)");
        evidence.put("remediation",
                "İmzayı üreten yazılım iki ds:Reference üretmelidir: biri "
                        + "URI=\"\" (belge body'si, enveloped-signature transform), "
                        + "diğeri URI=\"#<SignedPropertiesId>\" "
                        + "Type=\"http://uri.etsi.org/01903#SignedProperties\" "
                        + "(qualifying properties).");

        return new AppliedRejection(
                rc.getCode(),
                rc.getTitle(),
                rc.getDefaultReason() + " SignedProperties Id: \"" + signedPropertiesId + "\".",
                rc.getSeverity(),
                indication.name(),
                subIndication.name(),
                evidence,
                rc.getDocsUrl());
    }

    /**
     * <strong>TR-özel XAdES patoloji değerlendirmesi için ortak ön-koşullar
     * (gate v2)</strong>. Hem {@link #evaluateTrLegacyXadesTolerance} hem
     * {@link #evaluateTrLegacyXadesRejection} bu gate'i geçmek zorunda; tek
     * noktada toplu tutmak iki yolu birbirine paralel kılar (tanı koşulları
     * kayar/uyumsuz kalmaz).
     *
     * <h3>v1 → v2 hardening (whitelist mentality)</h3>
     * <p>Önceki sürümde (v1) iki ayrı helper vardı:
     * {@code isOnlyBbbSavFailureMessageDigestOrSignedProperties} (SAV
     * white-list) ve {@code hasAnyBbbXcvFailure} (XCV no-failure). Ama
     * FC/ISC/VCI/CV/PSV blokları <em>hiç</em> kontrol edilmiyordu —
     * dolayısıyla bir saldırgan hash mismatch yaratıp (CV blok) üzerine
     * legacy Type URI yazım hatası eklerse, gate kapanmıyordu ve imza
     * yanlışlıkla VALID görünebiliyordu.</p>
     *
     * <p>v2 mantığı tek bir <strong>universal allow-list</strong>:
     * {@link #collectAllBbbFailureKeys} tüm BBB bloklarındaki NOT_OK
     * constraint key'lerini toplar; bu set
     * {@link #ALLOWED_TOLERANCE_FAILURE_KEYS}'in alt-kümesi olmalıdır.
     * Tek izinli key {@code BBB_SAV_ISQPMDOSPP}; başka herhangi bir
     * FAIL (hangi blokta olursa olsun) gate'i kapatır.</p>
     *
     * <h3>Defansif strateji</h3>
     * <p>{@link #collectAllBbbFailureKeys} introspection patlarsa
     * sentetik bir marker key ({@code "__INTROSPECTION_FAILED__"}) ekler;
     * allow-list bu marker'ı içermediği için gate kapanır. "Şüphede
     * affetme" prensibi.</p>
     *
     * @return tüm ön-koşullar sağlanırsa <code>true</code>; aksi halde
     *         <code>false</code> ve çağıran <code>null</code> dönmelidir.
     *         Reddetme nedeni metric counter {@code mdss_tolerance_rejected_total}
     *         altında <code>reason</code> label'ı ile sayılır.
     */
    private boolean matchesTrLegacyXadesGate(
            Indication indication,
            SubIndication subIndication,
            SignatureWrapper signatureWrapper,
            DetailedReport detailedReport,
            String signatureId,
            byte[] originalXmlBytes) {
        // 1) Indication INDETERMINATE olmalı (verdict mismatch'i tolere
        // etmek imzayı yanlış raporlamak demek; TOTAL_PASSED zaten geçer,
        // FAILED ise gerçekten kırık).
        if (indication != Indication.INDETERMINATE) {
            bumpToleranceRejected("indication_not_indeterminate");
            return false;
        }
        // 2) SubIndication explicit allow-set'te olmalı (Katman 2). Default:
        // sadece SIG_CONSTRAINTS_FAILURE. HASH_FAILURE/FORMAT_FAILURE/
        // CHAIN_CONSTRAINTS_FAILURE/CRYPTO_CONSTRAINTS_FAILURE/EXPIRED/
        // REVOKED/NO_POE asla tolere edilmez.
        if (!ALLOWED_TOLERANCE_SUB_INDICATIONS.contains(subIndication)) {
            bumpToleranceRejected("sub_indication_not_allowed");
            return false;
        }
        // 3) SignatureWrapper kanonik (DSS DiagnosticData'da bulunabilmesi
        // gerekir; aksi halde kriptografik bütünlük sorgulayamayız).
        if (signatureWrapper == null) {
            bumpToleranceRejected("signature_wrapper_missing");
            return false;
        }
        // 4) Kriptografik bütünlük: SignatureValue PKI key ile doğrulandı mı?
        // Bu false ise gerçek bir kriptografik kırılma var demektir.
        if (!signatureWrapper.isSignatureIntact()) {
            bumpToleranceRejected("signature_not_intact");
            return false;
        }
        // 5) ds:Reference'ların digest kontrolü: içerik (body + signed
        // properties) hash'leri eşleşiyor mu? False ise içerik değişmiş
        // olabilir, asla tolere etme.
        if (!signatureWrapper.isSignatureValid()) {
            bumpToleranceRejected("signature_not_valid");
            return false;
        }
        // 6) Universal allow-list (Katman 1): tüm BBB bloklarındaki FAIL
        // key set'i ALLOWED_TOLERANCE_FAILURE_KEYS'in alt-kümesi olmalı.
        Set<String> observed = collectAllBbbFailureKeys(detailedReport, signatureId);
        if (observed.isEmpty()) {
            // Hiç FAIL yok ama INDETERMINATE? DSS edge-case; gate'e gerek
            // yok — zaten allow-list ihlali değil ama tolerance candidate
            // değil. Defansif olarak red.
            bumpToleranceRejected("no_failure_observed");
            return false;
        }
        if (!ALLOWED_TOLERANCE_FAILURE_KEYS.containsAll(observed)) {
            Set<String> blockers = new LinkedHashSet<>(observed);
            blockers.removeAll(ALLOWED_TOLERANCE_FAILURE_KEYS);
            logger.debug("TR XAdES toleransı uygulanmadı: izin verilmeyen FAIL key(ler) "
                            + "mevcut (signatureId={}, blockers={}, allowed={}).",
                    signatureId, blockers, ALLOWED_TOLERANCE_FAILURE_KEYS);
            bumpToleranceRejected("unallowed_failure_key");
            return false;
        }
        // 7) Detector + original byte'lar mevcut (suppression için XML
        // byte-level pattern eşleşmesi şart).
        if (originalXmlBytes == null || legacyTrXadesDetector == null) {
            bumpToleranceRejected("pattern_no_match");
            return false;
        }
        return true;
    }

    /**
     * <strong>Universal Allow-List helper</strong> (gate v2). DSS BBB
     * yapısındaki <em>tüm</em> blokları (FC/ISC/VCI/CV/SAV/XCV-top/SubXCV/PSV)
     * gezer ve {@link XmlStatus#NOT_OK} statüsündeki tüm constraint
     * key'lerini tek bir set olarak döner. Yalnız belirli bir blok için
     * white/black-list yapmak yerine kümeyi bütün olarak
     * {@link #ALLOWED_TOLERANCE_FAILURE_KEYS} ile karşılaştırırız —
     * tek noktada güvenlik politikası, eksik blok riski sıfır.
     *
     * <h3>Hangi bloklar gezilir?</h3>
     * <ul>
     *   <li><code>FC</code>  — Format Checks (signature byterange, duplicate
     *       sigs, vb. — <code>BBB_FC_*</code>)</li>
     *   <li><code>ISC</code> — Identification of Signing Certificate
     *       (<code>BBB_ICS_*</code>)</li>
     *   <li><code>VCI</code> — Validation Context Initialization
     *       (<code>BBB_VCI_*</code>)</li>
     *   <li><code>CV</code>  — Cryptographic Verification (reference digest
     *       mismatch — <strong>kritik</strong>: <code>BBB_CV_IRDOI</code>
     *       içerik manipülasyonu demek!)</li>
     *   <li><code>SAV</code> — Signed Attributes Validation
     *       (<code>BBB_SAV_*</code>) — bizim allow-list'imizdeki tek key
     *       buradan gelir</li>
     *   <li><code>XCV</code> — X.509 Certificate Validation
     *       (top-level + her <code>SubXCV</code> katmanı —
     *       <code>BBB_XCV_*</code>)</li>
     *   <li><code>PSV</code> — Past Signature Validation (LTV/LTA —
     *       <code>PSV_*</code>)</li>
     * </ul>
     *
     * <h3>Defansif kontrat</h3>
     * <p>JAXB introspection patlarsa sentetik bir marker key
     * <code>__INTROSPECTION_FAILED__</code> set'e eklenir. Bu marker
     * {@link #ALLOWED_TOLERANCE_FAILURE_KEYS}'te bulunmadığı için gate
     * otomatik olarak kapanır — "şüphede affetme" prensibi.</p>
     *
     * <h3>Test edilebilirlik</h3>
     * <p>{@code package-private} görünürlük: golden test matrisi (
     * {@code AdvancedSignatureVerificationServiceGateTest}) bu metodu
     * doğrudan çağırarak her tip blok için davranışı sabitler.</p>
     *
     * @param detailedReport DSS DetailedReport (null güvenli)
     * @param signatureId    aranan imza ID (null güvenli)
     * @return non-null, mutable {@link LinkedHashSet} — gözlenen tüm
     *         NOT_OK constraint key'leri (yoksa boş set)
     */
    Set<String> collectAllBbbFailureKeys(DetailedReport detailedReport, String signatureId) {
        Set<String> keys = new LinkedHashSet<>();
        if (detailedReport == null || signatureId == null) {
            return keys;
        }
        try {
            for (XmlBasicBuildingBlocks bbb :
                    detailedReport.getJAXBModel().getBasicBuildingBlocks()) {
                if (!signatureId.equals(bbb.getId())) {
                    continue;
                }
                collectKeysFrom(keys, bbb.getFC());
                collectKeysFrom(keys, bbb.getISC());
                collectKeysFrom(keys, bbb.getVCI());
                collectKeysFrom(keys, bbb.getCV());
                collectKeysFrom(keys, bbb.getSAV());
                XmlXCV xcv = bbb.getXCV();
                if (xcv != null) {
                    collectKeysFrom(keys, xcv);
                    if (xcv.getSubXCV() != null) {
                        for (XmlSubXCV sub : xcv.getSubXCV()) {
                            collectKeysFrom(keys, sub);
                        }
                    }
                }
                collectKeysFrom(keys, bbb.getPSV());
                break;
            }
        } catch (Exception e) {
            // DEFENSIVE: introspection patlarsa "şüphede affetme" —
            // sentetik marker ekle, allow-list'te olmadığı için gate kapanır.
            logger.debug("BBB key collection hatası ({}): {} — defansif olarak "
                            + "introspection-failed marker ekleniyor, gate kapanacak.",
                    signatureId, e.getMessage());
            keys.add("__INTROSPECTION_FAILED__");
        }
        return keys;
    }

    /**
     * Verilen DSS BBB blokunun NOT_OK constraint'lerindeki key'leri
     * {@code out} set'ine ekler. Null güvenli; null/empty constraint
     * listesi no-op.
     */
    private static void collectKeysFrom(Set<String> out, XmlConstraintsConclusion block) {
        if (block == null || block.getConstraint() == null) {
            return;
        }
        for (XmlConstraint c : block.getConstraint()) {
            if (c == null || c.getStatus() != XmlStatus.NOT_OK) {
                continue;
            }
            if (c.getName() != null && c.getName().getKey() != null) {
                out.add(c.getName().getKey());
            }
        }
    }

    /**
     * Tolerance reddedildiğinde counter'ı artırır (best-effort).
     * MeterRegistry null ise (test/minimal context) no-op.
     */
    private void bumpToleranceRejected(String reason) {
        if (meterRegistry == null) {
            return;
        }
        try {
            meterRegistry.counter(METRIC_TOLERANCE_REJECTED,
                    "code", SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getCode(),
                    "gate_version", TOLERANCE_GATE_VERSION,
                    "reason", reason).increment();
        } catch (Exception ignore) {
            // Metric registry hatası asla doğrulama akışını bozmamalı.
        }
    }

    /**
     * Tolerance uygulandığında counter'ı artırır (best-effort).
     * MeterRegistry null ise no-op.
     */
    private void bumpToleranceApplied() {
        if (meterRegistry == null) {
            return;
        }
        try {
            meterRegistry.counter(METRIC_TOLERANCE_APPLIED,
                    "code", SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getCode(),
                    "gate_version", TOLERANCE_GATE_VERSION).increment();
        } catch (Exception ignore) {
            // Metric registry hatası asla doğrulama akışını bozmamalı.
        }
    }

    /**
     * DSS BBB içindeki tüm FAIL constraint'leri toplayıp insan-okur
     * mesajlarla {@code "[KEY] Açıklama"} formatında listeye döndürür.
     *
     * <p>DSS validation pipeline'ı (bkz.
     * <code>ChainItem.recordConstraint</code>) her FAIL constraint için
     * {@link XmlConstraint#getError()} alanına {@code I18nProvider} ile
     * (varsayılan {@code Locale.ENGLISH}) doldurulmuş hazır mesaj
     * yerleştirir. Bu helper o mesajları opaque BBB key'leriyle birlikte
     * toplayıp <code>SignatureInfo.validationErrors</code> listesine
     * eklenmek üzere döndürür — operatör/son kullanıcı
     * "BBB_XCV_ISCGKU" gibi bir kodun ne demek olduğunu (örn.
     * <em>"The certificate does not have an expected key-usage!"</em>)
     * tek bakışta görür.</p>
     *
     * <h3>Hangi bloklar gezilir?</h3>
     * <ul>
     *   <li><code>FC</code>  — Format Checks (signature format/byterange)</li>
     *   <li><code>ISC</code> — Identification of Signing Certificate</li>
     *   <li><code>VCI</code> — Validation Context Initialization</li>
     *   <li><code>CV</code>  — Cryptographic Verification (digest/refs)</li>
     *   <li><code>SAV</code> — Signed Attributes Validation</li>
     *   <li><code>XCV</code> — X.509 Certificate Validation
     *       (top-level + her <code>SubXCV</code> katmanı)</li>
     *   <li><code>PSV</code> — Past Signature Validation (LTV/LTA)</li>
     * </ul>
     *
     * <h3>Format ve dedup</h3>
     * <ul>
     *   <li>Mesaj satırı: <code>[BBB_KEY] error.value</code>. Eğer DSS
     *       <code>error.value</code> doldurmamışsa
     *       <code>name.value</code> (constraint başlığı, örn. soru
     *       cümlesi) fallback olarak kullanılır.</li>
     *   <li>Constraint
     *       <code>additionalInfo</code> alanı doluysa (örn. CN, serial,
     *       expiry tarihi vb. ekleme) " — " ile birleştirilir.</li>
     *   <li>Aynı satır birden fazla kez eklenmez (LinkedHashSet ile
     *       sıra korunur, tekrarlar elenir).</li>
     * </ul>
     *
     * <h3>Locale</h3>
     * <p>DSS pipeline'ı default <code>Locale.ENGLISH</code> ile
     * I18nProvider'ı kuruyor; mesajlar İngilizce gelir. Türkçeleştirme
     * gerekiyorsa custom <code>I18nProvider(Locale)</code> + properties
     * override yolu izlenebilir; bu helper aynı çıktıyı kullanır.
     * dss-i18n 6.3 jar'ı yalnızca <code>dss-messages.properties</code>
     * (English) sağlar — bkz. dss-validation transitive dependency.</p>
     *
     * <p>Defansif: introspection patlarsa boş liste döner; çağıran tarafa
     * yalnızca jenerik "İmza geçersiz: ..." satırı kalır.</p>
     */
    List<String> collectFailingBbbConstraintMessages(DetailedReport detailedReport, String signatureId) {
        List<FailedConstraint> details = collectFailingBbbConstraintDetails(detailedReport, signatureId);
        List<String> out = new ArrayList<>(details.size());
        for (FailedConstraint d : details) {
            StringBuilder sb = new StringBuilder();
            if (d.getKey() != null && !d.getKey().isEmpty()) {
                sb.append('[').append(d.getKey()).append("] ");
            }
            sb.append(d.getMessage() != null ? d.getMessage() : "(constraint failed)");
            out.add(sb.toString());
        }
        return out;
    }

    /**
     * DSS DetailedReport içindeki BBB blok kimliği — sınıflandırmada
     * <em>hangi katmandan</em> geldiğimizi takip etmek için. Frontend'e
     * sızdırmıyoruz; yalnız {@link #classifyFailure} için iç durum.
     */
    private enum BbbBlockKind { FC, ISC, VCI, CV, SAV, XCV_TOP, SUB_XCV, PSV }

    /**
     * XCV-top bloğunda <em>summary roll-up</em> rolü oynayan constraint
     * key'leri. Bu key'ler SubXCV'lerden biri NOT_OK olduğunda <em>otomatik
     * NOT_OK</em> olur — yeni bilgi taşımaz, kategori
     * {@link FailureCategory#DERIVED} olarak işaretlenir.
     *
     * <p>Liste muhafazakâr: yalnız ETSI EN 319 102-1 / DSS 6.3 sözleşmesinde
     * kesin roll-up rolü olduğu bilinen iki anahtar. Yeni adaylar tespit
     * edilirse buraya eklenmeden önce DSS source'ta semantiği doğrulanmalı
     * (yanlış pozitif → frontend gerçek bir failure'ı gizler).</p>
     */
    private static final Set<String> XCV_ROLL_UP_KEYS;
    static {
        Set<String> rollUps = new HashSet<>();
        rollUps.add("BBB_XCV_SUB");      // "Is the SubXCV conclusion valid?"
        rollUps.add("BBB_XCV_ICTIVRSC"); // "Is cert chain trusted in validation root system cert?"
        XCV_ROLL_UP_KEYS = Collections.unmodifiableSet(rollUps);
    }

    /**
     * DSS DetailedReport'taki BBB <em>FAIL</em> constraint'lerini yapısal
     * {@link FailedConstraint} listesi olarak toplar — her satır
     * {@link FailureCategory} ile etiketlenmiş halde:
     * {@link FailureCategory#ROOT_CAUSE},
     * {@link FailureCategory#DERIVED} (XCV-top summary roll-up),
     * {@link FailureCategory#CASCADE} (SAV/CV downstream yan ürün).
     *
     * <h3>API kontratındaki rolü</h3>
     * <p>Bu liste iki ayrı görünüm için kullanılır:</p>
     * <ul>
     *   <li>{@link SignatureInfo#getRootCause() rootCause} (default, her zaman):
     *       Listeden {@link #selectRootCause} ile {@code ROOT_CAUSE}
     *       kategorisindeki <em>ilk</em> satır seçilir. Frontend dispatch
     *       ve operatör eylem mesajı için. Liste içeriği response'a
     *       eklenmez.</li>
     *   <li>{@link SignatureInfo#getFailedConstraints() failedConstraints}
     *       (opt-in, {@code ?includeFailedConstraints=true}): Listenin
     *       tamamı — tüm kategoriler dahil — response'a eklenir. Audit,
     *       forensic, "neden bu satır seçildi?" gibi sorular için.</li>
     * </ul>
     *
     * <h3>Sınıflandırma kuralları</h3>
     * <ul>
     *   <li><b>XCV roll-up → DERIVED</b>: XCV-top bloğundaki
     *       {@code BBB_XCV_SUB} / {@code BBB_XCV_ICTIVRSC} gibi summary
     *       constraint'ler — eğer SubXCV'lerden biri zaten NOT_OK ise
     *       (üst-blok yalnız alt-bloğun yansımasıdır, yeni bilgi taşımaz).</li>
     *   <li><b>SAV/CV cascade → CASCADE</b>: SAV/CV bloklarındaki NOT_OK
     *       constraint'ler — eğer XCV bloğunun {@code Conclusion.Indication}'ı
     *       INDETERMINATE/FAILED ise (sertifika context'i kullanılamaz
     *       hale gelmiş; bu blokların "kontrol edilemedi" üretmesi
     *       doğal yan ürün).</li>
     *   <li><b>Diğer her şey → ROOT_CAUSE</b>: SubXCV içindeki specific
     *       check (KeyUsage, expiry, revocation), FC bloğunda format
     *       failure, CV'de bağımsız reference hash mismatch (XCV
     *       başarılıyken), PSV/FC/ISC/VCI bloklarındaki bağımsız NOT_OK
     *       constraint'ler.</li>
     * </ul>
     *
     * <h3>Davranış</h3>
     * <ul>
     *   <li>Gezilen bloklar: FC, ISC, VCI, CV, SAV, XCV (top-level + her
     *       SubXCV katmanı), PSV.</li>
     *   <li>{@code XmlConstraint.error.value} (i18n çeviriden gelir) →
     *       {@code XmlConstraint.name.value} (soru cümlesi) sırasıyla
     *       fallback. Hiçbiri yoksa <code>"(constraint failed)"</code>
     *       sentetik mesajı kullanılır.</li>
     *   <li>{@code additionalInfo} doluysa mesaja " — " ile eklenir.</li>
     *   <li>Aynı (key, message) çifti birden fazla kez yer almaz
     *       (LinkedHashSet dedup, sıra korunur).</li>
     *   <li>Sıra deterministik: BBB gezme sırası (FC → ISC → VCI → CV →
     *       SAV → XCV-top → SubXCV[0..n] → PSV).</li>
     *   <li>Defansif: introspection patlarsa boş liste döner.</li>
     * </ul>
     *
     * <h3>Locale</h3>
     * <p>{@code message} alanı, validator'a {@code setLocale(...)} ile
     * geçirilen Locale ile (default <code>tr</code>) doldurulur. TR
     * çevirimiz {@code dss-messages_tr.properties}; eksik anahtarlar DSS
     * jar default'una (İngilizce) fallback eder. {@code key} her zaman
     * stabil DSS kodu, locale'den bağımsız.</p>
     */
    List<FailedConstraint> collectFailingBbbConstraintDetails(DetailedReport detailedReport, String signatureId) {
        if (detailedReport == null || signatureId == null) {
            return new ArrayList<>();
        }
        LinkedHashSet<String> seenKeys = new LinkedHashSet<>();
        List<FailedConstraint> all = new ArrayList<>();
        try {
            for (XmlBasicBuildingBlocks bbb :
                    detailedReport.getJAXBModel().getBasicBuildingBlocks()) {
                if (!signatureId.equals(bbb.getId())) {
                    continue;
                }
                // Bu BBB için filter context'i — XCV bloğu ile SAV/CV
                // bloklarının roll-up/cascade tespiti için bir kez
                // hesaplanır, tüm appendFailureDetails çağrılarına geçer.
                XmlXCV xcv = bbb.getXCV();
                boolean xcvHasSubFailure = hasAnySubXcvFailure(xcv);
                boolean xcvIndeterminateOrFailed = isIndeterminateOrFailed(xcv);

                appendFailureDetails(all, seenKeys, bbb.getFC(),  BbbBlockKind.FC,  xcvHasSubFailure, xcvIndeterminateOrFailed);
                appendFailureDetails(all, seenKeys, bbb.getISC(), BbbBlockKind.ISC, xcvHasSubFailure, xcvIndeterminateOrFailed);
                appendFailureDetails(all, seenKeys, bbb.getVCI(), BbbBlockKind.VCI, xcvHasSubFailure, xcvIndeterminateOrFailed);
                appendFailureDetails(all, seenKeys, bbb.getCV(),  BbbBlockKind.CV,  xcvHasSubFailure, xcvIndeterminateOrFailed);
                appendFailureDetails(all, seenKeys, bbb.getSAV(), BbbBlockKind.SAV, xcvHasSubFailure, xcvIndeterminateOrFailed);
                if (xcv != null) {
                    appendFailureDetails(all, seenKeys, xcv, BbbBlockKind.XCV_TOP, xcvHasSubFailure, xcvIndeterminateOrFailed);
                    if (xcv.getSubXCV() != null) {
                        for (XmlSubXCV sub : xcv.getSubXCV()) {
                            appendFailureDetails(all, seenKeys, sub, BbbBlockKind.SUB_XCV, xcvHasSubFailure, xcvIndeterminateOrFailed);
                        }
                    }
                }
                appendFailureDetails(all, seenKeys, bbb.getPSV(), BbbBlockKind.PSV, xcvHasSubFailure, xcvIndeterminateOrFailed);
                break;
            }
        } catch (Exception e) {
            logger.debug("BBB constraint detail enrichment hatası ({}): {}",
                    signatureId, e.getMessage());
            return new ArrayList<>();
        }
        return all;
    }

    /**
     * Verilen blok içindeki {@link XmlStatus#NOT_OK} constraint'leri
     * {@link #classifyFailure} ile kategori atanmış halde {@code out}
     * listesine ekler. {@code block} <code>null</code> ise no-op.
     */
    private static void appendFailureDetails(
            List<FailedConstraint> out,
            LinkedHashSet<String> seenKeys,
            XmlConstraintsConclusion block,
            BbbBlockKind kind,
            boolean xcvHasSubFailure,
            boolean xcvIndeterminateOrFailed) {
        if (block == null || block.getConstraint() == null) {
            return;
        }
        for (XmlConstraint c : block.getConstraint()) {
            if (c == null || c.getStatus() != XmlStatus.NOT_OK) {
                continue;
            }
            String key = c.getName() != null ? c.getName().getKey() : null;
            String baseMessage = preferred(c.getError(), c.getName());
            if (baseMessage == null) {
                baseMessage = "(constraint failed)";
            }
            String additional = c.getAdditionalInfo();
            String message = baseMessage;
            if (additional != null && !additional.trim().isEmpty()) {
                message = baseMessage + " — " + additional.trim();
            }
            // Dedup anahtarı: hem key hem message dahil; aynı KEY iki farklı
            // additionalInfo ile gelmiş olabilir (örn. iki ayrı sertifika
            // için BBB_XCV_ISCGKU), bu durumda iki giriş de korunmalı.
            String dedupKey = (key == null ? "" : key) + "|" + message;
            if (!seenKeys.add(dedupKey)) {
                continue;
            }
            FailureCategory category =
                    classifyFailure(key, kind, xcvHasSubFailure, xcvIndeterminateOrFailed);
            out.add(new FailedConstraint(key, message, category));
        }
    }

    /**
     * Bir constraint'in DSS failure zincirindeki rolünü
     * {@link FailureCategory} olarak belirler. Sınıflandırma muhafazakâr:
     * yanlış pozitif derive/cascade gerçek bir kök nedeni
     * {@code rootCause} seçiminde gizleyebileceği için, yalnız
     * <em>kesin</em> pattern'ler ROOT_CAUSE dışında bir kategoriye düşer.
     *
     * <ol>
     *   <li><b>DERIVED</b>: XCV-top bloğunda + key
     *       {@link #XCV_ROLL_UP_KEYS} listesinde + SubXCV'lerden biri zaten
     *       NOT_OK. Bu summary üst-blok yalnız alt-bloğun yansımasıdır.</li>
     *   <li><b>CASCADE</b>: SAV veya CV bloğunda + XCV bloğunun
     *       Conclusion.Indication INDETERMINATE/FAILED. Sertifika context'i
     *       kullanılamadığı için bu blokların "kontrol edilemedi" tipi
     *       NOT_OK üretmesi doğal.</li>
     *   <li><b>ROOT_CAUSE</b> (default): Diğer her şey — SubXCV içindeki
     *       specific check, FC/ISC/VCI/PSV bağımsız failure'lar, XCV-top'un
     *       whitelist dışı key'leri, vb.</li>
     * </ol>
     */
    private static FailureCategory classifyFailure(
            String key,
            BbbBlockKind kind,
            boolean xcvHasSubFailure,
            boolean xcvIndeterminateOrFailed) {
        if (kind == BbbBlockKind.XCV_TOP
                && xcvHasSubFailure
                && key != null
                && XCV_ROLL_UP_KEYS.contains(key)) {
            return FailureCategory.DERIVED;
        }
        if ((kind == BbbBlockKind.SAV || kind == BbbBlockKind.CV)
                && xcvIndeterminateOrFailed) {
            return FailureCategory.CASCADE;
        }
        return FailureCategory.ROOT_CAUSE;
    }

    /**
     * SubXCV blok'larının herhangi birinde en az bir {@link XmlStatus#NOT_OK}
     * constraint var mı? XCV-top'taki summary roll-up'ı tetikleyen koşul.
     * {@code xcv} <code>null</code> veya SubXCV listesi boşsa <code>false</code>.
     */
    private static boolean hasAnySubXcvFailure(XmlXCV xcv) {
        if (xcv == null || xcv.getSubXCV() == null) {
            return false;
        }
        for (XmlSubXCV sub : xcv.getSubXCV()) {
            if (sub == null || sub.getConstraint() == null) {
                continue;
            }
            for (XmlConstraint c : sub.getConstraint()) {
                if (c != null && c.getStatus() == XmlStatus.NOT_OK) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Verilen XCV bloğunun {@code Conclusion.Indication}'ı INDETERMINATE
     * veya FAILED mi? SAV/CV bloklarının cascade tespiti için —
     * sertifika context'i kullanılamaz hale geldiğinde bu blokların
     * "kontrol edilemedi" şekilde NOT_OK üretmesi normal.
     *
     * <p>{@code xcv} <code>null</code> veya {@code Conclusion} yoksa
     * <code>false</code>: cascade flag'i konservatif kapalı kalır,
     * marjinal failure'lar ROOT_CAUSE olarak görünür (yanlış pozitif
     * cascade'den daha az zararlı).</p>
     */
    private static boolean isIndeterminateOrFailed(XmlXCV xcv) {
        if (xcv == null || xcv.getConclusion() == null) {
            return false;
        }
        Indication ind = xcv.getConclusion().getIndication();
        return ind == Indication.INDETERMINATE
                || ind == Indication.FAILED
                || ind == Indication.TOTAL_FAILED;
    }

    /**
     * Tercih sırası: <code>error.value</code> (insan-okur açıklama, örn.
     * <em>"The certificate does not have an expected key-usage!"</em>) →
     * <code>name.value</code> (soru cümlesi, örn. <em>"Does the certificate
     * have an expected key-usage?"</em>) → <code>null</code>. DSS i18n
     * provider mesajı doldurmadıysa fallback ile en azından bir bağlam
     * sunarız.
     */
    private static String preferred(XmlMessage error, XmlMessage name) {
        if (error != null && error.getValue() != null && !error.getValue().isEmpty()) {
            return error.getValue();
        }
        if (name != null && name.getValue() != null && !name.getValue().isEmpty()) {
            return name.getValue();
        }
        return null;
    }

    /**
     * Signature wrapper'dan detaylı bilgi çıkarır
     *
     * @param detailedReport DSS DetailedReport — timestamp BBB blokları
     *        gezilirken kullanılır (rootCause + opt-in failedConstraints
     *        her timestamp için imza simetrisinde doldurulur).
     * @param includeFailedConstraints opt-in flag — true ise her timestamp
     *        için kategorize FAIL listesi {@code TimestampInfo.failedConstraints}
     *        alanına yazılır (boş bile olsa).
     */
    private void processSignatureWrapper(
            SignatureInfo sigInfo,
            SignatureWrapper signatureWrapper,
            VerificationLevel level,
            DetailedReport detailedReport,
            boolean includeFailedConstraints) {

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

        // İmzayı üreten kriptografik algoritmalar — DSS DiagnosticData'dan
        // doğrudan okunur. İki ayrı alan döneriz ki istemci "belge nasıl
        // özetlenmiş + nasıl imzalanmış" sorusuna tek bakışta cevap alsın:
        //
        //   signatureAlgorithm  → encryption + digest kombinasyonu
        //                          (örn. RSA_SHA256, ECDSA_SHA384). DSS
        //                          {@link SignatureAlgorithm} enum sabit
        //                          ismi — machine-readable, stabil API.
        //   digestAlgorithm     → ds:SignedInfo'da kullanılan özet
        //                          algoritması (örn. SHA256). Audit ve
        //                          kriptografik politika kontrolleri için
        //                          tek başına da gerekir.
        //
        // ÖNEMLİ: Buradaki signatureAlgorithm imzanın kendisinin
        // algoritmasıdır (signer'ın belgeyi nasıl imzaladığı). Bu,
        // {@link CertificateInfo#getSignatureAlgorithm()}'dan farklıdır —
        // o sertifikayı CA'nın hangi algoritmayla imzaladığını söyler.
        SignatureAlgorithm sigAlg = signatureWrapper.getSignatureAlgorithm();
        if (sigAlg != null) {
            sigInfo.setSignatureAlgorithm(sigAlg.name());
        } else {
            // Bazı eksik DiagnosticData kayıtlarında kompozit dönmeyebilir;
            // bu durumda encryption + digest'i ayrı ayrı birleştirip kompakt
            // bir gösterim üretiriz ("RSA_SHA256" formatı korunsun).
            EncryptionAlgorithm enc = signatureWrapper.getEncryptionAlgorithm();
            DigestAlgorithm dig = signatureWrapper.getDigestAlgorithm();
            if (enc != null && dig != null) {
                sigInfo.setSignatureAlgorithm(enc.name() + "_" + dig.name());
            } else if (enc != null) {
                sigInfo.setSignatureAlgorithm(enc.name());
            }
        }
        DigestAlgorithm digestAlg = signatureWrapper.getDigestAlgorithm();
        if (digestAlg != null) {
            sigInfo.setDigestAlgorithm(digestAlg.getName());
        }

        // Sertifika bilgileri
        CertificateWrapper signingCert = signatureWrapper.getSigningCertificate();
        if (signingCert != null) {
            sigInfo.setSignerCertificate(extractCertificateInfo(signingCert));
        }

        // Timestamp bilgileri
        List<TimestampWrapper> timestamps = signatureWrapper.getTimestampList();
        if (timestamps != null && !timestamps.isEmpty()) {
            sigInfo.setTimestampInfo(extractTimestampInfo(
                    timestamps.get(0), detailedReport, includeFailedConstraints));
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
     * Timestamp bilgilerini çıkarır.
     *
     * <p>Imza tarafıyla simetrik kontrat: DSS DetailedReport'taki timestamp
     * BBB bloğunu gezer, FAIL constraint'leri kategorize eder; tek bir
     * {@link FailedConstraint} <em>kök neden</em> {@code rootCause} alanına
     * yazılır, opt-in açıkken tüm liste {@code failedConstraints}'e
     * (boş olsa bile — frontend "alan istendi mi?" sınamasından kurtulur).</p>
     *
     * <h3>Timestamp BBB ID semantiği</h3>
     * <p>DSS DetailedReport'ta her timestamp için ayrı bir
     * {@link XmlBasicBuildingBlocks} entry'si var; {@code Id} alanı
     * {@link TimestampWrapper#getId() timestampWrapper.getId()} ile
     * birebir eşleşir. {@code collectFailingBbbConstraintDetails} helper'ı
     * imza vs timestamp ayrımı yapmıyor — sadece eşleşen ID için BBB
     * blokları gezer; aynı sınıflandırma kuralları (XCV roll-up DERIVED,
     * SAV/CV cascade CASCADE) timestamp tarafında da geçerli.</p>
     *
     * @param detailedReport DSS DetailedReport — timestamp BBB bloğunu
     *        bulmak için. <code>null</code> ise rootCause/failedConstraints
     *        doldurulmaz (imza tarafıyla aynı best-effort kontratı).
     * @param includeFailedConstraints opt-in flag — true ise kategorize
     *        liste her timestamp için yazılır (boş bile olsa).
     */
    private TimestampInfo extractTimestampInfo(
            TimestampWrapper timestampWrapper,
            DetailedReport detailedReport,
            boolean includeFailedConstraints) {
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

        // BBB FAIL constraint analizi — imza tarafıyla bire bir simetrik.
        // DetailedReport null ise (defansif) hiçbir alan doldurulmaz;
        // rootCause/failedConstraints null kalır, NON_NULL ile JSON'a
        // yazılmaz. Liste boş çıkarsa rootCause null kalır (timestamp
        // VALID veya BBB pipeline'ı temiz). includeFailedConstraints açıksa
        // boş liste de set edilir → frontend opt-in'i "alan ile" doğrular.
        if (detailedReport != null && timestampWrapper.getId() != null) {
            List<FailedConstraint> tsFailures = collectFailingBbbConstraintDetails(
                    detailedReport, timestampWrapper.getId());
            tsInfo.setRootCause(selectRootCause(tsFailures));
            if (includeFailedConstraints) {
                tsInfo.setFailedConstraints(tsFailures);
            }
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
     * @param trToleranceApplied TR-özel XAdES <em>suppression</em> bu imzaya
     *        uygulandıysa <code>true</code>. Bu durumda DSS'in raporladığı
     *        SIG_CONSTRAINTS_FAILURE artık <em>hata</em> değil, açıklayıcı bir
     *        uyarıdır — istemciyi yanıltmamak için validationErrors yerine
     *        validationWarnings'e taşırız.
     * @param trSuppression uygulanan suppression objesi (null olabilir).
     *        Warning metnindeki kod değerini bastırmak için.
     * @param trRejection uygulanan rejection objesi (null olabilir). Verdict
     *        değişmez; validationErrors içine kataloglu Mersel rejection
     *        koduyla zenginleştirilmiş satır eklenir (operatör DSS jenerik
     *        SIG_CONSTRAINTS_FAILURE'ından öte Türkiye-spesifik patolojiyi
     *        tek bakışta görsün).
     */
    private void collectErrorsAndWarnings(
            SignatureInfo sigInfo,
            SimpleReport simpleReport,
            DetailedReport detailedReport,
            String signatureId,
            boolean trToleranceApplied,
            AppliedSuppression trSuppression,
            AppliedRejection trRejection,
            boolean includeFailedConstraints) {

        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        // BBB FAIL constraint'lerinin yapısal, kategorize listesi —
        // {key, message, category} objeleri. rootCause seçimi için her
        // zaman hesaplanır; failedConstraints alanına yalnız
        // includeFailedConstraints=true ise yazılır.
        List<FailedConstraint> failedConstraints = new ArrayList<>();

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

            // BBB constraint enrichment — yapısal kanal (failedConstraints).
            // DSS pipeline'ı I18nProvider ile XmlConstraint.error.value
            // alanını configured locale ile (default tr) doldurmuş halde
            // veriyor; biz {key, message} olarak ayrı ayrı yansıtıyoruz.
            // Frontend bu kodlar üzerinden doğrudan dispatch yapabilir;
            // regex parse gereksiz.
            failedConstraints.addAll(
                    collectFailingBbbConstraintDetails(detailedReport, signatureId));
        }

        // TR-özel rejection devrede mi? Verdict değişmez, ama DSS'in jenerik
        // SubIndication mesajının yanına Mersel kataloglu tanı kodunu da
        // ekliyoruz ki operatör log/grep ile hızlıca filtreleyebilsin.
        if (trRejection != null && trRejection.getCode() != null) {
            errors.add("[" + trRejection.getCode() + "] " + trRejection.getReason());
        }

        // SubIndication kontrolü
        SubIndication subIndication = simpleReport.getSubIndication(signatureId);
        if (subIndication != null) {
            if (trToleranceApplied && subIndication == SubIndication.SIG_CONSTRAINTS_FAILURE) {
                // TR-özel suppression devrede: DSS'in SIG_CONSTRAINTS_FAILURE'ı
                // jenerik bir kriptografik hata değil, KamuSM/GİB üreticisinin
                // yapısal Type URI varyantı. Operatör/istemci için anlaşılır
                // bir uyarıya çevir; tam audit detayı sigInfo.appliedSuppressions
                // altında.
                String code = trSuppression != null && trSuppression.getCode() != null
                        ? trSuppression.getCode()
                        : SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getCode();
                String detail = "İmza, KamuSM/GİB ekosistemine özgü XAdES "
                        + "SignedProperties Type URI yazım hatası içeriyor "
                        + "(\"…/v1.3.2/XAdES.xsd#SignedProperties\"). "
                        + "Kriptografik bütünlük doğrulandı; tolerans uygulandı.";
                warnings.add("[" + code + "] " + detail);
            } else if (trRejection != null && subIndication == SubIndication.SIG_CONSTRAINTS_FAILURE) {
                // Rejection enrichment devrede: Mersel kataloglu satır zaten
                // yukarıda eklendi. Jenerik "(Kritik hata)" satırını eklemek
                // operatöre aynı sorun için ikinci bir hata satırı gösterir
                // ve "kaç hata var?" sayımını yanıltır; bu yüzden atlanır.
                logger.debug("SIG_CONSTRAINTS_FAILURE detail line suppressed because "
                        + "Mersel rejection code is already in validationErrors "
                        + "(signatureId={}, code={}).", signatureId, trRejection.getCode());
            } else {
                String subIndicationMsg = "İmza uyarısı: " + subIndication.name();

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
        // Tek kök neden — DSS pipeline'ının ürettiği failure zincirinden
        // category=ROOT_CAUSE satırı (yoksa defansif fallback ile ham
        // listenin ilki). Liste tamamen boşsa null — JSON'a yazılmaz
        // (NON_NULL).
        sigInfo.setRootCause(selectRootCause(failedConstraints));
        // Opt-in: tüm kategorize liste (ROOT_CAUSE + DERIVED + CASCADE).
        // Default kapalı — alan null kalır, JSON'a yazılmaz. Opt-in
        // ?includeFailedConstraints=true geldiğinde alan deterministik
        // olarak set edilir — liste boş olsa bile (örn. VALID imza). Bu
        // sayede frontend "alan istendi mi?" sınamasından kurtulur:
        // alan varsa opt-in onaylandı; boş array olması "FAIL constraint
        // yok" anlamına gelir.
        if (includeFailedConstraints) {
            sigInfo.setFailedConstraints(failedConstraints);
        }
    }

    /**
     * BBB FAIL constraint listesinden tek bir <em>kök neden</em> seçer.
     *
     * <p>Algoritma:</p>
     * <ol>
     *   <li>{@link FailureCategory#ROOT_CAUSE} kategorisindeki ilk
     *       satırı döndür (DSS gezme sırasında deterministik:
     *       FC → ISC → VCI → CV → SAV → XCV-top → SubXCV[0..n] → PSV).</li>
     *   <li>Hiç ROOT_CAUSE yoksa (DSS yeni sürümünde whitelist eksik
     *       veya beklenmeyen blok ilişkisi → tüm satırlar DERIVED/CASCADE
     *       sınıflanmış), defansif fallback: listenin ilk elemanını döndür.
     *       Operatör hiçbir zaman bilgisiz kalmaz.</li>
     * </ol>
     *
     * <p>Birden fazla gerçek kök neden varsa (örn. signer + counter signer
     * sertifikalarında ayrı ayrı KeyUsage failure) operatör tüm pipeline
     * detayını {@code ?includeFailedConstraints=true} parametresi ile
     * {@link SignatureInfo#getFailedConstraints() failedConstraints}
     * alanından alabilir. Tek bir {@code rootCause} alanı UX odaklı
     * sade kontratı korur.</p>
     *
     * @param failedConstraints kategorize edilmiş BBB FAIL listesi
     * @return ROOT_CAUSE'lardan ilki, yoksa listenin ilki, liste boş/null ise null
     */
    private static FailedConstraint selectRootCause(List<FailedConstraint> failedConstraints) {
        if (failedConstraints == null || failedConstraints.isEmpty()) {
            return null;
        }
        for (FailedConstraint fc : failedConstraints) {
            if (fc != null && fc.getCategory() == FailureCategory.ROOT_CAUSE) {
                return fc;
            }
        }
        // Defansif fallback — sınıflandırma her şeyi DERIVED/CASCADE
        // saydı (DSS yeni sürümünde whitelist eksik ya da beklenmeyen
        // blok ilişkisi). Bilgi kaybetmektense ilk satırı göster;
        // bir sonraki sürümde whitelist genişletilebilir.
        return failedConstraints.get(0);
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

