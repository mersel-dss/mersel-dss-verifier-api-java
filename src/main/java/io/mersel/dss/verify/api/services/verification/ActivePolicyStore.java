package io.mersel.dss.verify.api.services.verification;

import io.mersel.dss.verify.api.exceptions.PolicyActivationException;
import io.mersel.dss.verify.api.exceptions.VerificationException;
import io.mersel.dss.verify.api.models.ActivePolicy;
import io.mersel.dss.verify.api.models.PolicyContext;
import org.apache.commons.codec.digest.DigestUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Sunucunun etkin doğrulama politikası (process-local, bellek içi).
 *
 * <p>Başlangıçta {@code dss.policy.path} / {@code dss.policy.profile} yapılandırmasını yansıtır
 * ({@code origin=CONFIGURATION}); POST /api/v1/policy/active ile değiştirildiğinde
 * ({@code origin=API}) sonraki tüm imza doğrulamaları yeni politikayı kullanır. Yeniden başlatma
 * yapılandırmaya döner. {@code policyId} örneğe özgü bir revizyon kimliğidir
 * ({@code <instance-uuid>:<revision>}); her etkinleştirmede ve her yeniden başlatmada değişir,
 * eski kimlikle yapılan etkinleştirme {@link PolicyActivationException#conflict()} ile reddedilir.</p>
 *
 * <p><b>Feature flag:</b> etkinleştirme yalnız {@code POLICY_ACTIVATION_ENABLED=true}
 * ({@code dss.policy.activation-enabled}) ile açılır; varsayılan kapalıdır ve başka hiçbir ayar
 * (evaluation profili, {@code REQUEST_TRUST_ENABLED}) açmaz. <b>Prod ortamında kesinlikle
 * kullanmayın</b> — bu özellik yalnız TÜBİTAK Uyum Değerlendirme sürecindeki deployment'lar için
 * geliştirilmiştir. Açıkken başlangıçta WARN loglanır.</p>
 *
 * <p>Her doğrulama {@link #snapshot()} ile değişmez bir kopya alır; eşzamanlı bir etkinleştirme
 * devam eden isteğin politikasını (XML, özet, kimlik) karıştırmaz. GET /api/v1/policy/active/xml
 * de gövdeyi ve başlıkları tek bir {@link #currentSnapshot()} sonucundan üretir.</p>
 *
 * <p>Yapılandırmadaki politika ilk ihtiyaçta yüklenir: {@code /info} kaynağı açmaz, explicit
 * {@code dss.policy.path} erişilemezse servis yine ayağa kalkar ve doğrulamalar bugünkü gibi
 * {@link VerificationException} ile fail-fast olur (sessiz fallback yok); kaynak düzelince sonraki
 * istek yükler.</p>
 *
 * <p><b>Hata durumu</b> (yapılandırma yüklenemedi, henüz hiçbir politika etkin değil): GET
 * {@code 503 POLICY_UNAVAILABLE} döner ve gövdesinde güncel {@code policyId} ile
 * {@code activationEnabled} bulunur. İstemci bu kimlikle BUILT_IN / CUSTOM_XML etkinleştirerek veya
 * düzeltilmiş dosyayı CONFIGURED ile yeniden yükleyerek kurtarabilir; o ana kadar doğrulamalar
 * fail-fast kalır. Dosya kendiliğinden düzelip ilk istekte yüklenirse yeni bir revizyon alır;
 * hata durumunu görmüş bir istemcinin bayat kurtarma isteği böylece 409 ile reddedilir.</p>
 */
@Component
public class ActivePolicyStore {
    private static final Logger logger = LoggerFactory.getLogger(ActivePolicyStore.class);

    public static final int DEFAULT_MAX_BYTES = 1024 * 1024;
    public static final int MAX_NAME_LENGTH = 120;
    public static final String PROFILE_CUSTOM = "custom";
    public static final String SOURCE_BUILT_IN = "BUILT_IN";
    public static final String SOURCE_CUSTOM_XML = "CUSTOM_XML";
    public static final String ORIGIN_CONFIGURATION = "CONFIGURATION";
    public static final String ORIGIN_API = "API";
    public static final String DEFAULT_CUSTOM_NAME = "Özel politika";
    /** Adı verilmemiş özel XML ve {@code dss.policy.path} için indirme adı (sunucu yolu asla kullanılmaz). */
    public static final String DEFAULT_FILE_NAME = "active-policy.xml";
    static final int MAX_FILE_NAME_BASE_LENGTH = 80;
    private static final String RESOURCE_FILE_TEMPLATE = "kamusm-%s-constraint.xml";
    private static final String RESOURCE_TEMPLATE = "classpath:policy/" + RESOURCE_FILE_TEMPLATE;
    private static final Pattern XML_DECLARATION_ENCODING =
            Pattern.compile("^<\\?xml[^>]*?\\sencoding\\s*=\\s*[\"']([A-Za-z][A-Za-z0-9._-]*)[\"']");
    private static final Map<String, String> BUILT_IN_NAMES;
    static {
        Map<String, String> names = new LinkedHashMap<>();
        names.put(AdvancedSignatureVerificationService.PROFILE_SIGNER_STRICT, "KamuSM Signer Strict");
        names.put(AdvancedSignatureVerificationService.PROFILE_STRICT, "KamuSM Strict");
        BUILT_IN_NAMES = Collections.unmodifiableMap(names);
    }

    private final String instanceId = UUID.randomUUID().toString();
    private final String configuredProfile;
    private final String configuredPath;
    private final ResourceLoader resourceLoader;
    private final int maxBytes;
    private final boolean activationEnabled;

    private long revision;
    private String activatedAt = Instant.now().toString();
    /** null: yapılandırmadaki politika henüz yüklenmedi (yalnız revision 0'da olabilir). */
    private volatile Snapshot current;
    /** current == null iken yapılandırma en az bir kez yüklenemedi (hata durumu görüldü). Kilit altında. */
    private boolean configuredLoadFailed;

    @Autowired
    public ActivePolicyStore(@Value("${dss.policy.profile:signer-strict}") String configuredProfile,
            @Value("${dss.policy.path:}") String configuredPath,
            ResourceLoader resourceLoader,
            @Value("${dss.policy.max-bytes:1048576}") int maxBytes,
            @Value("${dss.policy.activation-enabled:false}") boolean activationEnabled) {
        if (maxBytes <= 0) throw new IllegalArgumentException("dss.policy.max-bytes pozitif olmalıdır: " + maxBytes);
        this.configuredProfile = configuredProfile;
        this.configuredPath = configuredPath == null ? "" : configuredPath.trim();
        this.resourceLoader = resourceLoader;
        this.maxBytes = maxBytes;
        this.activationEnabled = activationEnabled;
        if (activationEnabled) {
            logger.warn("Çalışma anında politika etkinleştirme AÇIK (POLICY_ACTIVATION_ENABLED=true): "
                    + "POST /api/v1/policy/active sonraki tüm imza doğrulamalarının politikasını değiştirebilir. "
                    + "Prod ortamında kesinlikle kullanmayın; yalnız TÜBİTAK Uyum Değerlendirme sürecindeki "
                    + "deployment'lar için geliştirilmiştir.");
        }
    }

    public boolean isActivationEnabled() { return activationEnabled; }
    public int getMaxBytes() { return maxBytes; }

    /** Bir doğrulamanın kullanacağı politika. Yapılandırma yüklenemezse bugünkü {@link VerificationException}. */
    public Snapshot snapshot() {
        Snapshot snapshot = current;
        if (snapshot != null) return snapshot;
        synchronized (this) {
            if (current == null) current = loadInitial();
            return current;
        }
    }

    /** Kilit altında, current == null iken: yapılandırmadaki politikayı yükler; başarısızsa durum değişmez. */
    private Snapshot loadInitial() {
        Definition configured;
        try {
            configured = loadConfigured();
        } catch (VerificationException e) {
            configuredLoadFailed = true;
            throw e;
        }
        if (configuredLoadFailed) {
            // Hata durumu (policyId'si 503 ile istemcilere gösterilmiş olabilir) kendiliğinden düzeldi:
            // yeni revizyon, böylece o kimlikle gelen bayat bir kurtarma isteği düzelen politikanın üzerine yazmaz.
            configuredLoadFailed = false;
            revision++;
            activatedAt = Instant.now().toString();
            logger.info("Yapılandırmadaki doğrulama politikası artık yüklenebiliyor: policyId={}", id());
        }
        return new Snapshot(configured, id(), activatedAt, ORIGIN_CONFIGURATION);
    }

    /**
     * GET /api/v1/policy/active. Yapılandırma yüklenemiyorsa ve henüz hiçbir politika etkin değilse
     * {@code 503 POLICY_UNAVAILABLE}; hata, kurtarma için gereken güncel {@code policyId}'yi taşır.
     */
    public ActivePolicy current() {
        return currentSnapshot().toActivePolicy(activationEnabled);
    }

    /**
     * GET /api/v1/policy/active ve /api/v1/policy/active/xml için okunan değişmez snapshot. Hata durumu
     * {@link #current()} ile aynıdır ({@code 503 POLICY_UNAVAILABLE}, güncel {@code policyId} ile). Çağıran
     * XML'i ve kimlik/özet başlıklarını bu tek nesneden üretir; eşzamanlı etkinleştirme bunları karıştırmaz.
     */
    public Snapshot currentSnapshot() {
        Snapshot snapshot = current;
        if (snapshot != null) return snapshot;
        synchronized (this) {
            try {
                return snapshot();
            } catch (VerificationException e) {
                // Kilit altında: yükleme hatası ile bildirilen policyId aynı durumu gösterir.
                logger.warn("Etkin doğrulama politikası okunamadı: {}", e.getMessage());
                throw PolicyActivationException.unavailable(id(), activationEnabled, true);
            }
        }
    }

    /** /info {@code verificationPolicy}: {profile, source, fallbackApplied}; yapılandırma kaynağını açmaz. */
    public Map<String, Object> describe() {
        Snapshot snapshot = current;
        Map<String, Object> result = new LinkedHashMap<>();
        if (snapshot != null) {
            result.put("profile", snapshot.getProfile());
            result.put("source", snapshot.getSource());
            result.put("fallbackApplied", snapshot.isFallbackApplied());
        } else if (!configuredPath.isEmpty()) {
            result.put("profile", PROFILE_CUSTOM);
            result.put("source", SOURCE_CUSTOM_XML);
            result.put("fallbackApplied", false);
        } else {
            String requested = normalizedConfiguredProfile();
            boolean known = BUILT_IN_NAMES.containsKey(requested);
            result.put("profile", known ? requested : AdvancedSignatureVerificationService.PROFILE_SIGNER_STRICT);
            result.put("source", SOURCE_BUILT_IN);
            result.put("fallbackApplied", !known);
        }
        return result;
    }

    /** /info {@code policyCapabilities}. */
    public Map<String, Object> capabilities() {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("activationSupported", true);
        result.put("activationEnabled", activationEnabled);
        result.put("maxBytes", maxBytes);
        result.put("contentAvailable", true); // GET /api/v1/policy/active/xml
        return result;
    }

    public void requireActivationEnabled() {
        if (!activationEnabled) throw PolicyActivationException.disabled();
    }

    /** mode=BUILT_IN: paketle gelen profil XML'i. */
    public ActivePolicy activateBuiltIn(String expectedPolicyId, String profile) {
        requireActivationEnabled();
        if (profile == null || !BUILT_IN_NAMES.containsKey(profile)) {
            throw PolicyActivationException.invalid("profile şu değerlerden biri olmalıdır: "
                    + String.join(", ", BUILT_IN_NAMES.keySet()));
        }
        requireCurrent(expectedPolicyId);
        return commit(expectedPolicyId, builtIn(profile, false), ORIGIN_API);
    }

    /** mode=CUSTOM_XML: XXE-güvenli ayrıştırma + DSS şema doğrulamasından geçen XML. */
    public ActivePolicy activateCustom(String expectedPolicyId, byte[] xml, String policyName) {
        requireActivationEnabled();
        String name = displayName(policyName);
        if (xml == null || xml.length == 0) throw PolicyActivationException.invalid("policyXml dosyası boş olamaz.");
        if (xml.length > maxBytes) throw tooLarge();
        requireCurrent(expectedPolicyId);
        PolicyXmlValidator.validate(xml);
        String fileName = DEFAULT_CUSTOM_NAME.equals(name) ? DEFAULT_FILE_NAME : safeFileName(name);
        return commit(expectedPolicyId,
                new Definition(PROFILE_CUSTOM, SOURCE_CUSTOM_XML, name, fileName, xml.clone(), false), ORIGIN_API);
    }

    /**
     * mode=CONFIGURED: başlangıç yapılandırmasına (dss.policy.path / dss.policy.profile) döner.
     * Dosya hâlâ yüklenemiyorsa {@code 503 POLICY_UNAVAILABLE} ve durum değişmez (hata durumunda doğrulamalar
     * fail-fast kalır, aksi halde önceki etkin politika korunur).
     */
    public ActivePolicy restoreConfiguration(String expectedPolicyId) {
        requireActivationEnabled();
        requireCurrent(expectedPolicyId);
        Definition configured;
        try {
            configured = loadConfigured();
        } catch (VerificationException e) {
            logger.warn("Yapılandırmadaki doğrulama politikası yüklenemedi: {}", e.getMessage());
            synchronized (this) {
                boolean failedState = current == null;
                if (failedState) configuredLoadFailed = true;
                throw PolicyActivationException.unavailable(id(), activationEnabled, failedState);
            }
        }
        return commit(expectedPolicyId, configured, ORIGIN_CONFIGURATION);
    }

    public PolicyActivationException tooLarge() {
        return PolicyActivationException.invalid("Politika XML'i en fazla " + maxBytes + " bayt olabilir.");
    }

    private ActivePolicy commit(String expectedPolicyId, Definition next, String origin) {
        Snapshot activated;
        synchronized (this) {
            requireCurrent(expectedPolicyId);
            revision++;
            activatedAt = Instant.now().toString();
            activated = new Snapshot(next, id(), activatedAt, origin);
            current = activated;
            configuredLoadFailed = false; // hata durumundan (varsa) açık bir etkinleştirmeyle çıkıldı
        }
        logger.info("Doğrulama politikası etkinleştirildi: policyId={}, profile={}, source={}, origin={}, name='{}', sha256={}",
                activated.getPolicyId(), activated.getProfile(), activated.getSource(), activated.getOrigin(),
                activated.getName(), activated.getSha256());
        return activated.toActivePolicy(activationEnabled);
    }

    private synchronized void requireCurrent(String expectedPolicyId) {
        if (!id().equals(expectedPolicyId)) throw PolicyActivationException.conflict();
    }

    private String id() { return instanceId + ":" + revision; }

    private String normalizedConfiguredProfile() {
        return configuredProfile == null ? "" : configuredProfile.trim().toLowerCase(Locale.ROOT);
    }

    private static String displayName(String policyName) {
        if (policyName == null || policyName.trim().isEmpty()) return DEFAULT_CUSTOM_NAME;
        String name = policyName.trim();
        if (name.codePointCount(0, name.length()) > MAX_NAME_LENGTH) {
            throw PolicyActivationException.invalid("policyName en fazla " + MAX_NAME_LENGTH + " karakter olabilir.");
        }
        for (int i = 0; i < name.length(); i++) {
            if (Character.isISOControl(name.charAt(i))) {
                throw PolicyActivationException.invalid("policyName kontrol karakteri içeremez.");
            }
        }
        return name;
    }

    /**
     * Yapılandırmadaki politika. Mesajlar ve fail-fast davranışı eski
     * {@code AdvancedSignatureVerificationService#openValidationPolicyStream()} ile aynıdır.
     */
    private Definition loadConfigured() {
        if (!configuredPath.isEmpty()) {
            byte[] xml;
            try {
                Resource resource = resourceLoader.getResource(configuredPath);
                if (!resource.exists()) {
                    throw new VerificationException(
                            "dss.policy.path olarak verilen kaynak bulunamadı: "
                                    + configuredPath + ". Operatör explicit XML belirtti, "
                                    + "sessiz fallback yapılmıyor.");
                }
                try (InputStream in = resource.getInputStream()) {
                    xml = StreamUtils.copyToByteArray(in);
                }
            } catch (VerificationException ve) {
                throw ve;
            } catch (Exception e) {
                throw new VerificationException(
                        "dss.policy.path yüklenemedi (" + configuredPath + "): " + e.getMessage(), e);
            }
            logger.info("Using custom validation policy from dss.policy.path={}", configuredPath);
            return new Definition(PROFILE_CUSTOM, SOURCE_CUSTOM_XML, DEFAULT_CUSTOM_NAME, DEFAULT_FILE_NAME, xml, false);
        }
        String requested = normalizedConfiguredProfile();
        boolean known = BUILT_IN_NAMES.containsKey(requested);
        if (!known) {
            logger.warn("Bilinmeyen dss.policy.profile='{}' (geçerli değerler: {}). "
                            + "Default '{}' profiline düşülüyor.",
                    configuredProfile, BUILT_IN_NAMES.keySet(), AdvancedSignatureVerificationService.PROFILE_SIGNER_STRICT);
        }
        return builtIn(known ? requested : AdvancedSignatureVerificationService.PROFILE_SIGNER_STRICT, !known);
    }

    private Definition builtIn(String profile, boolean fallbackApplied) {
        String resourcePath = String.format(RESOURCE_TEMPLATE, profile);
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
            try (InputStream in = resource.getInputStream()) {
                byte[] xml = StreamUtils.copyToByteArray(in);
                logger.info("Using built-in validation policy profile '{}' ({})", profile, resourcePath);
                return new Definition(profile, SOURCE_BUILT_IN, BUILT_IN_NAMES.get(profile),
                        String.format(RESOURCE_FILE_TEMPLATE, profile), xml, fallbackApplied);
            }
        } catch (VerificationException ve) {
            throw ve;
        } catch (Exception e) {
            throw new VerificationException(
                    "Built-in policy profile XML'i okunamadı (" + resourcePath + "): " + e.getMessage(), e);
        }
    }

    /**
     * Görünen addan güvenli, ASCII bir indirme adı: Türkçe harfler ASCII karşılığına, diğer aksanlar
     * tabanına indirilir; harf/rakam/{@code _}/{@code -} dışındaki her dizi tek bir {@code -} olur (yol
     * ayırıcıları ve noktalar dahil), en fazla {@value #MAX_FILE_NAME_BASE_LENGTH} karakter + {@code .xml}.
     * Geriye bir şey kalmazsa {@link #DEFAULT_FILE_NAME}.
     */
    static String safeFileName(String displayName) {
        if (displayName == null) return DEFAULT_FILE_NAME;
        String base = displayName.trim();
        if (base.toLowerCase(Locale.ROOT).endsWith(".xml")) base = base.substring(0, base.length() - 4);
        // NFD ç/ğ/İ/ö/ş/ü'yü taban harf + birleşik işarete ayırır; noktasız ı ayrışmadığı için ayrıca eşlenir.
        base = Normalizer.normalize(base.replace('ı', 'i'), Normalizer.Form.NFD).replaceAll("\\p{M}+", "");
        base = base.replaceAll("[^A-Za-z0-9_-]+", "-").replaceAll("-{2,}", "-");
        if (base.length() > MAX_FILE_NAME_BASE_LENGTH) base = base.substring(0, MAX_FILE_NAME_BASE_LENGTH);
        base = base.replaceAll("^[-_]+|[-_]+$", "");
        return base.isEmpty() ? DEFAULT_FILE_NAME : base + ".xml";
    }

    /**
     * XML'in kendi kodlaması (byte'lar yeniden kodlanmadan sunulduğu için Content-Type charset'i): BOM,
     * yoksa XML bildirimindeki {@code encoding}, o da yoksa/desteklenmiyorsa UTF-8 (XML varsayılanı).
     */
    static Charset declaredCharset(byte[] xml) {
        if (xml.length >= 3 && (xml[0] & 0xFF) == 0xEF && (xml[1] & 0xFF) == 0xBB && (xml[2] & 0xFF) == 0xBF) {
            return StandardCharsets.UTF_8;
        }
        if (xml.length >= 2 && ((xml[0] & 0xFF) == 0xFE && (xml[1] & 0xFF) == 0xFF
                || (xml[0] & 0xFF) == 0xFF && (xml[1] & 0xFF) == 0xFE)) {
            return StandardCharsets.UTF_16; // bayt sırası BOM'dan okunur
        }
        Matcher declaration = XML_DECLARATION_ENCODING.matcher(
                new String(xml, 0, Math.min(xml.length, 256), StandardCharsets.ISO_8859_1));
        if (declaration.find()) {
            try {
                Charset declared = Charset.forName(declaration.group(1));
                // Bildirim ASCII olarak okunabildi: BOM'suz UTF-16/32 iddiası byte'larla çelişir, yok sayılır.
                if (!declared.name().startsWith("UTF-16") && !declared.name().startsWith("UTF-32")) return declared;
            } catch (RuntimeException ignored) {
                // Desteklenmeyen/geçersiz kodlama adı: XML varsayılanı (UTF-8).
            }
        }
        return StandardCharsets.UTF_8;
    }

    /** Henüz kimlik almamış politika içeriği. */
    private static final class Definition {
        final String profile, source, name, fileName, sha256;
        final byte[] xml;
        final Charset charset;
        final boolean fallbackApplied;
        Definition(String profile, String source, String name, String fileName, byte[] xml, boolean fallbackApplied) {
            this.profile = profile; this.source = source; this.name = name; this.fileName = fileName; this.xml = xml;
            this.sha256 = DigestUtils.sha256Hex(xml);
            this.charset = declaredCharset(xml);
            this.fallbackApplied = fallbackApplied;
        }
    }

    /** Değişmez etkin politika: bir isteğin başında alınır, istek boyunca aynı kalır. */
    public static final class Snapshot {
        private final Definition definition;
        private final String policyId;
        private final String activatedAt;
        private final String origin;

        private Snapshot(Definition definition, String policyId, String activatedAt, String origin) {
            this.definition = definition; this.policyId = policyId; this.activatedAt = activatedAt; this.origin = origin;
        }

        /** Politika XML'inin bu snapshot'a ait byte'ları (her çağrıda yeni akış). */
        public InputStream openStream() { return new ByteArrayInputStream(definition.xml); }
        /** DSS'e verilen byte'ların kopyası (değiştirilmemiş; SHA-256'sı {@link #getSha256()}). */
        public byte[] xml() { return definition.xml.clone(); }
        /** Güvenli ASCII indirme adı; sunucu yolu içermez. */
        public String getFileName() { return definition.fileName; }
        /** XML'in kendi kodlaması (Content-Type charset'i). */
        public Charset getCharset() { return definition.charset; }
        public PolicyContext context() {
            return new PolicyContext(policyId, definition.profile, definition.source, definition.name, definition.sha256);
        }
        ActivePolicy toActivePolicy(boolean activationEnabled) {
            return new ActivePolicy(context(), origin, activatedAt, definition.fallbackApplied, activationEnabled);
        }
        public String getPolicyId() { return policyId; }
        public String getProfile() { return definition.profile; }
        public String getSource() { return definition.source; }
        public String getName() { return definition.name; }
        public String getSha256() { return definition.sha256; }
        public String getOrigin() { return origin; }
        public String getActivatedAt() { return activatedAt; }
        public boolean isFallbackApplied() { return definition.fallbackApplied; }
    }
}
