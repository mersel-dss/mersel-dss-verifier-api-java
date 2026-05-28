package io.mersel.dss.verify.api.config;

import java.util.Locale;

import javax.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * DSS i18n locale konfigürasyonu — doğrulama mesajlarının dilini belirler.
 *
 * <h2>Neden ayrı bir config sınıfı?</h2>
 * <ul>
 *   <li>{@link Locale} bean'ini Spring DI üzerinden tek bir kanaldan
 *       expose etmek (test override, ayrı profilelerde farklı locale'ler).</li>
 *   <li>Startup-time validation: operatör <code>verification.i18n-locale</code>'a
 *       geçersiz bir tag verdiyse uygulama ayağa kalktığı sırada (sessiz
 *       fallback yerine) WARN log'u basılır — operatör config hatasını
 *       erken görür.</li>
 *   <li>Tüm DSS validator instance'ları (signature + timestamp pipeline'ları)
 *       bu tek Locale bean'ini autowire eder; doğrulama dili tutarlı kalır.</li>
 * </ul>
 *
 * <h2>DSS i18n çalışma mantığı</h2>
 * <ol>
 *   <li>Bu Locale, DSS {@code SignedDocumentValidator.setLocale(...)} ile
 *       her doğrulama akışına geçirilir.</li>
 *   <li>DSS pipeline'ı kendi {@code I18nProvider}'ını {@code locale} ile
 *       kurar; <code>dss-messages</code> bundle'ını
 *       <code>ResourceBundle.getBundle("dss-messages", locale)</code>
 *       ile yükler.</li>
 *   <li>Java standard fallback chain devreye girer:
 *       <ul>
 *         <li><code>dss-messages_tr_TR.properties</code></li>
 *         <li><code>dss-messages_tr.properties</code> — biz bunu sağlarız
 *             ve TR çevirileri buraya gider</li>
 *         <li><code>dss-messages.properties</code> — DSS jar'ı içinden
 *             gelen İngilizce default; eksik anahtarlar otomatik buradan
 *             okunur, çıktı asla boş kalmaz</li>
 *       </ul>
 *   </li>
 *   <li>BBB constraint mesajları (<code>BBB_XCV_ISCGKU</code>,
 *       <code>TRUSTED_SERVICE_STATUS</code>, vb.) seçilen locale'de
 *       <code>XmlConstraint.error.value</code> alanına yazılır;
 *       <code>AdvancedSignatureVerificationService#collectFailingBbbConstraintMessages</code>
 *       bunları <code>validationErrors</code> listesine zenginleştirir.</li>
 * </ol>
 *
 * <h2>Yeni bir TR çeviri eklemek</h2>
 * <p><code>src/main/resources/dss-messages_tr.properties</code> dosyasını
 * açın ve standart Java {@code ResourceBundle} formatında satır ekleyin:</p>
 * <pre>
 * BBB_XCV_ISCGKU=Sertifikanın anahtar kullanım alanı (KeyUsage) imza için yetkili mi?
 * TRUSTED_SERVICE_STATUS=Güven hizmeti durumu : {0}
 * </pre>
 *
 * <p>DSS jar'ı içindeki tüm anahtar listesi referans olarak DSS jar'ı
 * altındaki <code>dss-messages.properties</code> dosyasında bulunabilir
 * (yaklaşık 600 anahtar; placeholder'lar <code>{0}</code>, <code>{1}</code>
 * formatında). Eksik bıraktıklarınız İngilizce default ile gelmeye devam
 * eder — gradual translation desteklenir.</p>
 */
@Configuration
public class I18nProviderConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(I18nProviderConfiguration.class);

    private final VerificationConfiguration verificationConfiguration;

    public I18nProviderConfiguration(VerificationConfiguration verificationConfiguration) {
        this.verificationConfiguration = verificationConfiguration;
    }

    /**
     * Startup-time uyarı: operatör geçersiz bir locale tag'i verdiyse
     * (örn. <code>verification.i18n-locale=foo_bar</code>) WARN log'u
     * bas. {@link VerificationConfiguration#parseLocaleOrDefault(String)}
     * sessiz fallback yapar; bu uyarı hatayı operatöre görünür kılar.
     */
    @PostConstruct
    void warnOnInvalidLocale() {
        String configured = verificationConfiguration.getI18nLocale();
        if (configured == null || configured.trim().isEmpty()) {
            LOG.info("DSS i18n locale belirtilmedi; default '{}' kullanılıyor.",
                    VerificationConfiguration.DEFAULT_I18N_LOCALE_TAG);
            return;
        }
        Locale parsed = Locale.forLanguageTag(configured.trim());
        if (parsed.getLanguage().isEmpty()) {
            LOG.warn(
                    "DSS i18n locale tag'i geçersiz: '{}'. Default '{}' kullanılacak. "
                            + "Geçerli örnekler: tr, en, en-US, fr, de, tr-TR (BCP-47).",
                    configured, VerificationConfiguration.DEFAULT_I18N_LOCALE_TAG);
            return;
        }
        LOG.info("DSS i18n locale aktif: '{}' (language='{}', country='{}'). "
                        + "BBB constraint mesajları bu locale'de doldurulacak; "
                        + "eksik anahtarlar dss-messages.properties (İngilizce default) ile fallback edecek.",
                configured, parsed.getLanguage(), parsed.getCountry());
    }

    /**
     * DSS validator pipeline'ına injecte edilecek tek-doğruluk-kaynağı
     * {@link Locale} bean'i. Hem signature hem timestamp doğrulama
     * servisleri bunu autowire eder.
     *
     * <p><b>Neden Locale (objesi)?</b> DSS {@code SignedDocumentValidator}
     * tek başına {@code I18nProvider} kabul etmez; üzerinde sadece
     * <code>setLocale(Locale)</code> setter'ı vardır. Bu API'yi tek
     * noktadan beslemek için Locale'i bean olarak expose etmek doğru
     * boundary noktası — {@code I18nProvider}'ı manuel kurmak yerine
     * DSS'in pipeline'ını standart yoldan yönetiyoruz.</p>
     */
    @Bean
    public Locale dssValidationLocale() {
        return verificationConfiguration.getI18nLocaleObject();
    }
}
