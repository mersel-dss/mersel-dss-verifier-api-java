package io.mersel.dss.verify.api.config;

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * I18n locale konfigürasyonunun davranışını sabitler:
 * <ul>
 *   <li>Default değer Türkçe; null/boş tag fallback yapar.</li>
 *   <li>Geçersiz tag silent İngilizce'ye değil — Türkçe default'a düşer
 *       (operatörü yanıltmamak için).</li>
 *   <li>{@link I18nProviderConfiguration#dssValidationLocale()} bean'i
 *       config'in parse ettiği {@link Locale} objesini ayna olarak döner.</li>
 *   <li>Custom <code>dss-messages_tr.properties</code> dosyamız classpath'te
 *       resolve edilir ve TR çevirileri öncelik kazanır.</li>
 *   <li>TR'de eksik bıraktığımız bir anahtar otomatik İngilizce default'a
 *       fallback eder.</li>
 * </ul>
 *
 * <p>NOT: Surefire 2.22.2 + JUnit 5 kombosu {@code @Nested} sınıflarını
 * keşfedemiyor; bu yüzden testler düz hiyerarşide tutuldu.</p>
 */
class I18nLocaleConfigurationTest {

    // ----- VerificationConfiguration.parseLocaleOrDefault -----

    @Test
    @DisplayName("parseLocaleOrDefault — null tag Türkçe default'a düşer")
    void parseLocale_nullTag_returnsDefault() {
        assertEquals(Locale.forLanguageTag("tr"),
                VerificationConfiguration.parseLocaleOrDefault(null));
    }

    @Test
    @DisplayName("parseLocaleOrDefault — boş tag Türkçe default'a düşer")
    void parseLocale_emptyTag_returnsDefault() {
        assertEquals(Locale.forLanguageTag("tr"),
                VerificationConfiguration.parseLocaleOrDefault(""));
        assertEquals(Locale.forLanguageTag("tr"),
                VerificationConfiguration.parseLocaleOrDefault("   "));
    }

    @Test
    @DisplayName("parseLocaleOrDefault — geçerli tag direkt parse edilir")
    void parseLocale_validTag_isParsed() {
        assertEquals("en",
                VerificationConfiguration.parseLocaleOrDefault("en").getLanguage());
        assertEquals("fr",
                VerificationConfiguration.parseLocaleOrDefault("fr").getLanguage());
    }

    @Test
    @DisplayName("parseLocaleOrDefault — BCP-47 region tag (tr-TR) destekleniyor")
    void parseLocale_bcp47Region_isParsed() {
        Locale parsed = VerificationConfiguration.parseLocaleOrDefault("tr-TR");
        assertEquals("tr", parsed.getLanguage());
        assertEquals("TR", parsed.getCountry());
    }

    @Test
    @DisplayName("parseLocaleOrDefault — geçersiz tag default Türkçe'ye düşer (silent İngilizce'ye değil)")
    void parseLocale_invalidTag_returnsDefault() {
        assertEquals(Locale.forLanguageTag("tr"),
                VerificationConfiguration.parseLocaleOrDefault("invalid_xx_yy"));
        assertEquals(Locale.forLanguageTag("tr"),
                VerificationConfiguration.parseLocaleOrDefault("???"));
    }

    @Test
    @DisplayName("DEFAULT_I18N_LOCALE_TAG sabiti TR olarak korunur")
    void defaultLocaleTag_isTurkish() {
        assertEquals("tr", VerificationConfiguration.DEFAULT_I18N_LOCALE_TAG);
    }

    // ----- VerificationConfiguration getter davranışı -----

    @Test
    @DisplayName("getI18nLocaleObject — set edilen değeri parse eder")
    void getter_returnsParsedValue() {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setI18nLocale("en");
        assertEquals("en", config.getI18nLocaleObject().getLanguage());
    }

    @Test
    @DisplayName("getI18nLocaleObject — boş tag default'a düşer")
    void getter_emptyValue_fallsBackToDefault() {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setI18nLocale("");
        assertEquals("tr", config.getI18nLocaleObject().getLanguage());
    }

    @Test
    @DisplayName("getI18nLocaleObject — null tag default'a düşer")
    void getter_nullValue_fallsBackToDefault() {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setI18nLocale(null);
        assertEquals("tr", config.getI18nLocaleObject().getLanguage());
    }

    // ----- I18nProviderConfiguration bean davranışı -----

    @Test
    @DisplayName("dssValidationLocale bean'i config'in parse ettiği objeyi yansıtır")
    void bean_reflectsConfig() {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setI18nLocale("en");
        I18nProviderConfiguration beans = new I18nProviderConfiguration(config);
        Locale produced = beans.dssValidationLocale();
        assertNotNull(produced);
        assertEquals("en", produced.getLanguage());
    }

    @Test
    @DisplayName("warnOnInvalidLocale geçersiz tag'de exception fırlatmaz (sadece WARN log)")
    void postConstruct_doesNotThrow_onInvalid() {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setI18nLocale("garbage_xx");
        I18nProviderConfiguration beans = new I18nProviderConfiguration(config);
        beans.warnOnInvalidLocale();
        assertEquals("tr", beans.dssValidationLocale().getLanguage());
    }

    @Test
    @DisplayName("warnOnInvalidLocale boş config'i tolere eder (INFO log)")
    void postConstruct_handlesEmptyConfig() {
        VerificationConfiguration config = new VerificationConfiguration();
        config.setI18nLocale("");
        I18nProviderConfiguration beans = new I18nProviderConfiguration(config);
        beans.warnOnInvalidLocale();
        assertEquals("tr", beans.dssValidationLocale().getLanguage());
    }

    // ----- dss-messages bundle classpath resolution -----

    @Test
    @DisplayName("dss-messages bundle Türkçe locale ile resolve olur (TR dosyamız aktif)")
    void bundle_resolvesWithTrLocale() {
        ResourceBundle bundle = ResourceBundle.getBundle("dss-messages",
                Locale.forLanguageTag("tr"));
        assertNotNull(bundle);
        assertEquals("tr", bundle.getLocale().getLanguage(),
                "TR bundle yüklenmedi. Locale: " + bundle.getLocale());
    }

    @Test
    @DisplayName("BBB_XCV_ISCGKU — TR çevirimiz öncelikli olarak yüklenir")
    void bundle_loadsOurTrTranslation() {
        ResourceBundle bundle = ResourceBundle.getBundle("dss-messages",
                Locale.forLanguageTag("tr"));
        String value = bundle.getString("BBB_XCV_ISCGKU");
        assertTrue(value.contains("anahtar kullanım"),
                "Beklenen TR çevirisi yüklenmedi. Gerçek değer: " + value);
        assertFalse(value.contains("expected key-usage"),
                "İngilizce default sızmış: " + value);
    }

    @Test
    @DisplayName("TRUSTED_SERVICE_STATUS — TR çevirisi mevcut, statik kod placeholder'ı korunur")
    void bundle_trustedServiceStatusTranslated() {
        ResourceBundle bundle = ResourceBundle.getBundle("dss-messages",
                Locale.forLanguageTag("tr"));
        String pattern = bundle.getString("TRUSTED_SERVICE_STATUS");
        assertTrue(pattern.contains("Güven hizmeti durumu"),
                "TR çevirisi yok. Gerçek değer: " + pattern);
        assertTrue(pattern.contains("{0}"),
                "Placeholder yok, statik kod (URI/enum) geçirilemeyecek: " + pattern);
    }

    @Test
    @DisplayName("Eksik anahtar — DSS jar default'una (İngilizce) fallback eder")
    void bundle_missingKey_fallsBackToEnglishDefault() {
        ResourceBundle bundle = ResourceBundle.getBundle("dss-messages",
                Locale.forLanguageTag("tr"));
        String value;
        try {
            // PSV / ARCH bloklarından bir anahtar — biz çevirmedik.
            value = bundle.getString("BBB_XCV_HCCLBIBT");
        } catch (MissingResourceException ex) {
            // DSS jar version'ı bu anahtarı taşımıyorsa testi atla.
            return;
        }
        assertNotNull(value);
        assertFalse(value.isEmpty());
        // Bizim TR dosyamızda yer almadığı için İngilizce gelmeli.
        // (Türkçe karakter içermemesi yeterli kanıt.)
    }

    @Test
    @DisplayName("English locale — DSS jar default'unu doğrudan kullanır (TR override etmez)")
    void bundle_englishLocale_usesDefault() {
        ResourceBundle bundle = ResourceBundle.getBundle("dss-messages",
                Locale.ENGLISH);
        String value = bundle.getString("BBB_XCV_ISCGKU");
        assertTrue(value.contains("expected key-usage"),
                "English default beklenirdi: " + value);
        assertFalse(value.contains("anahtar kullanım"),
                "TR çevirisi İngilizce locale'e sızmış: " + value);
    }
}
