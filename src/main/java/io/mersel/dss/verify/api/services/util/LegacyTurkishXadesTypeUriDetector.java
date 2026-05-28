package io.mersel.dss.verify.api.services.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * KamuSM / GİB ekosisteminde yaygın olan eski imzalama araçlarının ürettiği
 * <strong>standart dışı XAdES <code>Reference Type</code> URI</strong>'lerini
 * tespit eder.
 *
 * <h3>Pratik problem</h3>
 * <p>ETSI TS 101 903 (XAdES) ve EN 319 132-1, <code>SignedProperties</code>
 * referansının <code>Type</code> attribute'unu DSS'in tanıdığı üç URI'den
 * biriyle ister:</p>
 * <pre>
 *   http://uri.etsi.org/01903#SignedProperties           (XAdES 1.3.2 / current — versiyonsuz)
 *   http://uri.etsi.org/01903/v1.1.1#SignedProperties    (XAdES 1.1.1 — legacy)
 *   http://uri.etsi.org/01903/v1.2.2#SignedProperties    (XAdES 1.2.2 — legacy)
 * </pre>
 *
 * <p>(Kaynak: <code>specs-xades</code> jar'ında
 * <code>XAdES111Path / XAdES122Path / XAdES132Path#getSignedPropertiesUri()</code>.
 * XAdES 1.3.2 için Type URI <em>versiyonsuz</em>'dur; namespace ise
 * <code>http://uri.etsi.org/01903/v1.3.2#</code> olur — bu ikisini
 * karıştırmak yaygın bir üretici hatasıdır.)</p>
 *
 * <h3>Yakaladığımız üç TR-özel patoloji</h3>
 * <ol>
 *   <li><b>P1 — ".xsd" karışıklığı</b> ({@link LegacyTurkishXadesAnomaly.Kind#TYPE_URI_VARIANT})
 *       — Tool, Type URI'sini schema location ile karıştırıp şöyle yazıyor:
 *       <pre>http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties</pre></li>
 *   <li><b>P2 — Versiyon prefix'i yanlış kullanımı</b>
 *       ({@link LegacyTurkishXadesAnomaly.Kind#TYPE_URI_VARIANT}) — Tool,
 *       XAdES 1.3.2 / 1.4.1 namespace'inin versiyon segmentini Type URI'sine
 *       de ekliyor. DSS bunu tanımıyor (1.3.2 için versiyonsuz URI
 *       bekleniyor):
 *       <pre>http://uri.etsi.org/01903/v1.3.2#SignedProperties
 *http://uri.etsi.org/01903/v1.4.1#SignedProperties</pre>
 *       (Sabancı Dijital / Türkiye Sigorta envelope'larında görülen yaygın
 *       varyant.)</li>
 *   <li><b>P3 — SignedProperties referansı eksik (tek referanslı imza)</b>
 *       ({@link LegacyTurkishXadesAnomaly.Kind#MISSING_SP_REFERENCE}) —
 *       <code>&lt;xades:SignedProperties Id="…"&gt;</code> elementi
 *       <code>&lt;ds:Object&gt;</code> altında mevcut fakat
 *       <strong>hiçbir</strong> <code>&lt;ds:Reference&gt;</code> ona pointing
 *       değil: ne URI fragment'iyle (<code>URI="#SignedProperties_…"</code>)
 *       ne de Type attribute'uyla (<code>Type=".../#SignedProperties"</code>).
 *       ETSI EN 319 132-1 (XAdES-BES) iki referans (biri body, biri
 *       SignedProperties) zorunluluğuna aykırı; imzayı üreten yazılımın
 *       hatasıdır ve <strong>tolere edilmez</strong>. P1/P2'nin aksine
 *       bu yapı suppression yoluyla geçerli sayılmaz; verifier akışında
 *       yalnızca tanı amaçlı rejection olarak raporlanır
 *       ({@link io.mersel.dss.verify.api.models.enums.RejectionCode#MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE}).</li>
 * </ol>
 *
 * <p>Her üç varyantta da Eclipse DSS imzayı <code>BBB_SAV_ISQPMDOSPP</code>
 * ile reddediyor (<em>"ne message-digest ne SignedProperties mevcut"</em>) ve
 * <code>INDETERMINATE / SIG_CONSTRAINTS_FAILURE</code> dönüyor. P1/P2
 * yalnızca <code>Type</code> attribute'unda bir yazım hatasıyken (kriptografi
 * sağlam, içerik kapsamı tam), P3 tamamen ayrı bir kategoridir: ikinci
 * referansın hiç üretilmemiş olması SignedProperties içeriğinin imza
 * kapsamı dışında kalmasına yol açar — düzeltilmesi gereken bir
 * regresyondur.</p>
 *
 * <h3>Bu sınıfın görevi</h3>
 * <p>Yalnızca tespit yapar — XML'i değiştirmez. Doğrulama sonrası karar
 * akışında "bu imza Türkiye ekosistemi varyantı mı, yoksa gerçekten kırık mı?"
 * sorusuna kesin cevap vermek için kullanılır.</p>
 *
 * <h3>Tespit kuralı (deliberately narrow)</h3>
 * <p>P1, P2, P3 üç koşulun TAM EŞLEŞMESİNİ ister; jenerik bir SIG_CONSTRAINTS
 * bypass'ı değildir. DSS'in zaten kabul ettiği <code>v1.1.1</code> ve
 * <code>v1.2.2</code> SignedProperties URI'leri bilerek dışarıda — onlar
 * legacy XAdES standart Type URI'leridir, BBB_SAV_ISQPMDOSPP zaten oluşmaz;
 * tolerance gate'ine düşürmek anlamsız olur ve risk yüzeyi açar.</p>
 *
 * <h3>Algoritma sırası</h3>
 * <p>{@link #detectAnomaly(byte[])} önce P1/P2'yi (Type URI varyantı) dener;
 * eşleşme yoksa P3'ü (missing SP reference) dener. İlk eşleşme döndürülür.</p>
 *
 * <h3>Charset & performans</h3>
 * <p>XML byte'larını <code>ISO-8859-1</code> ile çözer (lossless 1:1).
 * SignatureValue/sertifika base64'leri ASCII olduğu için Türkçe karakterli
 * faturalarda bile byte-level pattern matching güvenli. Hızlı sniff için
 * önce byte düzeyinde <code>01903</code> marker'ı aranır; yoksa string'e
 * çevirme maliyetine girmiyoruz. Pattern'ler derlenmiştir (immutable),
 * Matcher lokal — thread-safe.</p>
 *
 * @see io.mersel.dss.verify.api.config.VerificationConfiguration#isTrLegacyXadesToleranceEnabled()
 */
@Component
public class LegacyTurkishXadesTypeUriDetector {

    private static final Logger logger =
            LoggerFactory.getLogger(LegacyTurkishXadesTypeUriDetector.class);

    /**
     * Hızlı sniff: byte düzeyinde "01903" marker'ı yoksa string'e çevirmenin
     * maliyetine girmeyiz. Tek başına yetmez, ama her iki patolojide de
     * <code>01903</code> mutlaka geçer; ucuz negatif filtre olarak idealdir.
     */
    private static final byte[] SNIFF_MARKER_ETSI =
            "01903".getBytes(StandardCharsets.US_ASCII);

    /**
     * P1 — "xsd karışıklığı" varyantı:
     * <code>…/01903/…XAdES.xsd…#SignedProperties</code> paterni. Olası
     * namespace prefix'leri (<code>ds:</code>, <code>dsig:</code>, prefix-yok)
     * tolere edilir.
     */
    private static final Pattern LEGACY_TYPE_URI_XSD_PATTERN = Pattern.compile(
            "<\\s*([\\w-]+\\s*:)?Reference\\b[^>]*\\bType\\s*=\\s*"
                    + "[\"']\\s*([^\"']*\\buri\\.etsi\\.org/01903[^\"']*\\.xsd[^\"']*#SignedProperties)\\s*[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * P2 — "versiyon prefix'i yanlış" varyantı: yalnızca
     * <code>v1.3.2#SignedProperties</code> veya
     * <code>v1.4.1#SignedProperties</code>. v1.1.1 ve v1.2.2 BİLEREK dışarıda
     * — onları DSS zaten kabul ediyor (bkz. sınıf-seviyesi JavaDoc).
     */
    private static final Pattern LEGACY_TYPE_URI_VERSIONED_PATTERN = Pattern.compile(
            "<\\s*([\\w-]+\\s*:)?Reference\\b[^>]*\\bType\\s*=\\s*"
                    + "[\"']\\s*(https?://uri\\.etsi\\.org/01903/v1\\.(?:3\\.2|4\\.1)#SignedProperties)\\s*[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * P3-1 — <code>&lt;xades:SignedProperties Id="…"&gt;</code> elementinin
     * XML'de bulunup bulunmadığını ve <code>Id</code> değerini yakalar.
     * Namespace prefix'i değişebilir (<code>xades:</code>, <code>xa:</code>,
     * prefix-yok) — case-insensitive eşleştirme yapıyoruz.
     *
     * <p>Pattern <strong>başlangıç tag'ini</strong> hedefler. Self-closing
     * (<code>&lt;... /&gt;</code>) varyantı XAdES'te anlamsız (SignedProperties
     * boş olamaz: <code>SigningTime</code> alt elementi zorunlu) ama yine de
     * regex bunu da kapsar.</p>
     */
    private static final Pattern SIGNED_PROPERTIES_ELEMENT_PATTERN = Pattern.compile(
            "<\\s*([\\w-]+\\s*:)?SignedProperties\\b[^>]*\\bId\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * P3-2 — Bir <code>&lt;ds:Reference&gt;</code> elementinin <code>URI</code>
     * attribute'unu yakalar (fragment olsun veya olmasın). P3 tespiti için
     * "bu URI'lerden hiçbiri <code>#SignedPropertiesId</code> ile eşleşmiyor mu?"
     * sorusuna cevap aramak için kullanılır.
     */
    private static final Pattern REFERENCE_URI_PATTERN = Pattern.compile(
            "<\\s*([\\w-]+\\s*:)?Reference\\b[^>]*\\bURI\\s*=\\s*[\"']([^\"']*)[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * P3-3 — Bir <code>&lt;ds:Reference&gt;</code> elementinin <code>Type</code>
     * attribute'unun "<code>…/01903…#SignedProperties</code>" paterniyle
     * (versiyon, .xsd vs. herhangi bir biçimde) eşleşip eşleşmediğini kontrol
     * eder. P3 tespiti için bu kontrol ek bir filtre: eğer XML'de "bir şekilde"
     * SignedProperties Type URI'li bir reference VARSA, P3 patolojisi yok
     * demektir (P1/P2 olabilir veya zaten standart).
     */
    private static final Pattern ANY_SIGNED_PROPERTIES_TYPE_REFERENCE_PATTERN = Pattern.compile(
            "<\\s*([\\w-]+\\s*:)?Reference\\b[^>]*\\bType\\s*=\\s*"
                    + "[\"'][^\"']*\\buri\\.etsi\\.org/01903[^\"']*#SignedProperties\\s*[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * XML içinde bahsi geçen üretici hatalarından <em>herhangi birinin</em>
     * olup olmadığını kontrol eder.
     *
     * <p>Algoritma deterministik:</p>
     * <ol>
     *   <li>ETSI sniff marker'ı (<code>01903</code>) yoksa erken döner — XAdES
     *       işaretinin olmadığı XML'lerde detector hiç çalışmaz.</li>
     *   <li>P1 (xsd) → P2 (versiyon-prefix) sırasıyla denenir. Eşleşme
     *       varsa {@link LegacyTurkishXadesAnomaly.Kind#TYPE_URI_VARIANT}
     *       döner.</li>
     *   <li>Hiçbiri eşleşmezse P3 (missing SP reference) denenir:
     *       <code>SignedProperties</code> elementi VAR ama hiçbir
     *       <code>Reference</code> ona pointing değilse
     *       {@link LegacyTurkishXadesAnomaly.Kind#MISSING_SP_REFERENCE}
     *       döner.</li>
     * </ol>
     *
     * @param xmlBytes orijinal (preprocess'sız) XML byte'ları
     * @return tespit edilen patoloji veya <code>null</code> (hiçbir bilinen
     *         üretici hatası eşleşmiyor)
     */
    public LegacyTurkishXadesAnomaly detectAnomaly(byte[] xmlBytes) {
        if (xmlBytes == null || xmlBytes.length == 0) {
            return null;
        }
        if (indexOfBytes(xmlBytes, SNIFF_MARKER_ETSI) < 0) {
            return null;
        }

        String xml;
        try {
            xml = new String(xmlBytes, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            logger.debug("Legacy TR XAdES detector: charset decode hatası: {}", e.getMessage());
            return null;
        }

        Matcher xsdMatcher = LEGACY_TYPE_URI_XSD_PATTERN.matcher(xml);
        if (xsdMatcher.find()) {
            String hit = xsdMatcher.group(2);
            logger.warn("Legacy Türkiye XAdES Type URI tespit edildi (xsd varyantı): '{}'. "
                    + "Kriptografik imza sağlam ise tolerans uygulanacak.", hit);
            return new LegacyTurkishXadesAnomaly(
                    LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT, hit);
        }

        Matcher versionedMatcher = LEGACY_TYPE_URI_VERSIONED_PATTERN.matcher(xml);
        if (versionedMatcher.find()) {
            String hit = versionedMatcher.group(2);
            logger.warn("Legacy Türkiye XAdES Type URI tespit edildi (versiyon-prefix varyantı): '{}'. "
                    + "DSS XAdES 1.3.2 için versiyonsuz Type URI bekliyor; "
                    + "kriptografik imza sağlam ise tolerans uygulanacak.", hit);
            return new LegacyTurkishXadesAnomaly(
                    LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT, hit);
        }

        String missingSpReferenceId = detectMissingSignedPropertiesReference(xml);
        if (missingSpReferenceId != null) {
            logger.warn("XAdES tek referanslı imza tespit edildi (missing SP reference): "
                            + "SignedProperties Id='{}' var ama hiçbir Reference ona pointing değil. "
                            + "ETSI EN 319 132-1 iki referans zorunluluğuna aykırı; "
                            + "imza standart davranışla reddedilecek ve Mersel rejection kodu "
                            + "(MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE) ile zenginleştirilecek.",
                    missingSpReferenceId);
            return new LegacyTurkishXadesAnomaly(
                    LegacyTurkishXadesAnomaly.Kind.MISSING_SP_REFERENCE, missingSpReferenceId);
        }

        return null;
    }

    /**
     * P3 tespit mantığı — per-SignedProperties-Id evaluation.
     *
     * <p>Algoritma:</p>
     * <ol>
     *   <li>XML'deki tüm <code>&lt;…:SignedProperties Id="X"&gt;</code>
     *       elementlerinin Id değerleri toplanır.</li>
     *   <li>XML'deki tüm <code>&lt;…:Reference URI="#…"&gt;</code>
     *       fragment'ları toplanır.</li>
     *   <li><b>Tek SignedProperties</b> varsa (en yaygın senaryo): Id URI
     *       fragment'larında varsa null; yoksa
     *       <code>Type="…/01903…#SignedProperties"</code> taşıyan
     *       <em>herhangi bir</em> Reference olup olmadığına bakılır — varsa
     *       Type-only referansın bu tek SP'ye işaret ettiği konservatif
     *       varsayımıyla null döner (standart dışı ama geçmişten gelen
     *       kabul); yoksa Id flag edilir.</li>
     *   <li><b>Birden fazla SignedProperties</b> varsa (multi-signature
     *       senaryoları): Type-only referans hangi SP'ye işaret ettiği
     *       belirsiz olduğundan konservatif fallback geçersizdir. Her SP
     *       Id'si için ayrı URI fragment kontrolü yapılır; fragment'larda
     *       eşleşmeyen ilk Id döndürülür.</li>
     * </ol>
     *
     * <p>Bu ayrım önemli: önceki tek-pass fast-negative gate
     * (<em>"XML'de herhangi bir Type=SP Reference varsa P3'ü atla"</em>)
     * multi-signature senaryosunda false-negative üretebiliyordu:
     * Signature-A doğru kurulu, Signature-B'nin SP'sini hiç bağlamadan
     * bırakılmış. Yeni algoritma her SP Id'sini bağımsız değerlendirir.</p>
     */
    private static String detectMissingSignedPropertiesReference(String xml) {
        List<String> spIds = collectSignedPropertiesIds(xml);
        if (spIds.isEmpty()) {
            return null;
        }

        Set<String> referencedFragments = collectReferenceUriFragments(xml);

        if (spIds.size() == 1) {
            String onlyId = spIds.get(0);
            if (referencedFragments.contains(onlyId)) {
                return null;
            }
            // Konservatif fallback: tek SP varsa ve bir Type=SignedProperties
            // referansı (URI fragment'sız bile olsa) bulunuyorsa, o
            // referansın bu tek SP'ye yönelik olduğu varsayımıyla P3 atla.
            // Standart dışı ama geçmişten kabul edilen yapı.
            if (ANY_SIGNED_PROPERTIES_TYPE_REFERENCE_PATTERN.matcher(xml).find()) {
                return null;
            }
            return onlyId;
        }

        // Multi-signature: her Id ayrı ayrı kontrol edilir; Type-only
        // fallback uygulanmaz (hangi SP'ye işaret ettiği belirsiz).
        for (String id : spIds) {
            if (!referencedFragments.contains(id)) {
                return id;
            }
        }
        return null;
    }

    private static List<String> collectSignedPropertiesIds(String xml) {
        List<String> ids = new ArrayList<>();
        Matcher m = SIGNED_PROPERTIES_ELEMENT_PATTERN.matcher(xml);
        while (m.find()) {
            String id = m.group(2);
            if (id != null && !id.isEmpty()) {
                ids.add(id);
            }
        }
        return ids;
    }

    private static Set<String> collectReferenceUriFragments(String xml) {
        Set<String> referenced = new HashSet<>();
        Matcher m = REFERENCE_URI_PATTERN.matcher(xml);
        while (m.find()) {
            String uri = m.group(2);
            if (uri != null && uri.startsWith("#") && uri.length() > 1) {
                referenced.add(uri.substring(1));
            }
        }
        return referenced;
    }

    private static int indexOfBytes(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    // -------------------------------------------------------------------------
    // NOT — Eskiden burada "cryptographic re-validation" katmanı için Type
    // URI normalize ediliyordu (`normalizeTypeUri` + helper'lar). Tasarım
    // hatasıydı: `<ds:Reference Type="...">` attribute değeri SignedInfo
    // bloğu içinde yer aldığı için imza kapsamındadır; byte stream'inde
    // değiştirmek SignatureValue'yi geçersizleştirir
    // (`SIG_CRYPTO_FAILURE`). Re-validation gerçek P1/P2 vakalarda her
    // zaman patladığı için katman tamamen kaldırıldı; allow-list mantığı
    // (gate v2.2) suppression için yeterli güveni sağlar. Detail için
    // bkz. CHANGELOG "Re-validation katmanı kaldırıldı" entry'si.
}
