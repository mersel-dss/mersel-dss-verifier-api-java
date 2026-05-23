package io.mersel.dss.verify.api.services.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
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
 * <h3>Yakaladığımız iki TR-özel patoloji</h3>
 * <ol>
 *   <li><b>".xsd" karışıklığı</b> — Tool, Type URI'sini schema location ile
 *       karıştırıp şöyle yazıyor:
 *       <pre>http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties</pre></li>
 *   <li><b>Versiyon prefix'i yanlış kullanımı</b> — Tool, XAdES 1.3.2 / 1.4.1
 *       namespace'inin versiyon segmentini Type URI'sine de ekliyor. DSS bunu
 *       tanımıyor (1.3.2 için versiyonsuz URI bekleniyor):
 *       <pre>http://uri.etsi.org/01903/v1.3.2#SignedProperties
 *http://uri.etsi.org/01903/v1.4.1#SignedProperties</pre>
 *       (Sabancı Dijital / Türkiye Sigorta envelope'larında görülen yaygın
 *       varyant.)</li>
 * </ol>
 *
 * <p>Her iki varyantta da Eclipse DSS imzayı <code>BBB_SAV_ISQPMDOSPP</code>
 * ile reddediyor (<em>"ne message-digest ne SignedProperties mevcut"</em>) ve
 * <code>INDETERMINATE / SIG_CONSTRAINTS_FAILURE</code> dönüyor. Oysa TÜBİTAK
 * İmzager ve KamuSM tarafları bu imzaları geçerli kabul ediyor —
 * kriptografik imza ZATEN doğru, sadece Type attribute'unda yazım hatası
 * var.</p>
 *
 * <h3>Bu sınıfın görevi</h3>
 * <p>Yalnızca tespit yapar — XML'i değiştirmez. Doğrulama sonrası karar
 * akışında "bu imza Türkiye ekosistemi varyantı mı, yoksa gerçekten kırık mı?"
 * sorusuna kesin cevap vermek için kullanılır.</p>
 *
 * <h3>Tespit kuralı (deliberately narrow)</h3>
 * <p>Bir <code>&lt;ds:Reference&gt;</code> elementinde <code>Type</code>
 * attribute'u şu iki paternden BİRİYLE eşleşmeli:</p>
 * <ul>
 *   <li><b>P1 (xsd-karışıklığı)</b>: <code>uri.etsi.org/01903</code> +
 *       <code>.xsd</code> path segmenti + <code>#SignedProperties</code> ile
 *       bitiyor.</li>
 *   <li><b>P2 (versiyon-prefix'i)</b>: tam olarak
 *       <code>uri.etsi.org/01903/v1.3.2#SignedProperties</code> veya
 *       <code>uri.etsi.org/01903/v1.4.1#SignedProperties</code>.</li>
 * </ul>
 *
 * <p>P2'ye DSS'in zaten kabul ettiği <code>v1.1.1</code> ve <code>v1.2.2</code>
 * SignedProperties URI'lerini bilerek <em>dahil etmiyoruz</em> — onlar legacy
 * XAdES standart Type URI'leridir, BBB_SAV_ISQPMDOSPP zaten oluşmaz; tolerance
 * gate'ine düşürmek anlamsız olur ve "jenerik bypass" risk yüzeyi açar.</p>
 *
 * <p>Dolayısıyla bu sınıf <em>jenerik bir SIG_CONSTRAINTS bypass'ı değildir</em>
 * — yalnızca dökümante edilmiş iki spesifik üretici patolojisini affeder.</p>
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
     * XML içinde bahsi geçen üretici hatalarından <em>herhangi birinin</em>
     * olup olmadığını kontrol eder.
     *
     * <p>Eşleşme algoritması deterministik: önce P1 (xsd) denenir, eşleşme
     * yoksa P2 (versiyon-prefix) denenir. İlk eşleşme döndürülür; birden
     * fazla yakalanırsa ilki yeterlidir çünkü tolerance kararı yes/no'dur.</p>
     *
     * @param xmlBytes orijinal (preprocess'sız) XML byte'ları
     * @return tespit edilen problematik Type URI veya <code>null</code>.
     *         Eşleşme varsa loglarda ve audit evidence'ında referans için
     *         döndürülen değer aynen kullanılabilir.
     */
    public String detect(byte[] xmlBytes) {
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
            return hit;
        }

        Matcher versionedMatcher = LEGACY_TYPE_URI_VERSIONED_PATTERN.matcher(xml);
        if (versionedMatcher.find()) {
            String hit = versionedMatcher.group(2);
            logger.warn("Legacy Türkiye XAdES Type URI tespit edildi (versiyon-prefix varyantı): '{}'. "
                    + "DSS XAdES 1.3.2 için versiyonsuz Type URI bekliyor; "
                    + "kriptografik imza sağlam ise tolerans uygulanacak.", hit);
            return hit;
        }
        return null;
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
}
