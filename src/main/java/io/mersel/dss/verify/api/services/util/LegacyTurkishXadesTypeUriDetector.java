package io.mersel.dss.verify.api.services.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * KamuSM / GİB ekosisteminde yaygın olan eski imzalama araçlarının ürettiği
 * <strong>standart dışı XAdES <code>Reference Type</code> URI</strong>'sini
 * tespit eder.
 *
 * <h3>Pratik problem</h3>
 * <p>ETSI TS 101 903 (XAdES) ve EN 319 132-1, <code>SignedProperties</code>
 * referansının <code>Type</code> attribute'unu şu üç URI'den biriyle ister:</p>
 * <pre>
 *   http://uri.etsi.org/01903#SignedProperties           (current)
 *   http://uri.etsi.org/01903/v1.1.1#SignedProperties    (legacy)
 *   http://uri.etsi.org/01903/v1.2.2#SignedProperties    (legacy)
 * </pre>
 *
 * <p>Bazı Türkiye'deki imzalama kütüphaneleri (özellikle eski GİB-uyumlu
 * tool'lar) bu URI'yi <em>schema location</em> ile karıştırıp şu varyantı
 * üretiyor:</p>
 * <pre>
 *   http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties
 * </pre>
 *
 * <p>Eclipse DSS spec'e harfiyen uyduğu için bu Type URI'yi tanımıyor ve
 * imzayı <code>BBB_SAV_ISQPMDOSPP</code> ile reddediyor:
 * <em>"ne message-digest ne SignedProperties mevcut"</em>. Oysa TÜBİTAK
 * İmzager ve KamuSM tarafları bu imzaları geçerli kabul ediyor — kriptografik
 * imza ZATEN doğru, yalnızca Type attribute'unda yazım hatası var.</p>
 *
 * <h3>Bu sınıfın görevi</h3>
 * <p>Yalnızca tespit yapar — XML'i değiştirmez. Doğrulama sonrası karar
 * akışında "bu imza Türkiye ekosistemi varyantı mı, yoksa gerçekten kırık mı?"
 * sorusuna kesin cevap vermek için kullanılır.</p>
 *
 * <h3>Tespit kuralı (deliberately narrow)</h3>
 * <p>Pattern: bir <code>&lt;ds:Reference&gt;</code> elementinde
 * <code>Type</code> attribute'u şu üç koşulu birlikte sağlamalı:</p>
 * <ol>
 *   <li><code>uri.etsi.org/01903</code> içeriyor</li>
 *   <li><code>.xsd</code> path segment'i içeriyor</li>
 *   <li><code>#SignedProperties</code> ile bitiyor</li>
 * </ol>
 *
 * <p>Bu üçü aynı anda sadece bahsedilen üretici hatasıyla görülür; standart
 * URI'ler asla <code>.xsd</code> içermez. Dolayısıyla bu sınıf <em>jenerik
 * bir SIG_CONSTRAINTS bypass'ı değildir</em> — yalnızca dökümante edilmiş
 * tek bir patolojiyi affeder.</p>
 *
 * <h3>Charset & performans</h3>
 * <p>XML byte'larını <code>ISO-8859-1</code> ile çözer (lossless 1:1).
 * SignatureValue/sertifika base64'leri ASCII olduğu için Türkçe karakterli
 * faturalarda bile byte-level pattern matching güvenli. Pattern derlenmiştir
 * (immutable), Matcher lokal — thread-safe.</p>
 *
 * @see io.mersel.dss.verify.api.config.VerificationConfiguration#isTrLegacyXadesToleranceEnabled()
 */
@Component
public class LegacyTurkishXadesTypeUriDetector {

    private static final Logger logger =
            LoggerFactory.getLogger(LegacyTurkishXadesTypeUriDetector.class);

    /**
     * Hızlı sniff: byte düzeyinde "01903" ve "XAdES.xsd" ikilisini ararız.
     * İkisi yoksa string'e çevirmenin maliyetine girmeyiz.
     */
    private static final byte[] SNIFF_MARKER_ETSI =
            "01903".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SNIFF_MARKER_XSD =
            "XAdES.xsd".getBytes(StandardCharsets.US_ASCII);

    /**
     * Pattern: bir Reference elementinde Type attribute'u 01903 + .xsd +
     * #SignedProperties paterniyle eşleşmeli. Olası namespace prefix'leri
     * (<code>ds:</code>, <code>dsig:</code>, prefix-yok) tolere edilir.
     *
     * <p>İki versiyon: (a) Type attribute'u doğrudan, (b) Type attribute'unun
     * argümanı içinde. Spec'e göre Type attribute'unun değeri tek bir URI'dir
     * — bu yüzden başlangıçtan itibaren yakalamayı tercih ediyoruz.</p>
     */
    private static final Pattern LEGACY_TYPE_URI_PATTERN = Pattern.compile(
            "<\\s*([\\w-]+\\s*:)?Reference\\b[^>]*\\bType\\s*=\\s*"
                    + "[\"']\\s*([^\"']*\\buri\\.etsi\\.org/01903[^\"']*\\.xsd[^\"']*#SignedProperties)\\s*[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * XML içinde bahsi geçen üretici hatasının olup olmadığını kontrol eder.
     *
     * @param xmlBytes orijinal (preprocess'sız) XML byte'ları
     * @return tespit edilen problematik Type URI veya <code>null</code>.
     *         Eşleşme varsa loglarda referans için döndürülen değer
     *         kullanılabilir.
     */
    public String detect(byte[] xmlBytes) {
        if (xmlBytes == null || xmlBytes.length == 0) {
            return null;
        }
        if (indexOfBytes(xmlBytes, SNIFF_MARKER_ETSI) < 0) {
            return null;
        }
        if (indexOfBytes(xmlBytes, SNIFF_MARKER_XSD) < 0) {
            return null;
        }

        String xml;
        try {
            xml = new String(xmlBytes, StandardCharsets.ISO_8859_1);
        } catch (Exception e) {
            logger.debug("Legacy TR XAdES detector: charset decode hatası: {}", e.getMessage());
            return null;
        }

        Matcher m = LEGACY_TYPE_URI_PATTERN.matcher(xml);
        if (m.find()) {
            String hit = m.group(2);
            logger.warn("Legacy Türkiye XAdES Type URI tespit edildi: '{}'. "
                    + "Kriptografik imza sağlam ise tolerans uygulanacak.", hit);
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
