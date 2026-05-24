package io.mersel.dss.verify.api.services.aia;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * AIA (Authority Information Access) için <strong>normalizing + caching</strong>
 * {@link DataLoader} dekoratörü. Bir delegate {@code DataLoader}'i (tipik
 * {@code CommonsDataLoader}) sarar; iki sorunu birden çözer:
 *
 * <h3>1) Normalizing — TR ekosistemindeki non-standard endpoint cevaplarını affet</h3>
 * <p>Bazı TR ESHS'leri ara CA sertifikasını
 * <code>Content-Type: application/pkix-cert</code> ile servis ederken
 * <em>raw DER yerine naked base64-encoded text</em> dönüyor (örnek:
 * <code>http://depo.e-imzatriptal.com/sertifika/neshs-v3.cer</code>). Java
 * <code>CertificateFactory</code> raw DER veya BEGIN/END header'lı PEM kabul
 * eder; naked base64'ü reddeder ve DSS <code>NO_CERTIFICATE_CHAIN_FOUND</code>
 * döner. Bu dekoratör, response byte'larını şu sırayla değerlendirir:</p>
 * <ol>
 *   <li><b>DER mi?</b> İlk byte <code>0x30</code> ve ikinci byte
 *       <code>0x82</code> ise (ASN.1 SEQUENCE long-form length tag, X.509
 *       sertifikaların prefix'i) — olduğu gibi döner.</li>
 *   <li><b>PEM mi?</b> İçerikte <code>-----BEGIN</code> marker'ı varsa — DSS
 *       ve Java <code>CertificateFactory</code> bunu zaten parse eder, olduğu
 *       gibi döner.</li>
 *   <li><b>Naked base64 mi?</b> Whitespace'i strip et, Base64 decode dene;
 *       decode'lanmış byte'lar DER prefix'iyle başlıyorsa — <strong>decoded
 *       DER byte'larını döner</strong>. Bu sayede DSS şikayet etmeden parse
 *       eder.</li>
 *   <li>Hiçbiri eşleşmezse — orijinal byte'ları döner (DSS kendi hatasını
 *       loglayacak, biz durumu maskelemiyoruz).</li>
 * </ol>
 *
 * <p>Normalize işlemi <strong>idempotent</strong>: zaten DER veya PEM olan
 * response'a dokunulmaz; yalnızca bozuk endpoint cevaplarını onarır.</p>
 *
 * <h3>2) Caching — Aynı ara CA URL'ine tekrar git'me</h3>
 * <p>KamuSM ekosisteminde aktif ara CA sayısı çok düşük (<=20 endpoint). Bir
 * dakika içinde gelen birkaç doğrulama isteğinin hepsi aynı ara CA'yı fetch
 * eder; Caffeine cache ile aynı URL bir kez vurulur, sonraki istekler bellekten
 * cevaplanır. Ara CA sertifikalarının geçerlilik süresi yıllarca olduğu için
 * 24 saat TTL tamamen güvenli (default).</p>
 *
 * <p><strong>Thread-safety</strong>: Caffeine cache thread-safe;
 * normalize işlemi stateless; Spring singleton bean olarak güvenle
 * paylaşılabilir.</p>
 *
 * <p><strong>Sınırlar</strong>: Yalnızca GET çağrılarını cache'ler. POST
 * (DSS AIA için POST kullanmaz), setContentType ve <code>get(List)</code>
 * çağrıları delegate'e şeffafça iletilir.</p>
 */
public class NormalizingCachingAiaDataLoader implements DataLoader {

    private static final long serialVersionUID = 1L;

    private static final Logger logger =
            LoggerFactory.getLogger(NormalizingCachingAiaDataLoader.class);

    /** Negative cache marker — null storeable değil ama "URL boş döndü" durumunu unutmak istemiyoruz. */
    private static final byte[] NEGATIVE_MARKER = new byte[0];

    private final transient DataLoader delegate;
    private final transient Cache<String, byte[]> cache;

    /**
     * @param delegate          asıl HTTP fetch yapan DataLoader (tipik
     *                          {@code CommonsDataLoader})
     * @param maxCacheSize      cache'te tutulacak maksimum URL sayısı
     * @param cacheTtlSeconds   her cache entry'nin TTL'i (saniye)
     */
    public NormalizingCachingAiaDataLoader(DataLoader delegate,
                                           long maxCacheSize,
                                           long cacheTtlSeconds) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        if (maxCacheSize <= 0) {
            throw new IllegalArgumentException("maxCacheSize must be > 0, was: " + maxCacheSize);
        }
        if (cacheTtlSeconds <= 0) {
            throw new IllegalArgumentException("cacheTtlSeconds must be > 0, was: " + cacheTtlSeconds);
        }
        this.cache = Caffeine.newBuilder()
                .maximumSize(maxCacheSize)
                .expireAfterWrite(cacheTtlSeconds, TimeUnit.SECONDS)
                .recordStats()
                .build();
        logger.info("NormalizingCachingAiaDataLoader initialized: delegate={}, maxSize={}, ttlSeconds={}",
                delegate.getClass().getSimpleName(), maxCacheSize, cacheTtlSeconds);
    }

    @Override
    public byte[] get(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        byte[] cached = cache.getIfPresent(url);
        if (cached != null) {
            if (cached == NEGATIVE_MARKER) {
                logger.debug("AIA cache hit (negative): {}", url);
                return null;
            }
            logger.debug("AIA cache hit: url={}, bytes={}", url, cached.length);
            return cached;
        }
        logger.info("AIA fetch: {}", url);
        byte[] raw;
        try {
            raw = delegate.get(url);
        } catch (RuntimeException e) {
            logger.warn("AIA fetch failed for url='{}': {}", url, e.getMessage());
            // Hatayı cache'lemiyoruz — transient olabilir, bir sonraki çağrıda
            // tekrar denenmesi DSS'in kontrolünde olsun.
            throw e;
        }

        if (raw == null || raw.length == 0) {
            logger.info("AIA fetch returned empty for url='{}'; cached as negative", url);
            cache.put(url, NEGATIVE_MARKER);
            return null;
        }

        byte[] normalized = normalize(raw, url);
        cache.put(url, normalized);
        logger.info("AIA cached: url={}, originalBytes={}, normalizedBytes={}",
                url, raw.length, normalized.length);
        return normalized;
    }

    @Override
    public DataAndUrl get(List<String> urlStrings) {
        // Multi-URL sequential fetch — DSS AIA pratikte single URL kullanır
        // ama interface contract'ı için delegate ediyoruz. Cache yok burada
        // çünkü hangi URL'den geldiği önemli; single-URL get() üzerinden gitse
        // de aynı sonuç.
        return delegate.get(urlStrings);
    }

    @Override
    public byte[] post(String url, byte[] content) {
        // DSS AIA fetch'i HTTP GET kullanır; POST burada tipik olarak
        // çağrılmaz. Tam delegasyon, cache yok.
        return delegate.post(url, content);
    }

    @Override
    public void setContentType(String contentType) {
        delegate.setContentType(contentType);
    }

    /**
     * Response byte'larını normalize eder. JavaDoc'ta açıklanan üç senaryoyu
     * sırayla değerlendirir.
     */
    static byte[] normalize(byte[] raw, String urlForLog) {
        if (looksLikeDer(raw)) {
            return raw;
        }
        if (looksLikePem(raw)) {
            return raw;
        }
        byte[] decoded = tryDecodeBase64(raw);
        if (decoded != null && looksLikeDer(decoded)) {
            logger.info("AIA response normalized: url='{}' was naked base64 (content-type lying), "
                    + "decoded to DER ({} bytes)", urlForLog, decoded.length);
            return decoded;
        }
        // Hiçbir bilinen forma uymuyor — orijinali döndür. DSS kendi hatasını
        // raporlasın; biz "tahmin ederek" yanlış bir şey üretmeyelim.
        logger.warn("AIA response did not match DER, PEM, or naked base64 patterns "
                + "(url='{}', first 16 bytes hex={}). Returning original.",
                urlForLog, hexPrefix(raw, 16));
        return raw;
    }

    /**
     * DER X.509 sertifika prefix'i tespiti: ASN.1 SEQUENCE tag
     * (<code>0x30</code>) + long-form length byte (<code>0x82</code>). Bu
     * her gerçek X.509 cert için sabit (cert'ler her zaman 256+ byte uzun
     * olduğundan long-form length kullanılır).
     */
    private static boolean looksLikeDer(byte[] b) {
        return b != null && b.length >= 4
                && (b[0] & 0xff) == 0x30 && (b[1] & 0xff) == 0x82;
    }

    /**
     * PEM marker tespiti: ilk 64 byte içinde <code>-----BEGIN</code> görmek
     * yeterli (CERTIFICATE / X509 CERTIFICATE varyantları için tek ortak
     * substring).
     */
    private static boolean looksLikePem(byte[] b) {
        if (b == null || b.length < 11) {
            return false;
        }
        int headLen = Math.min(b.length, 64);
        String head = new String(b, 0, headLen, StandardCharsets.US_ASCII);
        return head.contains("-----BEGIN");
    }

    /**
     * Naked base64 decode denemesi. Whitespace strip → MIME decoder
     * (76-column tolerant). Decode başarısız olursa veya sonuç çok kısaysa
     * (X.509 minimum birkaç yüz byte) <code>null</code> döner.
     */
    private static byte[] tryDecodeBase64(byte[] raw) {
        if (raw.length < 100) {
            // Bir base64-encoded X.509 cert tipik olarak 1500+ byte; çok
            // küçükse zaten cert değil, base64 hipotezi anlamsız.
            return null;
        }
        // Hızlı sanity: tüm byte'lar ASCII printable + whitespace mi?
        for (int i = 0; i < raw.length; i++) {
            int c = raw[i] & 0xff;
            boolean ok = (c >= 0x20 && c <= 0x7e)
                    || c == 0x09 || c == 0x0a || c == 0x0d;
            if (!ok) {
                return null;
            }
        }
        try {
            String text = new String(raw, StandardCharsets.US_ASCII);
            String stripped = text.replaceAll("\\s+", "");
            // Whitespace strip sonrası uzunluk ASCII heuristic'i geçmeli.
            // Aşırı küçük string'leri base64 decode etmeyi anlamsız tut.
            if (stripped.length() < 100) {
                return null;
            }
            byte[] decoded = Base64.getDecoder().decode(stripped);
            return decoded;
        } catch (IllegalArgumentException e) {
            // Base64 değildi
            return null;
        } catch (Exception e) {
            logger.debug("AIA normalize: base64 decode unexpected error: {}", e.getMessage());
            return null;
        }
    }

    private static String hexPrefix(byte[] b, int len) {
        int n = Math.min(b.length, len);
        StringBuilder sb = new StringBuilder(n * 3);
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", b[i] & 0xff));
        }
        return sb.toString();
    }

    /**
     * Test ve observability için Caffeine cache instance'ına public erişim.
     * Spring config'i ({@link io.mersel.dss.verify.api.config.RevocationServicesConfiguration})
     * bu cache'i Micrometer registry'sine bağlayarak Prometheus metric'lerini
     * (<code>cache_gets_total{cache="mersel.aia.fetch"}</code> vb.) üretir.
     */
    public Cache<String, byte[]> caffeineCache() {
        return cache;
    }

    /**
     * <strong>Serializable contract opt-out.</strong>
     * {@link DataLoader} {@link java.io.Serializable} extends ettiği için
     * compiler bu sınıfa da Serializable katıyor; ancak dekoratörün canlı
     * durumu (HTTP delegate ve Caffeine cache) transient — deserialize
     * edildiğinde her ikisi de <code>null</code> olur ve sonraki çağrı NPE
     * atar. Bu yüzden serialization'ı yöntem seviyesinde reddediyoruz; bir
     * Spring singleton bean'in serialize edilmeye çalışılması (örn. session
     * replication, distributed cache) erkenden net hatayla sonuçlanır.
     */
    private void writeObject(ObjectOutputStream out) throws IOException {
        throw new NotSerializableException(
                "NormalizingCachingAiaDataLoader is a Spring singleton with live "
                        + "delegate and Caffeine cache state; serialization is not supported.");
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        throw new NotSerializableException(
                "NormalizingCachingAiaDataLoader is a Spring singleton with live "
                        + "delegate and Caffeine cache state; deserialization is not supported.");
    }
}
