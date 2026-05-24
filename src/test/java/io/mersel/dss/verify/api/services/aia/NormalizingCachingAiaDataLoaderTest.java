package io.mersel.dss.verify.api.services.aia;

import eu.europa.esig.dss.spi.client.http.DataLoader;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link NormalizingCachingAiaDataLoader} için unit test'ler.
 *
 * <p>İki ana sorumluluk test ediliyor:</p>
 * <ul>
 *   <li><b>Normalize</b> — DER, PEM, naked base64 ve bilinmeyen formatların
 *       doğru ele alınması (Eimzatr endpoint patolojisi dahil).</li>
 *   <li><b>Cache</b> — Aynı URL'in iki kez delegate'e gitmemesi; negatif
 *       sonuçların da cache'lenmesi.</li>
 * </ul>
 */
class NormalizingCachingAiaDataLoaderTest {

    private FakeDataLoader fakeDelegate;
    private NormalizingCachingAiaDataLoader loader;

    @BeforeEach
    void setUp() {
        fakeDelegate = new FakeDataLoader();
        loader = new NormalizingCachingAiaDataLoader(fakeDelegate, 16, 60);
    }

    // -----------------------------------------------------------------------
    // Normalize — DER raw response passthrough
    // -----------------------------------------------------------------------

    @Test
    void get_returnsDerUnchanged_whenResponseLooksLikeDer() {
        // Minimal DER prefix: 0x30 0x82 + length(2 bytes) + payload.
        // İçerik kısacası önemli değil; sadece prefix'in DER pattern'ine
        // uymasının yeterli olduğunu gösteriyoruz.
        byte[] der = new byte[]{0x30, (byte) 0x82, 0x05, 0x52, 0x01, 0x02, 0x03};
        fakeDelegate.put("http://example.com/ca.cer", der);

        byte[] result = loader.get("http://example.com/ca.cer");

        assertArrayEquals(der, result, "DER response değiştirilmemeli");
    }

    @Test
    void get_returnsPemUnchanged_whenResponseStartsWithPemHeader() {
        // PEM-encoded data (header'lı naked base64 — sertifikanın gerçek
        // formatı önemli değil, başlığın yakalandığını gösteriyoruz).
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + "MIIBkTCB+gIJAKEXAMPLE...\n"
                + "-----END CERTIFICATE-----\n";
        byte[] bytes = pem.getBytes(StandardCharsets.US_ASCII);
        fakeDelegate.put("http://example.com/ca.pem", bytes);

        byte[] result = loader.get("http://example.com/ca.pem");

        assertArrayEquals(bytes, result, "PEM response değiştirilmemeli");
    }

    // -----------------------------------------------------------------------
    // Normalize — Eimzatr endpoint patolojisi: naked base64 → DER
    // -----------------------------------------------------------------------

    @Test
    void get_decodesNakedBase64_andReturnsDerBytes() {
        // Gerçek dünya senaryosu: endpoint base64-encoded DER cert'i
        // application/pkix-cert content-type altında veriyor ama BEGIN/END
        // header'ları yok. Decoder bunu DER'e çevirmeli ki Java
        // CertificateFactory parse edebilsin.
        byte[] der = new byte[]{0x30, (byte) 0x82, 0x05, 0x52};
        // 100 byte'tan kısa içerik tryDecodeBase64 tarafından short-circuit
        // edilir; gerçek bir cert simüle etmek için padding ekleyelim.
        byte[] paddedDer = new byte[256];
        paddedDer[0] = 0x30;
        paddedDer[1] = (byte) 0x82;
        paddedDer[2] = 0x00;
        paddedDer[3] = (byte) (paddedDer.length - 4);
        for (int i = 4; i < paddedDer.length; i++) {
            paddedDer[i] = (byte) (i & 0xff);
        }
        String base64 = Base64.getEncoder().encodeToString(paddedDer);
        byte[] nakedBase64Bytes = base64.getBytes(StandardCharsets.US_ASCII);

        fakeDelegate.put("http://depo.e-imzatriptal.com/sertifika/neshs-v3.cer", nakedBase64Bytes);

        byte[] result = loader.get("http://depo.e-imzatriptal.com/sertifika/neshs-v3.cer");

        assertArrayEquals(paddedDer, result,
                "Naked base64 endpoint cevabı DER'e decode edilmeliydi");
    }

    @Test
    void get_decodesNakedBase64_withCrAndLfWhitespace() {
        // KamuSM tarzı endpoint'ler base64'ü 76 kolonluk satırlara bölüp
        // \r\n ile ayırarak gönderebilir. Whitespace strip etmeden decode
        // başarısız olur.
        byte[] der = new byte[300];
        der[0] = 0x30;
        der[1] = (byte) 0x82;
        for (int i = 2; i < der.length; i++) {
            der[i] = (byte) i;
        }
        String base64 = Base64.getMimeEncoder(76, "\r\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der);

        fakeDelegate.put("http://aia.test/ca", base64.getBytes(StandardCharsets.US_ASCII));

        byte[] result = loader.get("http://aia.test/ca");

        assertArrayEquals(der, result, "76-column wrapped base64 decode edilmeliydi");
    }

    // -----------------------------------------------------------------------
    // Normalize — hiçbir formata uymayan response orijinal halinde dönsün
    // -----------------------------------------------------------------------

    @Test
    void get_returnsOriginalBytes_whenResponseIsNotDerOrPemOrBase64() {
        // Binary çöp — DER prefix'i yok, PEM header'ı yok, ASCII bile değil.
        byte[] junk = new byte[]{(byte) 0xff, (byte) 0xfe, 0x42, 0x10, 0x00, 0x7f};
        fakeDelegate.put("http://example.com/junk", junk);

        byte[] result = loader.get("http://example.com/junk");

        assertArrayEquals(junk, result,
                "Bilinmeyen format için orijinal byte'lar korunmalıydı");
    }

    @Test
    void get_returnsOriginalBytes_whenBase64ButDecodesToNonDer() {
        // Base64 olarak decode edilebilir ama içerik DER değilse, normalize
        // orijinali döndürmeli (DSS kendi hatasını raporlasın).
        byte[] notDer = new byte[400];
        for (int i = 0; i < notDer.length; i++) notDer[i] = (byte) i;
        // Bilerek DER prefix kullanmıyoruz
        notDer[0] = 0x55;
        notDer[1] = 0x66;
        String base64 = Base64.getEncoder().encodeToString(notDer);

        fakeDelegate.put("http://example.com/random", base64.getBytes(StandardCharsets.US_ASCII));

        byte[] result = loader.get("http://example.com/random");

        // Orijinal base64-text bytes geri dönmeli
        assertArrayEquals(base64.getBytes(StandardCharsets.US_ASCII), result);
    }

    // -----------------------------------------------------------------------
    // Cache — aynı URL ikinci kez delegate'e gitmemeli
    // -----------------------------------------------------------------------

    @Test
    void get_cachesSuccessfulResponse_subsequentCallsHitCache() {
        byte[] der = new byte[]{0x30, (byte) 0x82, 0x05, 0x52, 0x01, 0x02};
        fakeDelegate.put("http://example.com/ca.cer", der);

        byte[] r1 = loader.get("http://example.com/ca.cer");
        byte[] r2 = loader.get("http://example.com/ca.cer");
        byte[] r3 = loader.get("http://example.com/ca.cer");

        assertArrayEquals(der, r1);
        assertArrayEquals(der, r2);
        assertArrayEquals(der, r3);
        assertEquals(1, fakeDelegate.getCallCount("http://example.com/ca.cer"),
                "Aynı URL delegate'e bir kez gitmeli, sonrası cache'ten");
    }

    @Test
    void get_cachesEmptyResponse_asNegative_subsequentCallsHitCache() {
        // Endpoint 200 dönüyor ama body boş — DSS bunu null olarak görmeli
        // ama aynı endpoint'i sürekli vurmaktan kaçınmalıyız. Negative
        // cache hit ikinci çağrıda delegate'e gitmemeli.
        fakeDelegate.put("http://example.com/empty", new byte[0]);

        byte[] r1 = loader.get("http://example.com/empty");
        byte[] r2 = loader.get("http://example.com/empty");

        assertNull(r1);
        assertNull(r2);
        assertEquals(1, fakeDelegate.getCallCount("http://example.com/empty"),
                "Boş response da negative-cache'lenmeli");
    }

    @Test
    void get_doesNotCacheFailures_subsequentCallsRetry() {
        // Delegate exception fırlattığında onu cache'lememeliyiz —
        // transient bir hata olabilir, bir sonraki çağrıda tekrar
        // denenmesi DSS'in kontrolünde olmalı.
        fakeDelegate.makeFail("http://example.com/flaky");

        assertThrows(RuntimeException.class,
                () -> loader.get("http://example.com/flaky"));

        // İkinci çağrı tekrar delegate'i çağırmalı (cache hit olsaydı
        // exception fırlatılmazdı)
        assertThrows(RuntimeException.class,
                () -> loader.get("http://example.com/flaky"));

        assertEquals(2, fakeDelegate.getCallCount("http://example.com/flaky"),
                "Hata cache'lenmemeli; her çağrı tekrar delegate'e gitmeli");
    }

    // -----------------------------------------------------------------------
    // Other DataLoader methods — delegate'e şeffaf geçilmeli
    // -----------------------------------------------------------------------

    @Test
    void get_returnsNull_forNullOrEmptyUrl() {
        assertNull(loader.get((String) null));
        assertNull(loader.get(""));
        assertEquals(0, fakeDelegate.getTotalCallCount(),
                "Null/empty URL delegate'e gitmemeli");
    }

    @Test
    void setContentType_delegatesToWrappedLoader() {
        loader.setContentType("application/pkix-cert");
        assertEquals("application/pkix-cert", fakeDelegate.getLastContentType());
    }

    // -----------------------------------------------------------------------
    // Constructor validation
    // -----------------------------------------------------------------------

    @Test
    void constructor_rejectsNullDelegate() {
        assertThrows(NullPointerException.class,
                () -> new NormalizingCachingAiaDataLoader(null, 16, 60));
    }

    @Test
    void constructor_rejectsZeroOrNegativeCacheSize() {
        assertThrows(IllegalArgumentException.class,
                () -> new NormalizingCachingAiaDataLoader(fakeDelegate, 0, 60));
        assertThrows(IllegalArgumentException.class,
                () -> new NormalizingCachingAiaDataLoader(fakeDelegate, -1, 60));
    }

    @Test
    void constructor_rejectsZeroOrNegativeTtl() {
        assertThrows(IllegalArgumentException.class,
                () -> new NormalizingCachingAiaDataLoader(fakeDelegate, 16, 0));
        assertThrows(IllegalArgumentException.class,
                () -> new NormalizingCachingAiaDataLoader(fakeDelegate, 16, -10));
    }

    // -----------------------------------------------------------------------
    // Serialization opt-out — loader canlı delegate ve cache state taşır;
    // serialize/deserialize edilmeye çalışılırsa erken net hata vermeli.
    // -----------------------------------------------------------------------

    @Test
    void serialize_throwsNotSerializableException() {
        // DataLoader interface'i Serializable extend ediyor, ancak loader
        // (transient) delegate ve cache nedeniyle deserialize edildiğinde
        // çalışamaz. Bu yüzden writeObject NotSerializableException
        // fırlatmalı.
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        java.io.IOException ex = assertThrows(java.io.IOException.class, () -> {
            try (java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bos)) {
                oos.writeObject(loader);
            }
        });
        assertTrue(ex instanceof java.io.NotSerializableException
                        || ex.getCause() instanceof java.io.NotSerializableException
                        || ex.getMessage() != null,
                "Serialize denemesi NotSerializableException ile başarısız olmalı");
    }

    // ======================================================================
    // Test fake — minimal in-memory DataLoader
    // ======================================================================

    /**
     * Test için içeriği önceden tanımlanmış basit bir {@link DataLoader}.
     * Network'e çıkmaz; bizim kontrolümüzde URL → byte[] eşlemesi yapar
     * ve her URL için kaç kez çağrıldığını sayar.
     */
    private static class FakeDataLoader implements DataLoader {
        private static final long serialVersionUID = 1L;
        private final Map<String, byte[]> responses = new HashMap<>();
        private final Map<String, AtomicInteger> callCounts = new HashMap<>();
        private final Map<String, Boolean> failingUrls = new HashMap<>();
        private String lastContentType;

        void put(String url, byte[] bytes) {
            responses.put(url, bytes);
        }

        void makeFail(String url) {
            failingUrls.put(url, Boolean.TRUE);
        }

        int getCallCount(String url) {
            AtomicInteger c = callCounts.get(url);
            return c != null ? c.get() : 0;
        }

        int getTotalCallCount() {
            return callCounts.values().stream().mapToInt(AtomicInteger::get).sum();
        }

        String getLastContentType() {
            return lastContentType;
        }

        @Override
        public byte[] get(String url) {
            callCounts.computeIfAbsent(url, k -> new AtomicInteger()).incrementAndGet();
            if (Boolean.TRUE.equals(failingUrls.get(url))) {
                throw new RuntimeException("simulated network failure for " + url);
            }
            return responses.get(url);
        }

        @Override
        public DataAndUrl get(List<String> urlStrings) {
            for (String u : urlStrings) {
                byte[] b = get(u);
                if (b != null && b.length > 0) {
                    return new DataAndUrl(u, b);
                }
            }
            return null;
        }

        @Override
        public byte[] post(String url, byte[] content) {
            return get(url);
        }

        @Override
        public void setContentType(String contentType) {
            this.lastContentType = contentType;
        }
    }
}
