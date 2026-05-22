package io.mersel.dss.verify.api.services.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * GİB / TÜBİTAK Mali Mühür ECDSA imzalı XAdES dokümanları için pre-processor.
 *
 * <p><b>Sorun:</b> W3C XML-DSig (RFC 4051) ECDSA <code>SignatureValue</code>'sini
 * <b>raw r||s</b> concat olarak ister (P-256=64B, P-384=96B, P-521=132B).
 * Türkiye'deki Mali Mühür v3 üreticileri <b>ASN.1 DER SEQUENCE</b> ile imza üretir;
 * Eclipse DSS spec'e harfiyen uyduğu için <code>SIG_CRYPTO_FAILURE</code> verir.</p>
 *
 * <p><b>Çözüm:</b> XML byte'larını DSS'e geçmeden önce inceler ve <i>yalnızca</i>
 * şu tüm koşullar sağlanırsa müdahale eder:</p>
 * <ul>
 *     <li>İçerikte <code>SignatureValue</code> ASCII byte dizisi geçiyor.</li>
 *     <li>UTF-16 BOM yok (UTF-16 dosyalarda no-op).</li>
 *     <li>En az bir <code>X509Certificate</code> parse edilebiliyor.</li>
 *     <li>Bu sertifikanın public key'i <code>ECPublicKey</code>.</li>
 *     <li>(Varsa) <code>SignatureMethod Algorithm</code> URI'si "ecdsa" içeriyor.</li>
 *     <li>SignatureValue Base64'ü gerçekten <code>0x30</code> (DER SEQUENCE) ile başlıyor.</li>
 * </ul>
 *
 * <p>Aksi halde girdi byte dizisi <b>aynı referansla</b> geri döner — sıfır risk.</p>
 *
 * <p><b>Charset:</b> XML byte'larını <code>ISO-8859-1</code> ile decode eder; her
 * byte → 1 char (lossless 1:1). String üzerinde sadece SignatureValue içeriğini
 * değiştirip aynı charset ile geri encode eder. Bu, UTF-8/UTF-16 declaration veya
 * Türkçe karakter (ş, ğ, ı...) içeren faturalarda byte-perfect roundtrip garantiler.</p>
 *
 * <p><b>SignedInfo dokunulmazlığı:</b> <code>SignatureValue</code> <code>SignedInfo</code>
 * içinde değildir; dolayısıyla dönüşüm hiçbir Reference digest'ini bozmaz.</p>
 *
 * <p><b>Thread-safety:</b> Stateless; Pattern'ler immutable, Matcher'lar lokal.</p>
 */
@Component
public class EcdsaXmlSignaturePreprocessor {

    private static final Logger logger = LoggerFactory.getLogger(EcdsaXmlSignaturePreprocessor.class);

    /** Çok büyük dosyalarda string conversion yapmadan önce sniff sınırı. */
    private static final int FAST_SNIFF_THRESHOLD_BYTES = 64 * 1024; // 64 KB

    /** ASCII byte dizisi olarak aranan marker — UTF-16 dahil tüm encoding'lerde güvenli sniff. */
    private static final byte[] SIGNATURE_VALUE_MARKER =
            "SignatureValue".getBytes(StandardCharsets.US_ASCII);

    private static final Pattern SIGNATURE_VALUE_PATTERN = Pattern.compile(
            "(<([\\w-]+:)?SignatureValue\\b[^>]*>)([\\s\\S]*?)(</([\\w-]+:)?SignatureValue\\s*>)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern X509_CERTIFICATE_PATTERN = Pattern.compile(
            "<([\\w-]+:)?X509Certificate\\b[^>]*>([\\s\\S]*?)</([\\w-]+:)?X509Certificate\\s*>",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern SIGNATURE_METHOD_ALGO_PATTERN = Pattern.compile(
            "<([\\w-]+:)?SignatureMethod\\b[^>]*\\bAlgorithm\\s*=\\s*[\"']([^\"']+)[\"']",
            Pattern.CASE_INSENSITIVE);

    /**
     * XML byte'larını işler. Müdahale gerekmiyorsa <b>aynı</b> byte dizisi (identity)
     * geri döner — çağıran taraf <code>processed != original</code> ile değişiklik
     * olup olmadığını tespit edebilir.
     */
    public byte[] preprocess(byte[] originalBytes) {
        if (originalBytes == null || originalBytes.length == 0) {
            return originalBytes;
        }

        // Guard 1: UTF-16 BOM ise hiç dokunma (regex ASCII byte assumption'ı bozulur).
        if (isUtf16Bom(originalBytes)) {
            return originalBytes;
        }

        // Guard 2: ASCII byte düzeyinde SignatureValue marker'ı yoksa hiç string'e çevirme.
        if (indexOfBytes(originalBytes, SIGNATURE_VALUE_MARKER,
                Math.min(originalBytes.length, FAST_SNIFF_THRESHOLD_BYTES * 8)) < 0) {
            return originalBytes;
        }

        // ISO-8859-1: byte ↔ char tam 1:1 (Latin-1 her 256 byte değerini char'a maple).
        // Bu sayede UTF-8/Türkçe karakter içerikli dosyalarda dahi byte-perfect roundtrip
        // garantili (XML SignatureValue ve X509Certificate base64 olduğundan tamamen ASCII'dir).
        String xml = new String(originalBytes, StandardCharsets.ISO_8859_1);

        // Guard 3: Hızlı string-level kontrol (büyük dosyalarda contains O(n)).
        if (xml.indexOf("SignatureValue") < 0) {
            return originalBytes;
        }

        // Guard 4: Sertifika ZORUNLU. EC değilse hiç dokunma (RSA-PSS DER imzasıyla karışmasın).
        int fieldSizeBytes = detectEcFieldSize(xml);
        if (fieldSizeBytes <= 0) {
            logger.debug("ECDSA preprocessor: EC public key bulunamadı, dokuman değiştirilmiyor");
            return originalBytes;
        }

        // Guard 5: SignatureMethod URI'si varsa ECDSA olmalı. Yoksa permissive (eski XAdES'lerde
        // her zaman element bulunmayabilir ama bizim hedef ekosistemde her zaman var).
        if (!signatureMethodMentionsEcdsa(xml)) {
            logger.debug("ECDSA preprocessor: SignatureMethod ECDSA değil, dokuman değiştirilmiyor");
            return originalBytes;
        }

        Matcher matcher = SIGNATURE_VALUE_PATTERN.matcher(xml);
        StringBuffer rewritten = new StringBuffer(xml.length() + 64);
        boolean anyChange = false;
        int rewriteCount = 0;
        int seenCount = 0;

        while (matcher.find()) {
            seenCount++;
            String openTag = matcher.group(1);
            String body = matcher.group(3);
            String closeTag = matcher.group(4);

            // Defensive: SignatureValue içeriğinde XML yorum veya CDATA olmamalı (spec gereği
            // saf base64'tür). Görürsek bu instance'ı atla, koruma odaklı davran.
            if (body.indexOf("<!--") >= 0 || body.indexOf("<![CDATA[") >= 0) {
                logger.debug("ECDSA preprocessor: SignatureValue içinde CDATA/yorum, atlanıyor");
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group(0)));
                continue;
            }

            String b64 = stripWhitespace(body);
            String rewrittenB64 = maybeRewriteSignatureValue(b64, fieldSizeBytes);

            if (rewrittenB64 == null || rewrittenB64.equals(b64)) {
                matcher.appendReplacement(rewritten, Matcher.quoteReplacement(matcher.group(0)));
            } else {
                anyChange = true;
                rewriteCount++;
                matcher.appendReplacement(rewritten,
                        Matcher.quoteReplacement(openTag + rewrittenB64 + closeTag));
            }
        }
        matcher.appendTail(rewritten);

        if (!anyChange) {
            return originalBytes;
        }

        logger.info("GİB Mali Mühür ECDSA SignatureValue normalize edildi (DER -> raw r||s). " +
                "Toplam imza={} Düzeltilen={}", seenCount, rewriteCount);
        return rewritten.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    /**
     * Tek bir Base64 SignatureValue içeriğini inceler. DER-encoded ECDSA ise
     * raw r||s formatına çevrilmiş Base64 döner. Aksi halde <code>null</code>.
     */
    private String maybeRewriteSignatureValue(String b64, int fieldSizeBytes) {
        if (b64 == null || b64.isEmpty()) {
            return null;
        }
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(b64);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (sig.length == 0 || sig[0] != 0x30) {
            return null;
        }
        // Beklenen raw boyutuna zaten eşitse (ve 0x30 sadece tesadüfen ilk byte ise),
        // dokunmaktan kaçın. Tipik raw r||s rastgele byte'lardır, 0x30 olma olasılığı 1/256.
        int expectedRawLen = fieldSizeBytes * 2;
        if (sig.length == expectedRawLen) {
            // İhtimal düşük ama kesin DER mi diye doğrula: SEQ length + iki INTEGER patternı
            if (!looksLikeStrictDerEcdsa(sig)) {
                return null;
            }
        }
        try {
            byte[] raw = derToRawEcdsa(sig, fieldSizeBytes);
            if (raw == null) {
                return null;
            }
            return Base64.getEncoder().encodeToString(raw);
        } catch (Exception e) {
            logger.debug("ECDSA preprocessor: DER->raw dönüşümü başarısız: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Strict DER doğrulaması: SEQ(INT, INT) yapısı tutuyor mu?
     * Raw imza ile karışma riskine karşı ek bir filtre.
     */
    private static boolean looksLikeStrictDerEcdsa(byte[] sig) {
        if (sig.length < 8 || sig[0] != 0x30) return false;
        try {
            int idx = 1;
            int seqLen = readLength(sig, idx);
            idx += lengthOfLengthField(sig, idx);
            if (seqLen <= 0 || idx + seqLen != sig.length) return false;
            if (sig[idx] != 0x02) return false;
            idx++;
            int rLen = readLength(sig, idx);
            idx += lengthOfLengthField(sig, idx);
            if (rLen <= 0 || idx + rLen >= sig.length) return false;
            idx += rLen;
            if (sig[idx] != 0x02) return false;
            idx++;
            int sLen = readLength(sig, idx);
            idx += lengthOfLengthField(sig, idx);
            return sLen > 0 && idx + sLen == sig.length;
        } catch (Exception e) {
            return false;
        }
    }

    /** ECDSA DER SEQUENCE(r,s) -> raw r||s (her biri fieldSize byte). */
    private static byte[] derToRawEcdsa(byte[] der, int fieldSize) {
        int idx = 0;
        if (der[idx++] != 0x30) return null;
        int seqLen = readLength(der, idx);
        idx += lengthOfLengthField(der, idx);
        if (seqLen <= 0 || idx + seqLen > der.length) return null;

        if (der[idx++] != 0x02) return null;
        int rLen = readLength(der, idx);
        idx += lengthOfLengthField(der, idx);
        if (rLen <= 0 || idx + rLen > der.length) return null;
        BigInteger r = new BigInteger(1, slice(der, idx, rLen));
        idx += rLen;

        if (der[idx++] != 0x02) return null;
        int sLen = readLength(der, idx);
        idx += lengthOfLengthField(der, idx);
        if (sLen <= 0 || idx + sLen > der.length) return null;
        BigInteger s = new BigInteger(1, slice(der, idx, sLen));

        byte[] rBytes = toFixedSize(r, fieldSize);
        byte[] sBytes = toFixedSize(s, fieldSize);
        if (rBytes == null || sBytes == null) return null;

        byte[] out = new byte[fieldSize * 2];
        System.arraycopy(rBytes, 0, out, 0, fieldSize);
        System.arraycopy(sBytes, 0, out, fieldSize, fieldSize);
        return out;
    }

    private static byte[] toFixedSize(BigInteger v, int targetSize) {
        byte[] vb = v.toByteArray();
        if (vb.length == targetSize) {
            return vb;
        }
        if (vb.length == targetSize + 1 && vb[0] == 0x00) {
            byte[] trimmed = new byte[targetSize];
            System.arraycopy(vb, 1, trimmed, 0, targetSize);
            return trimmed;
        }
        if (vb.length < targetSize) {
            byte[] padded = new byte[targetSize];
            System.arraycopy(vb, 0, padded, targetSize - vb.length, vb.length);
            return padded;
        }
        return null;
    }

    private static int readLength(byte[] data, int offset) {
        int first = data[offset] & 0xff;
        if ((first & 0x80) == 0) {
            return first;
        }
        int numBytes = first & 0x7f;
        if (numBytes == 0 || numBytes > 4) {
            return -1;
        }
        int len = 0;
        for (int i = 0; i < numBytes; i++) {
            len = (len << 8) | (data[offset + 1 + i] & 0xff);
        }
        return len;
    }

    private static int lengthOfLengthField(byte[] data, int offset) {
        int first = data[offset] & 0xff;
        if ((first & 0x80) == 0) {
            return 1;
        }
        return 1 + (first & 0x7f);
    }

    private static byte[] slice(byte[] data, int offset, int len) {
        byte[] out = new byte[len];
        System.arraycopy(data, offset, out, 0, len);
        return out;
    }

    /**
     * İlk X509Certificate'ı parse ederek EC public key field boyutunu döner.
     * EC değilse veya parse edilemezse 0.
     */
    private int detectEcFieldSize(String xml) {
        Matcher m = X509_CERTIFICATE_PATTERN.matcher(xml);
        while (m.find()) {
            String certB64 = stripWhitespace(m.group(2));
            if (certB64.isEmpty()) continue;
            try {
                byte[] der = Base64.getDecoder().decode(certB64);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
                if (cert.getPublicKey() instanceof ECPublicKey) {
                    ECPublicKey ec = (ECPublicKey) cert.getPublicKey();
                    int fieldBits = ec.getParams().getCurve().getField().getFieldSize();
                    return (fieldBits + 7) / 8;
                }
                // EC değil — non-EC sertifika varsa kesin no-op.
                return 0;
            } catch (Exception e) {
                logger.debug("ECDSA preprocessor: sertifika parse hatası: {}", e.getMessage());
            }
        }
        return 0;
    }

    private boolean signatureMethodMentionsEcdsa(String xml) {
        Matcher m = SIGNATURE_METHOD_ALGO_PATTERN.matcher(xml);
        boolean found = false;
        while (m.find()) {
            found = true;
            String algo = m.group(2).toLowerCase();
            if (algo.contains("ecdsa")) {
                return true;
            }
        }
        // Hiç SignatureMethod element'i yoksa, eski stil bir XAdES'tir; konservatif: dokunma.
        // Var ama ECDSA değilse: RSA imzaya hiç dokunma.
        return !found;
    }

    private static boolean isUtf16Bom(byte[] b) {
        if (b.length < 2) return false;
        int b0 = b[0] & 0xff;
        int b1 = b[1] & 0xff;
        return (b0 == 0xfe && b1 == 0xff) || (b0 == 0xff && b1 == 0xfe);
    }

    /** Byte-level KMP-tarzı arama; basit ama JIT'le iyi optimize olur. */
    private static int indexOfBytes(byte[] haystack, byte[] needle, int upTo) {
        outer:
        for (int i = 0; i <= upTo - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static String stripWhitespace(String s) {
        if (s == null) return null;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c > ' ') {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
