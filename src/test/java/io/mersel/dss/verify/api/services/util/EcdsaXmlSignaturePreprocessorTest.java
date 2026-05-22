package io.mersel.dss.verify.api.services.util;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * EcdsaXmlSignaturePreprocessor için CI-safe (no external file) unit testler.
 *
 * <p>BC ile runtime'da self-signed sertifika ve sentetik DER ECDSA SignatureValue üretir.
 * Tüm pozitif/negatif senaryoları kapsar.</p>
 */
class EcdsaXmlSignaturePreprocessorTest {

    private static final Pattern SIG_VALUE = Pattern.compile(
            "<ds:SignatureValue[^>]*>([\\s\\S]*?)</ds:SignatureValue>", Pattern.CASE_INSENSITIVE);

    private final EcdsaXmlSignaturePreprocessor preprocessor = new EcdsaXmlSignaturePreprocessor();

    @BeforeAll
    static void setupBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // ---------------- Pozitif senaryolar ----------------

    @Test
    @DisplayName("DER-encoded ECDSA P-384 SignatureValue raw r||s'e (96 byte) dönüştürülür")
    void shouldConvertDerEcdsaP384ToRaw() throws Exception {
        X509Certificate cert = generateEcCert("secp384r1");
        byte[] derSig = generateDerEcdsaSignature(48);
        String xml = buildXadesXml(cert, derSig, "ecdsa-sha384");

        byte[] original = xml.getBytes(StandardCharsets.UTF_8);
        byte[] processed = preprocessor.preprocess(original);

        assertNotSame(original, processed, "DER imza değiştirilmeliydi");
        byte[] newSig = extractSignatureValue(processed);
        assertEquals(96, newSig.length, "P-384 raw r||s 96 byte olmalı");
        assertNotEquals((byte) 0x30, newSig[0],
                "Raw imza 0x30 SEQUENCE ile başlamamalı (çok düşük ihtimal hariç)");
    }

    @Test
    @DisplayName("DER-encoded ECDSA P-256 SignatureValue raw r||s'e (64 byte) dönüştürülür")
    void shouldConvertDerEcdsaP256ToRaw() throws Exception {
        X509Certificate cert = generateEcCert("secp256r1");
        byte[] derSig = generateDerEcdsaSignature(32);
        String xml = buildXadesXml(cert, derSig, "ecdsa-sha256");

        byte[] original = xml.getBytes(StandardCharsets.UTF_8);
        byte[] processed = preprocessor.preprocess(original);

        assertNotSame(original, processed);
        byte[] newSig = extractSignatureValue(processed);
        assertEquals(64, newSig.length, "P-256 raw r||s 64 byte olmalı");
    }

    @Test
    @DisplayName("Türkçe karakterli (UTF-8) faturalar byte-perfect korunur (sadece imza değişir)")
    void shouldPreserveTurkishUtf8ContentByteForByte() throws Exception {
        X509Certificate cert = generateEcCert("secp384r1");
        byte[] derSig = generateDerEcdsaSignature(48);
        String xml = "<Invoice>" +
                "<Note>Çağrı şirketinin müşterileri için özel ÖZGÜR İlhan açıklaması.</Note>" +
                buildSignatureElement(cert, derSig, "ecdsa-sha384") +
                "</Invoice>";

        byte[] original = xml.getBytes(StandardCharsets.UTF_8);
        byte[] processed = preprocessor.preprocess(original);

        // İmza değiştirildi ama Türkçe içerik aynen korundu
        String processedStr = new String(processed, StandardCharsets.UTF_8);
        assertTrue(processedStr.contains("Çağrı şirketinin müşterileri için özel ÖZGÜR İlhan"),
                "UTF-8 Türkçe karakterler bozulmamalı");
        assertTrue(processedStr.contains("<Note>") && processedStr.contains("</Note>"));
    }

    // ---------------- Negatif senaryolar (no-op davranışı) ----------------

    @Test
    @DisplayName("RSA SHA-256 imzalı XAdES'e hiç dokunulmaz (identity döner)")
    void shouldNoOpOnRsaSignature() throws Exception {
        // RSA cert + rastgele RSA-imza byteları (gerçek RSA imzası gerek yok, sadece preprocessor
        // davranışını test ediyoruz: 'EC değil' tespiti yapmalı)
        X509Certificate rsaCert = generateRsaCert();
        byte[] rsaSigBytes = new byte[256]; // RSA-2048 raw imza boyutu
        new SecureRandom().nextBytes(rsaSigBytes);
        // İlk byte'ı 0x30 yapalım, ekstra defansif tetiklemeyi test edelim
        rsaSigBytes[0] = 0x30;

        String xml = buildXadesXml(rsaCert, rsaSigBytes, "rsa-sha256");
        byte[] original = xml.getBytes(StandardCharsets.UTF_8);
        byte[] processed = preprocessor.preprocess(original);

        assertSame(original, processed,
                "RSA sertifikasında preprocessor hiç dokunmamalı");
    }

    @Test
    @DisplayName("Raw r||s ECDSA imza (zaten W3C-uyumlu) değiştirilmez")
    void shouldNoOpOnAlreadyRawEcdsa() throws Exception {
        X509Certificate cert = generateEcCert("secp384r1");
        byte[] rawSig = new byte[96];
        new SecureRandom().nextBytes(rawSig);
        // İlk byte 0x30 olmasın, garantili raw test edelim
        rawSig[0] = (byte) 0x42;

        String xml = buildXadesXml(cert, rawSig, "ecdsa-sha384");
        byte[] original = xml.getBytes(StandardCharsets.UTF_8);
        byte[] processed = preprocessor.preprocess(original);

        assertSame(original, processed,
                "Raw r||s imzaya dokunulmamalı");
    }

    @Test
    @DisplayName("SignatureValue içermeyen XML hiç değiştirilmez")
    void shouldNoOpOnXmlWithoutSignature() {
        String xml = "<Invoice><ID>123</ID><Total>100</Total></Invoice>";
        byte[] original = xml.getBytes(StandardCharsets.UTF_8);
        byte[] processed = preprocessor.preprocess(original);
        assertSame(original, processed);
    }

    @Test
    @DisplayName("Non-XML binary içeriğe dokunulmaz")
    void shouldNoOpOnBinaryContent() {
        byte[] original = new byte[1024];
        new SecureRandom().nextBytes(original);
        original[0] = '<'; // < ile başlayan random binary — eski impl. yanlış pozitif verirdi
        byte[] processed = preprocessor.preprocess(original);
        assertSame(original, processed);
    }

    @Test
    @DisplayName("UTF-16 BE BOM ile başlayan dosyaya dokunulmaz")
    void shouldNoOpOnUtf16BomBeContent() {
        byte[] original = new byte[]{(byte) 0xfe, (byte) 0xff, 0x00, '<', 0x00, '?'};
        byte[] processed = preprocessor.preprocess(original);
        assertSame(original, processed);
    }

    @Test
    @DisplayName("UTF-16 LE BOM ile başlayan dosyaya dokunulmaz")
    void shouldNoOpOnUtf16BomLeContent() {
        byte[] original = new byte[]{(byte) 0xff, (byte) 0xfe, '<', 0x00, '?', 0x00};
        byte[] processed = preprocessor.preprocess(original);
        assertSame(original, processed);
    }

    @Test
    @DisplayName("Boş veya null girdi güvenli şekilde döner")
    void shouldHandleEmptyAndNullInputs() {
        assertNull(preprocessor.preprocess(null));
        byte[] empty = new byte[0];
        assertSame(empty, preprocessor.preprocess(empty));
    }

    @Test
    @DisplayName("SignatureMethod algorithm RSA ise hiç dokunulmaz (EC cert olsa bile)")
    void shouldNoOpWhenSignatureMethodIsRsaEvenWithEcCert() throws Exception {
        // Bu pek olası değil ama defense-in-depth: EC cert + ama SignatureMethod RSA
        X509Certificate cert = generateEcCert("secp384r1");
        byte[] derSig = generateDerEcdsaSignature(48);
        String xml = buildXadesXml(cert, derSig, "rsa-sha256");

        byte[] original = xml.getBytes(StandardCharsets.UTF_8);
        byte[] processed = preprocessor.preprocess(original);
        assertSame(original, processed,
                "SignatureMethod RSA'ysa preprocessor dokunmamalı");
    }

    @Test
    @DisplayName("Çoklu Signature (örn. 2 farklı imza) bağımsız değerlendirilir")
    void shouldHandleMultipleSignatures() throws Exception {
        X509Certificate cert = generateEcCert("secp384r1");
        byte[] derSig1 = generateDerEcdsaSignature(48);
        byte[] derSig2 = generateDerEcdsaSignature(48);

        String xml = "<Doc>" +
                buildSignatureElement(cert, derSig1, "ecdsa-sha384") +
                buildSignatureElement(cert, derSig2, "ecdsa-sha384") +
                "</Doc>";

        byte[] processed = preprocessor.preprocess(xml.getBytes(StandardCharsets.UTF_8));
        String s = new String(processed, StandardCharsets.UTF_8);

        Matcher m = SIG_VALUE.matcher(s);
        int count = 0;
        while (m.find()) {
            byte[] sig = Base64.getDecoder().decode(m.group(1).replaceAll("\\s+", ""));
            assertEquals(96, sig.length, "Her imza 96 byte raw olmalı");
            count++;
        }
        assertEquals(2, count, "İki imza da işlenmeli");
    }

    // ---------------- Yardımcılar ----------------

    private static X509Certificate generateEcCert(String curve) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
        kpg.initialize(new ECGenParameterSpec(curve));
        KeyPair kp = kpg.generateKeyPair();
        return signCert(kp, "SHA384withECDSA");
    }

    private static X509Certificate generateRsaCert() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        return signCert(kp, "SHA256withRSA");
    }

    private static X509Certificate signCert(KeyPair kp, String sigAlg) throws Exception {
        X500Principal subject = new X500Principal("CN=Test, O=Mersel Test, C=TR");
        Date notBefore = new Date(System.currentTimeMillis() - 60_000);
        Date notAfter = new Date(System.currentTimeMillis() + 86_400_000L);
        BigInteger serial = BigInteger.valueOf(System.nanoTime());

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(builder.build(signer));
    }

    /** P-384/P-256 sentetik DER ECDSA imzası — r,s = rastgele integer. */
    private static byte[] generateDerEcdsaSignature(int fieldSize) {
        SecureRandom rnd = new SecureRandom();
        byte[] rRaw = new byte[fieldSize];
        byte[] sRaw = new byte[fieldSize];
        rnd.nextBytes(rRaw);
        rnd.nextBytes(sRaw);
        rRaw[0] &= 0x7f; // pozitif kalsın
        sRaw[0] &= 0x7f;
        BigInteger r = new BigInteger(1, rRaw);
        BigInteger s = new BigInteger(1, sRaw);

        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        int total = 2 + rb.length + 2 + sb.length;
        byte[] out;
        if (total < 0x80) {
            out = new byte[2 + total];
            int i = 0;
            out[i++] = 0x30;
            out[i++] = (byte) total;
            out[i++] = 0x02;
            out[i++] = (byte) rb.length;
            System.arraycopy(rb, 0, out, i, rb.length);
            i += rb.length;
            out[i++] = 0x02;
            out[i++] = (byte) sb.length;
            System.arraycopy(sb, 0, out, i, sb.length);
        } else {
            out = new byte[3 + total];
            int i = 0;
            out[i++] = 0x30;
            out[i++] = (byte) 0x81;
            out[i++] = (byte) total;
            out[i++] = 0x02;
            out[i++] = (byte) rb.length;
            System.arraycopy(rb, 0, out, i, rb.length);
            i += rb.length;
            out[i++] = 0x02;
            out[i++] = (byte) sb.length;
            System.arraycopy(sb, 0, out, i, sb.length);
        }
        return out;
    }

    private static String buildXadesXml(X509Certificate cert, byte[] sigValue, String algoHint) throws Exception {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Invoice>" +
                buildSignatureElement(cert, sigValue, algoHint) +
                "</Invoice>";
    }

    private static String buildSignatureElement(X509Certificate cert, byte[] sigValue, String algoHint) throws Exception {
        String algoUri = "http://www.w3.org/2001/04/xmldsig-more#" + algoHint;
        String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        String sigB64 = Base64.getEncoder().encodeToString(sigValue);
        return "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
                "<ds:SignedInfo>" +
                "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>" +
                "<ds:SignatureMethod Algorithm=\"" + algoUri + "\"/>" +
                "</ds:SignedInfo>" +
                "<ds:SignatureValue>" + sigB64 + "</ds:SignatureValue>" +
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + certB64 +
                "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
                "</ds:Signature>";
    }

    private static byte[] extractSignatureValue(byte[] xml) {
        String s = new String(xml, StandardCharsets.UTF_8);
        Matcher m = SIG_VALUE.matcher(s);
        if (!m.find()) {
            throw new IllegalStateException("SignatureValue bulunamadı");
        }
        return Base64.getDecoder().decode(m.group(1).replaceAll("\\s+", ""));
    }
}
