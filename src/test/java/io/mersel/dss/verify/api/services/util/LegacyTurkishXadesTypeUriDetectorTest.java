package io.mersel.dss.verify.api.services.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KamuSM/GİB üreticisinin XAdES Type URI yazım hatalarını tespit eden
 * {@link LegacyTurkishXadesTypeUriDetector} için unit test'ler.
 *
 * <p>Detector'ın <em>narrow</em> davranışı kritik: iki spesifik patolojiyi
 * yakalamalı (<code>.xsd</code> karışıklığı + <code>v1.3.2/v1.4.1</code>
 * versiyon-prefix'i), DSS'in zaten kabul ettiği legacy URI'leri (v1.1.1,
 * v1.2.2) yanlışlıkla flag'lememeli ve jenerik SIG_CONSTRAINTS bypass'ı
 * oluşturmamalı.</p>
 */
class LegacyTurkishXadesTypeUriDetectorTest {

    private final LegacyTurkishXadesTypeUriDetector detector =
            new LegacyTurkishXadesTypeUriDetector();

    // -----------------------------------------------------------------------
    // P1 — "xsd karışıklığı" varyantı
    // -----------------------------------------------------------------------

    @Test
    void detect_returnsHit_whenAxaStyleLegacyTypeUriPresent() {
        String xml = "<root>"
                + "<ds:Reference Id=\"SP-Ref\" "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\" "
                + "URI=\"#SP\"/>"
                + "</root>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly, "Üretici hatasını (xsd varyantı) yakalamadı");
        assertEquals(LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT, anomaly.getKind());
        assertEquals("http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties",
                anomaly.getEvidence());
    }

    @Test
    void detect_isCaseInsensitiveOnTagAndAttributeNames() {
        String xml = "<DS:REFERENCE TYPE=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\" "
                + "URI=\"#SP\"/>";

        assertNotNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_handlesAlternateNamespacePrefix() {
        // Bazı imzalama araçları "dsig:" veya prefix-yok kullanır
        String xml = "<dsig:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\"/>";

        assertNotNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));

        String xml2 = "<Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\"/>";
        assertNotNull(detector.detectAnomaly(xml2.getBytes(StandardCharsets.UTF_8)));
    }

    // -----------------------------------------------------------------------
    // P2 — "versiyon prefix'i yanlış" varyantı (Sabancı / Türkiye Sigorta)
    // -----------------------------------------------------------------------

    @Test
    void detect_returnsHit_forXades132VersionedTypeUri() {
        // DSS XAdES 1.3.2 için versiyonsuz Type URI bekler; bazı üretici
        // araçlar versiyon prefix'ini namespace ile karıştırıp Type'a da
        // ekliyor.
        String xml = "<root>"
                + "<ds:Reference Id=\"SP\" "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2#SignedProperties\" "
                + "URI=\"#SP\"/>"
                + "</root>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly, "v1.3.2 versiyon-prefix varyantı yakalanmadı");
        assertEquals(LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT, anomaly.getKind());
        assertEquals("http://uri.etsi.org/01903/v1.3.2#SignedProperties",
                anomaly.getEvidence());
    }

    @Test
    void detect_returnsHit_forXades141VersionedTypeUri() {
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.4.1#SignedProperties\" "
                + "URI=\"#SP\"/>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly, "v1.4.1 versiyon-prefix varyantı yakalanmadı");
        assertEquals(LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT, anomaly.getKind());
        assertEquals("http://uri.etsi.org/01903/v1.4.1#SignedProperties",
                anomaly.getEvidence());
    }

    @Test
    void detect_versionedPattern_isCaseInsensitive() {
        String xml = "<DS:REFERENCE "
                + "TYPE=\"http://uri.etsi.org/01903/v1.3.2#SignedProperties\" "
                + "URI=\"#SP\"/>";

        assertNotNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_versionedPattern_acceptsHttps() {
        String xml = "<ds:Reference "
                + "Type=\"https://uri.etsi.org/01903/v1.3.2#SignedProperties\" "
                + "URI=\"#SP\"/>";

        assertNotNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    // -----------------------------------------------------------------------
    // Negative cases — DSS'in zaten kabul ettiği URI'leri flag'lememeli
    // -----------------------------------------------------------------------

    @Test
    void detect_returnsNull_forStandardXades132Uri() {
        // XAdES 1.3.2'nin DSS tarafından beklenen standart Type URI'si:
        // versiyonsuz form.
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#SP\"/>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)),
                "Standart Type URI'sini yanlışlıkla flag'ledi");
    }

    @Test
    void detect_returnsNull_forXades111LegacyUri() {
        // DSS XAdES 1.1.1 path'i bu URI'yi tanır → BBB_SAV_ISQPMDOSPP zaten
        // oluşmaz, tolerance gate'ine düşürmeye gerek yok.
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.1.1#SignedProperties\" URI=\"#SP\"/>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_forXades122LegacyUri() {
        // DSS XAdES 1.2.2 path'i bu URI'yi tanır → null dönmeli.
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.2.2#SignedProperties\" URI=\"#SP\"/>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_whenXmlEmpty() {
        assertNull(detector.detectAnomaly(null));
        assertNull(detector.detectAnomaly(new byte[0]));
    }

    @Test
    void detect_returnsNull_whenNoEtsi01903AtAll() {
        String xml = "<root><ds:Reference Type=\"#Foo\"/></root>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_whenXsdAppearsOutsideTypeAttribute() {
        // .xsd kelimesi schemaLocation gibi başka bir attribute'ta geçebilir;
        // Type attribute'unda olmadıkça pattern eşleşmez.
        String xml = "<root xsi:schemaLocation=\"some-XAdES.xsd\">"
                + "<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "</root>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_forUnrelatedXsdLikeUri() {
        // "01903" + ".xsd" beraber geçiyor ama "#SignedProperties" yok →
        // pattern eşleşmemeli (örn. başka bir element referansı)
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/XAdES.xsd#OtherElement\"/>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_forUnknownVersionInVersionedPattern() {
        // v1.5.0 gibi var olmayan bir versiyon "v1.3.2/v1.4.1" allow-list
        // dışında — pattern eşleşmemeli. Bu, gelecekte ortaya çıkabilecek
        // başka XAdES versiyon prefix'lerini sessizce affetmemizi engelliyor.
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.5.0#SignedProperties\"/>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_handlesIso88591EncodedTurkishContent() {
        // SignatureValue base64'tür ama Türkçe karakterli içerik XML body'sinde
        // olabilir (faturalar). ISO-8859-1 byte-perfect roundtrip garantisi var.
        StringBuilder sb = new StringBuilder()
                .append("<root>")
                .append("<note>İmza geçerli — Türkçe karakterler: çğıöşü</note>")
                .append("<ds:Reference Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\"/>")
                .append("</root>");
        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);

        assertNotNull(detector.detectAnomaly(bytes));
    }

    @Test
    void detect_handlesVersionedPatternInsideRealUblEnvelope() {
        // UBL ApplicationResponse içinde XAdES Signature, Type attribute'u
        // versiyon-prefix yazım hatasıyla. ETSI sniff marker'ı ("01903")
        // namespace declaration'da da geçiyor — bu negatif filtreyi
        // tetiklememek için iyi bir senaryo.
        String xml = "<ApplicationResponse xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Signature>"
                + "<ds:Reference Id=\"SP-Ref\" "
                + "URI=\"#SignedProperties_1\" "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2#SignedProperties\"/>"
                + "</ds:Signature>"
                + "</ApplicationResponse>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly);
        assertEquals(LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT, anomaly.getKind());
        assertEquals("http://uri.etsi.org/01903/v1.3.2#SignedProperties",
                anomaly.getEvidence());
    }

    // -----------------------------------------------------------------------
    // P3 — SignedProperties referansı eksik (tek referanslı XAdES imza)
    // -----------------------------------------------------------------------

    /**
     * Tek referanslı XAdES imza repro'su: tek <code>ds:Reference URI=""</code>
     * (enveloped-signature transform), SignedProperties Object altında var
     * ama referans yok. ETSI namespace declaration'ı sniff marker'ı tetikler;
     * detectAnomaly'nin MISSING_SP_REFERENCE dönmesi beklenir.
     */
    @Test
    void detectAnomaly_returnsMissingSpReference_whenOnlyOneReferenceAndSignedPropertiesUnlinked() {
        String xml = "<Invoice xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Signature Id=\"Sig-1\">"
                + "<ds:SignedInfo>"
                + "<ds:Reference Id=\"All-Ref\" URI=\"\">"
                + "<ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></ds:Transforms>"
                + "<ds:DigestValue>aaa</ds:DigestValue>"
                + "</ds:Reference>"
                + "</ds:SignedInfo>"
                + "<ds:Object>"
                + "<xades:QualifyingProperties>"
                + "<xades:SignedProperties Id=\"SignedProperties_Sig-1\">"
                + "<xades:SignedSignatureProperties><xades:SigningTime>2026-05-18T16:16:43+03:00</xades:SigningTime></xades:SignedSignatureProperties>"
                + "</xades:SignedProperties>"
                + "</xades:QualifyingProperties>"
                + "</ds:Object>"
                + "</ds:Signature>"
                + "</Invoice>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly, "missing-SP-reference varyantı yakalanmadı");
        assertEquals(LegacyTurkishXadesAnomaly.Kind.MISSING_SP_REFERENCE, anomaly.getKind());
        assertEquals("SignedProperties_Sig-1", anomaly.getEvidence());
    }

    @Test
    void detectAnomaly_returnsNull_whenSpReferencedByUriFragment() {
        // Standart XAdES: Reference URI="#SP-1" SignedProperties Id="SP-1"
        // → DSS zaten kabul eder, BBB_SAV_ISQPMDOSPP oluşmaz; detector
        // hiçbir patoloji raporlamamalı.
        String xml = "<root xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Reference URI=\"#SP-1\" Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<ds:Reference URI=\"\"/>"
                + "<xades:SignedProperties Id=\"SP-1\"/>"
                + "</root>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detectAnomaly_returnsNull_whenSpReferencedByTypeOnlyEvenWithoutUriFragment() {
        // Birisi SignedProperties'i URI yerine sadece Type ile referans
        // ediyorsa (teknik olarak geçersiz ama olsun), P3 değil — Type URI
        // ZATEN "/01903.*#SignedProperties" formatında, dolayısıyla
        // ANY_SIGNED_PROPERTIES_TYPE_REFERENCE_PATTERN bunu yakalar ve
        // missing-SP-reference iddiası geçersiz olur.
        String xml = "<root xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<xades:SignedProperties Id=\"SP-X\"/>"
                + "</root>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detectAnomaly_typeUriVariantWinsOverMissingSpReference() {
        // İmza hem Type URI yazım hatalı hem de "referans yok" gibi
        // görünüyorsa, detector P1/P2'yi ÖNCE raporlamalı — daha spesifik
        // patoloji.
        String xml = "<root xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Reference URI=\"#X\" "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\"/>"
                + "<xades:SignedProperties Id=\"SP-Other\"/>"
                + "</root>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly);
        assertEquals(LegacyTurkishXadesAnomaly.Kind.TYPE_URI_VARIANT, anomaly.getKind());
    }

    @Test
    void detectAnomaly_returnsNull_whenNoSignedPropertiesElement() {
        // Plain XMLDSig (XAdES yok) — SignedProperties zaten yok, P3
        // tetiklenmemeli. ETSI sniff marker'ı yok da olabilir.
        String xml = "<root><ds:Reference URI=\"\"/></root>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detectAnomaly_handlesPrefixlessSignedPropertiesElement() {
        // Bazı imza üreticileri default namespace kullanır (prefix-yok).
        // SignedProperties Id'si hala yakalanabilmeli.
        String xml = "<root xmlns=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<Signature><SignedInfo><Reference URI=\"\"/></SignedInfo>"
                + "<Object><SignedProperties Id=\"NoPrefixSP\"/></Object></Signature>"
                + "</root>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly);
        assertEquals(LegacyTurkishXadesAnomaly.Kind.MISSING_SP_REFERENCE, anomaly.getKind());
        assertEquals("NoPrefixSP", anomaly.getEvidence());
    }

    @Test
    void detectAnomaly_returnsNull_whenMultipleSignedPropertiesAllReferenced() {
        // Multi-signature senaryosu: iki ayrı SignedProperties var ve
        // ikisi de URI fragment ile referansta. P3 patolojisi yok.
        String xml = "<root xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Reference URI=\"#SP-A\" Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<ds:Reference URI=\"#SP-B\" Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<xades:SignedProperties Id=\"SP-A\"/>"
                + "<xades:SignedProperties Id=\"SP-B\"/>"
                + "</root>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detectAnomaly_flagsUnreferencedSp_inMixedMultiSignatureScenario() {
        // İki imza: A'nın SP'si URI fragment ile bağlı (doğru), B'nin SP'si
        // hiçbir referansta yok (P3 patolojisi). Önceki tek-pass mantık
        // A'daki Type=SignedProperties Reference'ından dolayı B'yi
        // kaçırıyordu; yeni per-Id mantık B'yi yakalamalı.
        String xml = "<root xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Signature Id=\"Sig-A\">"
                + "<ds:Reference URI=\"\"/>"
                + "<ds:Reference URI=\"#SP-A\" Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<ds:Object><xades:SignedProperties Id=\"SP-A\"/></ds:Object>"
                + "</ds:Signature>"
                + "<ds:Signature Id=\"Sig-B\">"
                + "<ds:Reference URI=\"\"/>"
                + "<ds:Object><xades:SignedProperties Id=\"SP-B\"/></ds:Object>"
                + "</ds:Signature>"
                + "</root>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly, "Mixed multi-sig'te referanssız SP yakalanmadı");
        assertEquals(LegacyTurkishXadesAnomaly.Kind.MISSING_SP_REFERENCE, anomaly.getKind());
        assertEquals("SP-B", anomaly.getEvidence());
    }

    @Test
    void detectAnomaly_returnsNull_whenAllSpsReferencedDespiteExtraTypeOnlyReference() {
        // Multi-sig: SP-A ve SP-B'nin ikisi de URI fragment ile bağlı,
        // ayrıca bir adet Type-only Reference daha var (URI'siz). Type-only
        // Reference hangi SP'ye işaret ettiği belirsiz; ama URI fragment'lar
        // zaten tüm SP'leri kapsadığı için P3 patolojisi yok.
        String xml = "<root xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Reference URI=\"#SP-A\" Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<ds:Reference URI=\"#SP-B\" Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "<xades:SignedProperties Id=\"SP-A\"/>"
                + "<xades:SignedProperties Id=\"SP-B\"/>"
                + "</root>";

        assertNull(detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detectAnomaly_flagsFirstUnreferencedSp_whenBothMissingInMultiSig() {
        // Multi-sig'te iki SP de URI fragment'ında değil → ilk eşleşmeyen
        // (XML doc-order'da) flag edilir.
        String xml = "<root xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">"
                + "<ds:Reference URI=\"\"/>"
                + "<xades:SignedProperties Id=\"SP-First\"/>"
                + "<xades:SignedProperties Id=\"SP-Second\"/>"
                + "</root>";

        LegacyTurkishXadesAnomaly anomaly =
                detector.detectAnomaly(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(anomaly);
        assertEquals(LegacyTurkishXadesAnomaly.Kind.MISSING_SP_REFERENCE, anomaly.getKind());
        assertEquals("SP-First", anomaly.getEvidence());
    }
}
