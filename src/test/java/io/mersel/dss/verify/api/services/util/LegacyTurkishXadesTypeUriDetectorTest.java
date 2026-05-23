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

        String hit = detector.detect(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(hit, "Üretici hatasını (xsd varyantı) yakalamadı");
        assertEquals("http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties", hit);
    }

    @Test
    void detect_isCaseInsensitiveOnTagAndAttributeNames() {
        String xml = "<DS:REFERENCE TYPE=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\" "
                + "URI=\"#SP\"/>";

        assertNotNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_handlesAlternateNamespacePrefix() {
        // Bazı imzalama araçları "dsig:" veya prefix-yok kullanır
        String xml = "<dsig:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\"/>";

        assertNotNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));

        String xml2 = "<Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\"/>";
        assertNotNull(detector.detect(xml2.getBytes(StandardCharsets.UTF_8)));
    }

    // -----------------------------------------------------------------------
    // P2 — "versiyon prefix'i yanlış" varyantı (Sabancı / Türkiye Sigorta)
    // -----------------------------------------------------------------------

    @Test
    void detect_returnsHit_forXades132VersionedTypeUri() {
        // Sabancı Dijital / Türkiye Sigorta envelope'larında görülen varyant.
        // DSS XAdES 1.3.2 için versiyonsuz Type URI bekler; tool versiyon
        // prefix'ini namespace ile karıştırıp Type'a da eklemiş.
        String xml = "<root>"
                + "<ds:Reference Id=\"SP\" "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2#SignedProperties\" "
                + "URI=\"#SP\"/>"
                + "</root>";

        String hit = detector.detect(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(hit, "v1.3.2 versiyon-prefix varyantı yakalanmadı");
        assertEquals("http://uri.etsi.org/01903/v1.3.2#SignedProperties", hit);
    }

    @Test
    void detect_returnsHit_forXades141VersionedTypeUri() {
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.4.1#SignedProperties\" "
                + "URI=\"#SP\"/>";

        String hit = detector.detect(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(hit, "v1.4.1 versiyon-prefix varyantı yakalanmadı");
        assertEquals("http://uri.etsi.org/01903/v1.4.1#SignedProperties", hit);
    }

    @Test
    void detect_versionedPattern_isCaseInsensitive() {
        String xml = "<DS:REFERENCE "
                + "TYPE=\"http://uri.etsi.org/01903/v1.3.2#SignedProperties\" "
                + "URI=\"#SP\"/>";

        assertNotNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_versionedPattern_acceptsHttps() {
        String xml = "<ds:Reference "
                + "Type=\"https://uri.etsi.org/01903/v1.3.2#SignedProperties\" "
                + "URI=\"#SP\"/>";

        assertNotNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
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

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)),
                "Standart Type URI'sini yanlışlıkla flag'ledi");
    }

    @Test
    void detect_returnsNull_forXades111LegacyUri() {
        // DSS XAdES 1.1.1 path'i bu URI'yi tanır → BBB_SAV_ISQPMDOSPP zaten
        // oluşmaz, tolerance gate'ine düşürmeye gerek yok.
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.1.1#SignedProperties\" URI=\"#SP\"/>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_forXades122LegacyUri() {
        // DSS XAdES 1.2.2 path'i bu URI'yi tanır → null dönmeli.
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.2.2#SignedProperties\" URI=\"#SP\"/>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_whenXmlEmpty() {
        assertNull(detector.detect(null));
        assertNull(detector.detect(new byte[0]));
    }

    @Test
    void detect_returnsNull_whenNoEtsi01903AtAll() {
        String xml = "<root><ds:Reference Type=\"#Foo\"/></root>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_whenXsdAppearsOutsideTypeAttribute() {
        // .xsd kelimesi schemaLocation gibi başka bir attribute'ta geçebilir;
        // Type attribute'unda olmadıkça pattern eşleşmez.
        String xml = "<root xsi:schemaLocation=\"some-XAdES.xsd\">"
                + "<ds:Reference Type=\"http://uri.etsi.org/01903#SignedProperties\"/>"
                + "</root>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_forUnrelatedXsdLikeUri() {
        // "01903" + ".xsd" beraber geçiyor ama "#SignedProperties" yok →
        // pattern eşleşmemeli (örn. başka bir element referansı)
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/XAdES.xsd#OtherElement\"/>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_forUnknownVersionInVersionedPattern() {
        // v1.5.0 gibi var olmayan bir versiyon "v1.3.2/v1.4.1" allow-list
        // dışında — pattern eşleşmemeli. Bu, gelecekte ortaya çıkabilecek
        // başka XAdES versiyon prefix'lerini sessizce affetmemizi engelliyor.
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.5.0#SignedProperties\"/>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_handlesIso88591EncodedTurkishContent() {
        // SignatureValue base64'tür ama Türkçe karakterli içerik XML body'sinde
        // olabilir (faturalar). ISO-8859-1 byte-perfect roundtrip garantisi var.
        StringBuilder sb = new StringBuilder()
                .append("<root>")
                .append("<note>İmza geçerli — şirket bilgisi: AXA SİGORTA</note>")
                .append("<ds:Reference Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\"/>")
                .append("</root>");
        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);

        assertNotNull(detector.detect(bytes));
    }

    @Test
    void detect_handlesVersionedPatternInsideRealUblEnvelope() {
        // Sabancı / Türkiye Sigorta envelope'unun gerçek dünya minimal repro'su:
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

        String hit = detector.detect(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(hit);
        assertEquals("http://uri.etsi.org/01903/v1.3.2#SignedProperties", hit);
    }
}
