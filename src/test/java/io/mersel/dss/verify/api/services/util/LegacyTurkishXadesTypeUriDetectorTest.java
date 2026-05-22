package io.mersel.dss.verify.api.services.util;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KamuSM/GİB üreticisinin XAdES Type URI yazım hatasını tespit eden
 * {@link LegacyTurkishXadesTypeUriDetector} için unit test'ler.
 *
 * <p>Detector'ın <em>narrow</em> davranışı kritik: yalnızca dökümante edilmiş
 * paterni (<code>01903 + .xsd + #SignedProperties</code>) yakalamalı, jenerik
 * SIG_CONSTRAINTS bypass'ı oluşturmamalı.</p>
 */
class LegacyTurkishXadesTypeUriDetectorTest {

    private final LegacyTurkishXadesTypeUriDetector detector =
            new LegacyTurkishXadesTypeUriDetector();

    @Test
    void detect_returnsHit_whenAxaStyleLegacyTypeUriPresent() {
        String xml = "<root>"
                + "<ds:Reference Id=\"SP-Ref\" "
                + "Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\" "
                + "URI=\"#SP\"/>"
                + "</root>";

        String hit = detector.detect(xml.getBytes(StandardCharsets.UTF_8));

        assertNotNull(hit, "Üretici hatasını yakalamadı");
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

    @Test
    void detect_returnsNull_forStandardXades132Uri() {
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903#SignedProperties\" URI=\"#SP\"/>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)),
                "Standart Type URI'sini yanlışlıkla flag'ledi");
    }

    @Test
    void detect_returnsNull_forXades111LegacyUri() {
        String xml = "<ds:Reference "
                + "Type=\"http://uri.etsi.org/01903/v1.1.1#SignedProperties\" URI=\"#SP\"/>";

        assertNull(detector.detect(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void detect_returnsNull_forXades122LegacyUri() {
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
}
