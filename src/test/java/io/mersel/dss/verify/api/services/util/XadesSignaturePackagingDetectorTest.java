package io.mersel.dss.verify.api.services.util;

import io.mersel.dss.verify.api.models.enums.SignaturePackaging;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * {@link XadesSignaturePackagingDetector}'ın tip-bazlı (sıra-bağımsız)
 * algoritmasını davranışsal olarak doğrular.
 *
 * <p>Senaryolar TÜBİTAK BES (SignedProperties önce) ve DSS-orijinal
 * (data önce) sıralamaların hepsinde aynı doğru sonucu vermesini garanti
 * eder. Asıl regresyon korumamız bu: ileride algoritma pozisyonel veya
 * "transform var mı?" heuristic'ine kayarsa testler kırılır.</p>
 */
class XadesSignaturePackagingDetectorTest {

    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String XADES_NS = "http://uri.etsi.org/01903/v1.3.2#";

    private XadesSignaturePackagingDetector detector;
    private DocumentBuilder docBuilder;

    @BeforeEach
    void setUp() throws Exception {
        detector = new XadesSignaturePackagingDetector();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        docBuilder = dbf.newDocumentBuilder();
    }

    // ---------- TÜBİTAK BES ordering (SignedProperties, data, KeyInfo) ----------

    @Test
    @DisplayName("TÜBİTAK ordering + enveloped-signature transform → ENVELOPED")
    void tubitakOrdering_withEnvelopedTransform_returnsEnveloped() throws Exception {
        Element sig = parseSignature(buildSignature(
                referenceSignedProperties("#xades-id-1"),
                referenceData("", /* withEnvelopedTransform */ true, /* type */ null),
                referenceKeyInfo("#keyInfo-id-1")
        ));

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-1");

        assertEquals(SignaturePackaging.ENVELOPED, result);
    }

    @Test
    @DisplayName("TÜBİTAK ordering + URI=\"\" without transform → ENVELOPED (root-sign)")
    void tubitakOrdering_emptyUriNoTransform_returnsEnveloped() throws Exception {
        Element sig = parseSignature(buildSignature(
                referenceSignedProperties("#xades-id-1"),
                referenceData("", false, null),
                referenceKeyInfo("#keyInfo-id-1")
        ));

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-2");

        assertEquals(SignaturePackaging.ENVELOPED, result);
    }

    @Test
    @DisplayName("TÜBİTAK ordering + URI=#objId pointing to ds:Object → ENVELOPING")
    void tubitakOrdering_uriPointsToInternalObject_returnsEnveloping() throws Exception {
        String objId = "data-obj-1";
        String xml = "<ds:Signature xmlns:ds=\"" + DS_NS + "\" Id=\"sig-3\">"
                + "  <ds:SignedInfo>"
                + "    " + referenceSignedProperties("#xades-id-1")
                + "    " + referenceData("#" + objId, false,
                        "http://www.w3.org/2000/09/xmldsig#Object")
                + "    " + referenceKeyInfo("#keyInfo-id-1")
                + "  </ds:SignedInfo>"
                + "  <ds:Object Id=\"" + objId + "\">payload</ds:Object>"
                + "</ds:Signature>";

        Element sig = parseSignature(xml);

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-3");

        assertEquals(SignaturePackaging.ENVELOPING, result);
    }

    @Test
    @DisplayName("TÜBİTAK ordering + external URI without transform → DETACHED")
    void tubitakOrdering_externalUri_returnsDetached() throws Exception {
        Element sig = parseSignature(buildSignature(
                referenceSignedProperties("#xades-id-1"),
                referenceData("http://example.com/file.xml", false, null),
                referenceKeyInfo("#keyInfo-id-1")
        ));

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-4");

        assertEquals(SignaturePackaging.DETACHED, result);
    }

    // ---------- DSS original ordering (data, SignedProperties, KeyInfo) ----------
    // KRİTİK: Tip-bazlı algoritma sıralamadan bağımsız çalışmalı. DSS-sıralı
    // imzalar TÜBİTAK-sıralı muadilleriyle AYNI sonucu vermeli; pozisyon
    // önemli değil.

    @Test
    @DisplayName("DSS ordering (data first) + enveloped transform on data → ENVELOPED "
            + "(sıralamadan bağımsız, İMZAGER ile uyumlu)")
    void dssOriginalOrdering_envelopedTransformOnDataAtPos0_returnsEnveloped() throws Exception {
        Element sig = parseSignature(buildSignature(
                referenceData("", /* withEnvelopedTransform */ true, /* type */ null),
                referenceSignedProperties("#xades-id-1"),
                referenceKeyInfo("#keyInfo-id-1")
        ));

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-5");

        assertEquals(SignaturePackaging.ENVELOPED, result,
                "DSS-orijinal sıralamada bile data ref tip ile bulunmalı → ENVELOPED");
    }

    @Test
    @DisplayName("DSS ordering + URI=#objId → ENVELOPING (sıralamadan bağımsız)")
    void dssOriginalOrdering_internalObject_returnsEnveloping() throws Exception {
        String objId = "data-obj-9";
        String xml = "<ds:Signature xmlns:ds=\"" + DS_NS + "\" Id=\"sig-6\">"
                + "  <ds:SignedInfo>"
                + "    " + referenceData("#" + objId, false,
                        "http://www.w3.org/2000/09/xmldsig#Object")
                + "    " + referenceSignedProperties("#xades-id-1")
                + "    " + referenceKeyInfo("#keyInfo-id-1")
                + "  </ds:SignedInfo>"
                + "  <ds:Object Id=\"" + objId + "\">payload</ds:Object>"
                + "</ds:Signature>";

        Element sig = parseSignature(xml);

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-6");

        assertEquals(SignaturePackaging.ENVELOPING, result);
    }

    // ---------- Real-world AXA SİGORTA pattern (regresyon koruması) ----------

    @Test
    @DisplayName("AXA SİGORTA e-Fatura ApplicationResponse pattern: 2-ref DSS-ordered "
            + "+ KamuSM legacy SignedProperties Type URI → ENVELOPED")
    void axaSigortaApplicationResponsePattern_returnsEnveloped() throws Exception {
        // Bu test, /Users/erdembas/Desktop/411AA5CE-D6CA-470B-8CF1-1E22D523DC4A.envelope.xml
        // yapısını birebir taklit eder. KRİTİK detaylar:
        //   - Sadece 2 reference (KeyInfo ref yok)
        //   - DSS-orijinal sıralama: Reference[0]=data, Reference[1]=SignedProperties
        //   - SignedProperties Type URI'si KamuSM legacy varyantında:
        //     "http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties"
        //   - Reference[0]: URI="" + enveloped-signature transform
        //   - Signature içinde QualifyingProperties için bir ds:Object var
        //
        // İMZAGER bu dosyayı "Tümleşik" (W3C ENVELOPED) olarak raporlar.
        // Bizim de aynı sonucu vermemiz lazım.
        String xml = "<ds:Signature xmlns:ds=\"" + DS_NS + "\""
                + " xmlns:xades=\"" + XADES_NS + "\""
                + " Id=\"Signature_axa_test\">"
                + "  <ds:SignedInfo>"
                + "    <ds:Reference URI=\"\">"
                + "      <ds:Transforms>"
                + "        <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                + "      </ds:Transforms>"
                + "      <ds:DigestValue>bOU7FpnUi3pTzhG/29nOKw==</ds:DigestValue>"
                + "    </ds:Reference>"
                + "    <ds:Reference"
                + "        Type=\"http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties\""
                + "        URI=\"#SignedProperties_axa_test\">"
                + "      <ds:DigestValue>ob4sAmmYZCCmoKb0BQwD8A==</ds:DigestValue>"
                + "    </ds:Reference>"
                + "  </ds:SignedInfo>"
                + "  <ds:Object>"
                + "    <xades:QualifyingProperties Target=\"#Signature_axa_test\">"
                + "      <xades:SignedProperties Id=\"SignedProperties_axa_test\"/>"
                + "    </xades:QualifyingProperties>"
                + "  </ds:Object>"
                + "</ds:Signature>";

        Element sig = parseSignature(xml);

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "Signature_axa_test");

        assertEquals(SignaturePackaging.ENVELOPED, result,
                "AXA e-Fatura pattern: KamuSM legacy SignedProperties Type URI meta "
                        + "olarak filtrelenmeli, data ref enveloped-signature transform ile "
                        + "ENVELOPED'e düşmeli");
    }

    // ---------- Edge cases ----------

    @Test
    @DisplayName("Tek Reference (saf XMLDSig, XAdES değil) + URI=\"\" + transform → ENVELOPED")
    void singleReference_envelopedTransform_returnsEnveloped() throws Exception {
        Element sig = parseSignature("<ds:Signature xmlns:ds=\"" + DS_NS + "\">"
                + "  <ds:SignedInfo>"
                + "    " + referenceData("", true, null)
                + "  </ds:SignedInfo>"
                + "</ds:Signature>");

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-7");

        assertEquals(SignaturePackaging.ENVELOPED, result);
    }

    @Test
    @DisplayName("Hiç Reference yok → null")
    void noReferences_returnsNull() throws Exception {
        Element sig = parseSignature("<ds:Signature xmlns:ds=\"" + DS_NS + "\">"
                + "  <ds:SignedInfo/>"
                + "</ds:Signature>");

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-8");

        assertNull(result);
    }

    @Test
    @DisplayName("SignedInfo yok → null")
    void noSignedInfo_returnsNull() throws Exception {
        Element sig = parseSignature("<ds:Signature xmlns:ds=\"" + DS_NS + "\"/>");

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-9");

        assertNull(result);
    }

    @Test
    @DisplayName("UnsignedSignatureProperties altındaki Reference'lar sayılmamalı")
    void nestedReferencesUnderUnsignedProps_areIgnored() throws Exception {
        // Tip-bazlı algoritma SignedInfo'nun direct child'larına bakar.
        // Timestamp veya manifest içindeki Reference'lar dahil edilmemeli.
        String xml = "<ds:Signature xmlns:ds=\"" + DS_NS + "\""
                + " xmlns:xades=\"" + XADES_NS + "\" Id=\"sig-10\">"
                + "  <ds:SignedInfo>"
                + "    " + referenceSignedProperties("#xades-id-1")
                + "    " + referenceData("", true, null)
                + "  </ds:SignedInfo>"
                + "  <ds:Object>"
                + "    <xades:QualifyingProperties>"
                + "      <xades:UnsignedSignatureProperties>"
                + "        <xades:SignatureTimeStamp>"
                + "          <ds:Reference URI=\"http://evil.example.com\"/>"
                + "        </xades:SignatureTimeStamp>"
                + "      </xades:UnsignedSignatureProperties>"
                + "    </xades:QualifyingProperties>"
                + "  </ds:Object>"
                + "</ds:Signature>";

        Element sig = parseSignature(xml);

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-10");

        assertEquals(SignaturePackaging.ENVELOPED, result,
                "UnsignedSignatureProperties altındaki Reference'lar paketleme "
                        + "kararına etki etmemeli");
    }

    @Test
    @DisplayName("Tek meta reference (SignedProperties) + data reference yok → null")
    void onlyMetaReference_returnsNull() throws Exception {
        Element sig = parseSignature("<ds:Signature xmlns:ds=\"" + DS_NS + "\">"
                + "  <ds:SignedInfo>"
                + "    " + referenceSignedProperties("#xades-id-1")
                + "  </ds:SignedInfo>"
                + "</ds:Signature>");

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-11");

        assertNull(result,
                "Sadece meta ref varsa paketleme kararı verilemez — null");
    }

    @Test
    @DisplayName("KeyInfo Type'lı reference de meta sayılmalı (sınıflandırmaya etkimemeli)")
    void keyInfoTypedReferenceIsMeta() throws Exception {
        Element sig = parseSignature(buildSignature(
                referenceSignedProperties("#xades-id-1"),
                referenceData("", true, null),
                referenceKeyInfo("#keyInfo-id-1")
        ));

        SignaturePackaging result = detector.detectFromSignatureElement(sig, "sig-12");

        assertEquals(SignaturePackaging.ENVELOPED, result,
                "KeyInfo X509Data Type'lı ref data ref değil — sonuç hâlâ ENVELOPED");
    }

    // ---------- Helpers ----------

    private String buildSignature(String... references) {
        StringBuilder sb = new StringBuilder();
        sb.append("<ds:Signature xmlns:ds=\"").append(DS_NS).append("\">");
        sb.append("  <ds:SignedInfo>");
        for (String r : references) {
            sb.append("    ").append(r);
        }
        sb.append("  </ds:SignedInfo>");
        sb.append("</ds:Signature>");
        return sb.toString();
    }

    private String referenceSignedProperties(String uri) {
        return "<ds:Reference"
                + " Type=\"http://uri.etsi.org/01903#SignedProperties\""
                + " URI=\"" + uri + "\"/>";
    }

    private String referenceKeyInfo(String uri) {
        return "<ds:Reference"
                + " Type=\"http://www.w3.org/2000/09/xmldsig#X509Data\""
                + " URI=\"" + uri + "\"/>";
    }

    private String referenceData(String uri, boolean withEnvelopedTransform, String type) {
        StringBuilder sb = new StringBuilder();
        sb.append("<ds:Reference URI=\"").append(uri).append("\"");
        if (type != null) {
            sb.append(" Type=\"").append(type).append("\"");
        }
        sb.append(">");
        if (withEnvelopedTransform) {
            sb.append("<ds:Transforms>")
                    .append("<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>")
                    .append("</ds:Transforms>");
        }
        sb.append("</ds:Reference>");
        return sb.toString();
    }

    private Element parseSignature(String xml) throws Exception {
        Document doc = docBuilder.parse(
                new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        return doc.getDocumentElement();
    }
}
