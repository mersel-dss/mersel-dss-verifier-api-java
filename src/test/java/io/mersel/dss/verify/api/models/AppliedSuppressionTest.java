package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.verify.api.models.enums.SuppressionCode;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link AppliedSuppression} ve {@link SuppressionCode} için sözleşme test'leri.
 *
 * <p>Bu test'ler API kontratını koruyor: serileştirme alan sırası, kararlı
 * code string'leri, null evidence handling vs. Bir alanı silen veya bir kodu
 * yeniden adlandıran refactor PR'lerinde RED yanmalı.</p>
 */
class AppliedSuppressionTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void allSuppressionCodesFollowMdssNamingConvention() {
        for (SuppressionCode sc : SuppressionCode.values()) {
            assertNotNull(sc.getCode(), "code null olmamalı");
            assertTrue(sc.getCode().startsWith("MDSS-"),
                    "Tüm kodlar 'MDSS-' prefix'iyle başlamalı: " + sc.getCode());
            assertEquals(sc.getCode(), sc.getCode().toUpperCase(),
                    "Kod UPPER-KEBAB-CASE olmalı: " + sc.getCode());
            assertNotNull(sc.getTitle(), "title null olmamalı: " + sc);
            assertNotNull(sc.getDefaultReason(), "defaultReason null olmamalı: " + sc);
            assertNotNull(sc.getSeverity(), "severity null olmamalı: " + sc);
            assertNotNull(sc.getDocsUrl(), "docsUrl null olmamalı: " + sc);
        }
    }

    @Test
    void mdssXadesLegacyTrTypeUri_hasStableCode() {
        // Kararlı API kontratı — bu string asla değişmemeli
        assertEquals("MDSS-XADES-LEGACY-TR-TYPE-URI",
                SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getCode());
        assertEquals("INFO", SuppressionCode.MDSS_XADES_LEGACY_TR_TYPE_URI.getSeverity());
    }

    @Test
    void allSuppressionDocsUrlsPointToRepoDocsFolder() {
        // Hepsi GitHub blob/main/docs/suppressions/<CODE>.md paternine uymalı.
        // Bu guard, birinin yanlışlıkla harici/kırık bir URL'e dönmesine karşı
        // koruma sağlar; "kayıtlı kod" listesinin discoverability'sini sabitler.
        String prefix = "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/suppressions/";
        for (SuppressionCode sc : SuppressionCode.values()) {
            assertTrue(sc.getDocsUrl().startsWith(prefix),
                    "docsUrl beklenen prefix ile başlamalı: " + sc + " -> " + sc.getDocsUrl());
            assertTrue(sc.getDocsUrl().endsWith("/" + sc.getCode() + ".md"),
                    "docsUrl '/<CODE>.md' ile bitmeli: " + sc + " -> " + sc.getDocsUrl());
        }
    }

    @Test
    void serializesToJsonWithExpectedFields() throws Exception {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("detectedTypeUri", "http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties");

        AppliedSuppression s = new AppliedSuppression(
                "MDSS-XADES-LEGACY-TR-TYPE-URI",
                "TR-legacy XAdES SignedProperties Type URI toleransı",
                "Test reason",
                "INFO",
                "INDETERMINATE",
                "SIG_CONSTRAINTS_FAILURE",
                evidence,
                "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/suppressions/MDSS-XADES-LEGACY-TR-TYPE-URI.md");

        String json = mapper.writeValueAsString(s);

        assertTrue(json.contains("\"code\":\"MDSS-XADES-LEGACY-TR-TYPE-URI\""), json);
        assertTrue(json.contains("\"severity\":\"INFO\""), json);
        assertTrue(json.contains("\"originalIndication\":\"INDETERMINATE\""), json);
        assertTrue(json.contains("\"originalSubIndication\":\"SIG_CONSTRAINTS_FAILURE\""), json);
        assertTrue(json.contains("\"detectedTypeUri\""), json);
        assertTrue(json.contains("\"docsUrl\""), json);
    }

    @Test
    void omitsNullFieldsInJson() throws Exception {
        AppliedSuppression s = new AppliedSuppression();
        s.setCode("MDSS-TEST");

        String json = mapper.writeValueAsString(s);

        // @JsonInclude(NON_NULL) garanti
        assertTrue(json.contains("\"code\""));
        assertFalse(json.contains("\"reason\""), "null reason JSON'a yazılmamalı: " + json);
        assertFalse(json.contains("\"evidence\""), "null evidence JSON'a yazılmamalı: " + json);
    }

    @Test
    void evidenceMapIsImmutable() {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("k1", "v1");

        AppliedSuppression s = new AppliedSuppression(
                "MDSS-TEST", "t", "r", "INFO", null, null, evidence, null);

        // Caller'ın kendi map'inde değişiklik AppliedSuppression'a sızmamalı
        evidence.put("k2", "v2");
        assertEquals(1, s.getEvidence().size(), "External mutation suppression'ı etkilememeli");

        // Returned map de immutable olmalı
        assertThrows(UnsupportedOperationException.class,
                () -> s.getEvidence().put("hacked", "x"));
    }

    @Test
    void signatureInfoExposesAppliedSuppressionsField() {
        SignatureInfo si = new SignatureInfo();
        assertNull(si.getAppliedSuppressions());

        AppliedSuppression s = new AppliedSuppression();
        s.setCode("MDSS-TEST");
        si.setAppliedSuppressions(java.util.Collections.singletonList(s));

        assertEquals(1, si.getAppliedSuppressions().size());
        assertEquals("MDSS-TEST", si.getAppliedSuppressions().get(0).getCode());
    }
}
