package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AppliedSuppression} v2 audit metadata alanları için sözleşme
 * (kontrat) testleri. Bu alanlar tolerance gate v2'nin "forensic
 * grade" kanıt yazma yeteneğinin temel taşı:
 *
 * <ul>
 *   <li>{@code gateVersion} — kararın hangi gate sürümüyle alındığı</li>
 *   <li>{@code allowedFailureKeys} — pozitif tarafta beklenen izinli set</li>
 *   <li>{@code observedFailureKeys} — gerçekten gözlenen FAIL key'leri</li>
 *   <li>{@code documentSha256} + {@code documentSizeBytes} — forensic
 *       dispute için tam o byte dizisinin kanıtı</li>
 * </ul>
 *
 * <p><em>Tarihsel not:</em> v2.0/v2.1'de buraya bir
 * {@code reValidationVerdict} alanı da eklenmişti; v2.2'de re-validation
 * katmanı kaldırıldığı için alan da silindi.</p>
 */
class AppliedSuppressionAuditMetadataTest {

    private static final String SAMPLE_CODE = "MDSS-XADES-LEGACY-TR-TYPE-URI";
    private static final String SAMPLE_TITLE = "TR Legacy XAdES Type URI";

    // -------------------------------------------------------------------------
    // Legacy 8-args constructor — backward compatibility
    // -------------------------------------------------------------------------

    @Test
    void legacyConstructor_leavesAuditFieldsNull() {
        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, SAMPLE_TITLE, "reason", "INFO",
                "INDETERMINATE", "SIG_CONSTRAINTS_FAILURE",
                Collections.singletonMap("k", "v"), "https://docs/example");

        assertNull(s.getGateVersion(),
                "Legacy constructor audit alanları doldurmaz; "
                        + "geriye uyumlu davranış.");
        assertNull(s.getAllowedFailureKeys());
        assertNull(s.getObservedFailureKeys());
        assertNull(s.getDocumentSha256());
        assertNull(s.getDocumentSizeBytes());
        assertEquals(SAMPLE_CODE, s.getCode());
        assertEquals("reason", s.getReason());
        assertNotNull(s.getEvidence());
        assertEquals("v", s.getEvidence().get("k"));
    }

    // -------------------------------------------------------------------------
    // Audit-zengin constructor (gate v2)
    // -------------------------------------------------------------------------

    @Test
    void auditConstructor_populatesAllForensicFields() {
        Set<String> allowed = new LinkedHashSet<>(Collections.singletonList("BBB_SAV_ISQPMDOSPP"));
        Set<String> observed = new LinkedHashSet<>(Collections.singletonList("BBB_SAV_ISQPMDOSPP"));
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("detectedTypeUri", "http://uri.etsi.org/01903/v1.3.2/XAdES.xsd#SignedProperties");

        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, SAMPLE_TITLE, "reason", "INFO",
                "INDETERMINATE", "SIG_CONSTRAINTS_FAILURE",
                evidence, "https://docs/example",
                "v2.2", allowed, observed,
                "abcd1234", 12345L);

        assertEquals("v2.2", s.getGateVersion());
        assertEquals(allowed, s.getAllowedFailureKeys());
        assertEquals(observed, s.getObservedFailureKeys());
        assertEquals("abcd1234", s.getDocumentSha256());
        assertEquals(Long.valueOf(12345L), s.getDocumentSizeBytes());
    }

    @Test
    void auditConstructor_supportsNullCollectionsGracefully() {
        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, SAMPLE_TITLE, "reason", "INFO",
                "INDETERMINATE", "SIG_CONSTRAINTS_FAILURE",
                null, "https://docs/example",
                "v2.2", null, null,
                null, null);

        assertEquals("v2.2", s.getGateVersion());
        assertNull(s.getAllowedFailureKeys());
        assertNull(s.getObservedFailureKeys());
        assertNull(s.getDocumentSha256());
        assertNull(s.getDocumentSizeBytes());
    }

    // -------------------------------------------------------------------------
    // Defensive copy: getter'lar immutable referans döndürmeli
    // -------------------------------------------------------------------------

    @Test
    void allowedFailureKeys_isUnmodifiableThroughGetter() {
        Set<String> allowed = new LinkedHashSet<>(Arrays.asList("BBB_SAV_ISQPMDOSPP"));
        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, null, null, null, null, null, null, null,
                "v2.2", allowed, null, null, null);

        assertThrows(UnsupportedOperationException.class,
                () -> s.getAllowedFailureKeys().add("INJECTED"),
                "Getter, dış kodun audit set'ini kirletmesini engellemeli.");
    }

    @Test
    void observedFailureKeys_isUnmodifiableThroughGetter() {
        Set<String> observed = new LinkedHashSet<>(Arrays.asList("BBB_SAV_ISQPMDOSPP"));
        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, null, null, null, null, null, null, null,
                "v2.2", null, observed, null, null);

        assertThrows(UnsupportedOperationException.class,
                () -> s.getObservedFailureKeys().add("INJECTED"));
    }

    @Test
    void allowedFailureKeys_isDefensivelyCopiedFromInput() {
        Set<String> input = new LinkedHashSet<>(Arrays.asList("BBB_SAV_ISQPMDOSPP"));
        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, null, null, null, null, null, null, null,
                "v2.2", input, null, null, null);

        // Input set'i sonradan değişirse audit kaydı etkilenmemeli
        input.add("ATTACKER_INJECTED");
        assertFalse(s.getAllowedFailureKeys().contains("ATTACKER_INJECTED"),
                "Defensive copy: input mutation audit kaydını bozmamalı.");
    }

    @Test
    void setterAccepts_andDefensivelyCopiesInput() {
        AppliedSuppression s = new AppliedSuppression();
        Set<String> input = new LinkedHashSet<>(Arrays.asList("BBB_SAV_ISQPMDOSPP"));
        s.setAllowedFailureKeys(input);

        input.add("ATTACKER_INJECTED");
        assertFalse(s.getAllowedFailureKeys().contains("ATTACKER_INJECTED"));
        assertThrows(UnsupportedOperationException.class,
                () -> s.getAllowedFailureKeys().add("X"));
    }

    // -------------------------------------------------------------------------
    // JSON serialization — @JsonInclude(NON_NULL) sözleşmesi
    // -------------------------------------------------------------------------

    @Test
    void jsonSerialization_omitsNullAuditFieldsForLegacyConstructor() throws Exception {
        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, SAMPLE_TITLE, "reason", "INFO",
                "INDETERMINATE", "SIG_CONSTRAINTS_FAILURE",
                null, "https://docs/example");

        String json = new ObjectMapper().writeValueAsString(s);
        assertFalse(json.contains("gateVersion"),
                "Legacy constructor null bıraktığı için JSON'da görünmemeli.");
        assertFalse(json.contains("allowedFailureKeys"));
        assertFalse(json.contains("observedFailureKeys"));
        assertFalse(json.contains("documentSha256"));
        assertFalse(json.contains("documentSizeBytes"));
        assertFalse(json.contains("reValidationVerdict"),
                "v2.2'de re-validation katmanı kaldırıldı — alan JSON'da görünmemeli.");
        assertTrue(json.contains("\"code\":\"" + SAMPLE_CODE + "\""));
    }

    @Test
    void jsonSerialization_includesAllAuditFieldsWhenSet() throws Exception {
        Set<String> observed = new LinkedHashSet<>(Collections.singletonList("BBB_SAV_ISQPMDOSPP"));
        Set<String> allowed = new LinkedHashSet<>(Collections.singletonList("BBB_SAV_ISQPMDOSPP"));
        AppliedSuppression s = new AppliedSuppression(
                SAMPLE_CODE, SAMPLE_TITLE, "reason", "INFO",
                "INDETERMINATE", "SIG_CONSTRAINTS_FAILURE",
                null, "https://docs/example",
                "v2.2", allowed, observed,
                "deadbeef", 200L);

        String json = new ObjectMapper().writeValueAsString(s);
        assertTrue(json.contains("\"gateVersion\":\"v2.2\""));
        assertTrue(json.contains("\"allowedFailureKeys\":[\"BBB_SAV_ISQPMDOSPP\"]"));
        assertTrue(json.contains("\"observedFailureKeys\":[\"BBB_SAV_ISQPMDOSPP\"]"));
        assertTrue(json.contains("\"documentSha256\":\"deadbeef\""));
        assertTrue(json.contains("\"documentSizeBytes\":200"));
        assertFalse(json.contains("reValidationVerdict"),
                "v2.2'de re-validation katmanı kaldırıldı; alan modelden silindi.");
    }
}
