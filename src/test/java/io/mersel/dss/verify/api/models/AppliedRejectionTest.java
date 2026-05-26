package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link AppliedRejection} ve {@link RejectionCode} için sözleşme test'leri.
 *
 * <p>{@code AppliedSuppression}'ın aynası — API kontratını koruyor:
 * serileştirme, kararlı code string'leri, null evidence handling.
 * Bir alanı silen veya bir kodu yeniden adlandıran refactor PR'lerinde
 * RED yanmalı.</p>
 */
class AppliedRejectionTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void allRejectionCodesFollowMdssNamingConvention() {
        for (RejectionCode rc : RejectionCode.values()) {
            assertNotNull(rc.getCode(), "code null olmamalı");
            assertTrue(rc.getCode().startsWith("MDSS-"),
                    "Tüm kodlar 'MDSS-' prefix'iyle başlamalı: " + rc.getCode());
            assertEquals(rc.getCode(), rc.getCode().toUpperCase(),
                    "Kod UPPER-KEBAB-CASE olmalı: " + rc.getCode());
            assertNotNull(rc.getTitle(), "title null olmamalı: " + rc);
            assertNotNull(rc.getDefaultReason(), "defaultReason null olmamalı: " + rc);
            assertNotNull(rc.getSeverity(), "severity null olmamalı: " + rc);
            assertNotNull(rc.getDocsUrl(), "docsUrl null olmamalı: " + rc);
        }
    }

    @Test
    void mdssXadesLegacyTrMissingSpReference_hasStableCodeAndSeverity() {
        // Kararlı API kontratı — bu string asla değişmemeli
        assertEquals("MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
                RejectionCode.MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE.getCode());
        assertEquals("ERROR",
                RejectionCode.MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE.getSeverity());
    }

    @Test
    void mdssXcvSignerKeyUsageInsufficient_hasStableCodeAndSeverity() {
        // Kararlı API kontratı — operatörler ve müşteri istemcileri bu kodu
        // filter/grep'lerine yazacak. Renaming, kullanıcının log
        // alarmlarını sessizce bozar.
        assertEquals("MDSS-XCV-SIGNER-KEY-USAGE-INSUFFICIENT",
                RejectionCode.MDSS_XCV_SIGNER_KEY_USAGE_INSUFFICIENT.getCode());
        assertEquals("ERROR",
                RejectionCode.MDSS_XCV_SIGNER_KEY_USAGE_INSUFFICIENT.getSeverity());
        // Title kararlılığı — Slack alarmı / dashboard widget'larında görünür.
        assertEquals("İmzacı sertifikası KeyUsage'da imza yetkisi taşımıyor",
                RejectionCode.MDSS_XCV_SIGNER_KEY_USAGE_INSUFFICIENT.getTitle());
    }

    @Test
    void allRejectionDocsUrlsPointToRepoRejectionsFolder() {
        // Suppression'lardan ayrı bir folder altında olduğunu garanti et —
        // discoverability açısından kritik: operatör "valid override mı yoksa
        // invalid enrichment mı?" sorusunu URL'den anlasın.
        String prefix = "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/";
        for (RejectionCode rc : RejectionCode.values()) {
            assertTrue(rc.getDocsUrl().startsWith(prefix),
                    "docsUrl beklenen prefix ile başlamalı: " + rc + " -> " + rc.getDocsUrl());
            assertTrue(rc.getDocsUrl().endsWith("/" + rc.getCode() + ".md"),
                    "docsUrl '/<CODE>.md' ile bitmeli: " + rc + " -> " + rc.getDocsUrl());
        }
    }

    @Test
    void rejectionCodeNamespaceDoesNotCollideWithSuppressionCode() {
        // İki enum aynı kod uzayını paylaşır. Aynı kodun her ikisinde olması
        // semantik karışıklık yaratır (suppression mı rejection mı?). Bu test
        // gelecekteki birinin yanlışlıkla bir kodu hem suppression hem
        // rejection enum'a koymasını engeller.
        java.util.Set<String> suppressionCodes = new java.util.HashSet<>();
        for (io.mersel.dss.verify.api.models.enums.SuppressionCode sc :
                io.mersel.dss.verify.api.models.enums.SuppressionCode.values()) {
            suppressionCodes.add(sc.getCode());
        }
        for (RejectionCode rc : RejectionCode.values()) {
            assertFalse(suppressionCodes.contains(rc.getCode()),
                    "Kod aynı anda hem SuppressionCode hem RejectionCode olarak "
                            + "tanımlanmış: " + rc.getCode());
        }
    }

    @Test
    void serializesToJsonWithExpectedFields() throws Exception {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("signedPropertiesId", "SignedProperties_Signature_2B1660F5-...");
        evidence.put("missingProtection", "SigningTime, SigningCertificateV2");

        AppliedRejection r = new AppliedRejection(
                "MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
                "XAdES SignedProperties referansı eksik (tek referanslı imza)",
                "Test reason",
                "ERROR",
                "INDETERMINATE",
                "SIG_CONSTRAINTS_FAILURE",
                evidence,
                "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md");

        String json = mapper.writeValueAsString(r);

        assertTrue(json.contains("\"code\":\"MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE\""), json);
        assertTrue(json.contains("\"severity\":\"ERROR\""), json);
        assertTrue(json.contains("\"originalIndication\":\"INDETERMINATE\""), json);
        assertTrue(json.contains("\"originalSubIndication\":\"SIG_CONSTRAINTS_FAILURE\""), json);
        assertTrue(json.contains("\"signedPropertiesId\""), json);
        assertTrue(json.contains("\"missingProtection\""), json);
        assertTrue(json.contains("\"docsUrl\""), json);
    }

    @Test
    void omitsNullFieldsInJson() throws Exception {
        AppliedRejection r = new AppliedRejection();
        r.setCode("MDSS-TEST");

        String json = mapper.writeValueAsString(r);

        // @JsonInclude(NON_NULL) garanti
        assertTrue(json.contains("\"code\""));
        assertFalse(json.contains("\"reason\""), "null reason JSON'a yazılmamalı: " + json);
        assertFalse(json.contains("\"evidence\""), "null evidence JSON'a yazılmamalı: " + json);
    }

    @Test
    void evidenceMapIsImmutable() {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("k1", "v1");

        AppliedRejection r = new AppliedRejection(
                "MDSS-TEST", "t", "r", "ERROR", null, null, evidence, null);

        // Caller'ın kendi map'inde değişiklik AppliedRejection'a sızmamalı
        evidence.put("k2", "v2");
        assertEquals(1, r.getEvidence().size(), "External mutation rejection'ı etkilememeli");

        // Returned map de immutable olmalı
        assertThrows(UnsupportedOperationException.class,
                () -> r.getEvidence().put("hacked", "x"));
    }

    @Test
    void signatureInfoExposesAppliedRejectionsField() {
        SignatureInfo si = new SignatureInfo();
        assertNull(si.getAppliedRejections());

        AppliedRejection r = new AppliedRejection();
        r.setCode("MDSS-TEST");
        si.setAppliedRejections(java.util.Collections.singletonList(r));

        assertEquals(1, si.getAppliedRejections().size());
        assertEquals("MDSS-TEST", si.getAppliedRejections().get(0).getCode());
    }

    @Test
    void appliedRejectionsIsIndependentFromAppliedSuppressions() {
        // İki liste birbirinden tamamen ayrı yaşar — bir SignatureInfo aynı anda
        // hem suppression (örn. başka bir tolerance) hem rejection (örn.
        // farklı bir patoloji) içerebilir. Bu test field'ların izole tutulduğunu
        // garanti eder.
        SignatureInfo si = new SignatureInfo();

        AppliedSuppression s = new AppliedSuppression();
        s.setCode("MDSS-XADES-LEGACY-TR-TYPE-URI");
        si.setAppliedSuppressions(java.util.Collections.singletonList(s));

        AppliedRejection r = new AppliedRejection();
        r.setCode("MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE");
        si.setAppliedRejections(java.util.Collections.singletonList(r));

        assertEquals("MDSS-XADES-LEGACY-TR-TYPE-URI",
                si.getAppliedSuppressions().get(0).getCode());
        assertEquals("MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
                si.getAppliedRejections().get(0).getCode());
    }
}
