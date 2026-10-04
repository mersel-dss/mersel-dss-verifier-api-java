package io.mersel.dss.verify.api.services.verification;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.test.util.ReflectionTestUtils;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.springframework.util.StreamUtils;
import static org.junit.jupiter.api.Assertions.*;

class ActivePolicyInfoTest {
    private AdvancedSignatureVerificationService service(String profile, String path) {
        AdvancedSignatureVerificationService service = new AdvancedSignatureVerificationService();
        ReflectionTestUtils.setField(service, "policyProfile", profile);
        ReflectionTestUtils.setField(service, "policyPath", path);
        ReflectionTestUtils.setField(service, "resourceLoader", new DefaultResourceLoader());
        return service;
    }

    @Test void reportsTheSameNormalizedBuiltInProfileThatValidationOpens() throws Exception {
        for (String profile : new String[]{"strict", "signer-strict"}) {
            AdvancedSignatureVerificationService service = service(" " + profile.toUpperCase() + " ", "");
            assertEquals(profile, service.getValidationPolicyInfo().get("profile"));
            assertEquals("BUILT_IN", service.getValidationPolicyInfo().get("source"));
            assertEquals(false, service.getValidationPolicyInfo().get("fallbackApplied"));
            try (InputStream actual = service.openValidationPolicyStream();
                 InputStream expected = getClass().getResourceAsStream("/policy/kamusm-" + profile + "-constraint.xml")) {
                assertEquals(StreamUtils.copyToString(expected, StandardCharsets.UTF_8),
                        StreamUtils.copyToString(actual, StandardCharsets.UTF_8));
            }
        }
    }
    @Test void exposesFallbackWithoutClaimingUnknownProfileIsActive() {
        AdvancedSignatureVerificationService service = service("typo", " ");
        assertEquals("signer-strict", service.getValidationPolicyInfo().get("profile"));
        assertEquals(true, service.getValidationPolicyInfo().get("fallbackApplied"));
    }
    @Test void customPathTakesPrecedenceAndStatusDoesNotLoadOrExposeIt() {
        AdvancedSignatureVerificationService service = service("strict", "https://secret:password@example.invalid/policy.xml");
        assertEquals("custom", service.getValidationPolicyInfo().get("profile"));
        assertEquals("CUSTOM_XML", service.getValidationPolicyInfo().get("source"));
        assertEquals(false, service.getValidationPolicyInfo().get("fallbackApplied"));
        assertFalse(service.getValidationPolicyInfo().toString().contains("password"));
    }
}
