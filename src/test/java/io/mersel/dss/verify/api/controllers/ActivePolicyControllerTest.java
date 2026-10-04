package io.mersel.dss.verify.api.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import io.mersel.dss.verify.api.GlobalExceptionHandler;
import io.mersel.dss.verify.api.config.SecurityConfiguration;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import io.mersel.dss.verify.api.services.certificate.RequestTrustContext;
import io.mersel.dss.verify.api.services.certificate.RequestTrustFactory;
import io.mersel.dss.verify.api.services.util.LegacyTurkishXadesTypeUriDetector;
import io.mersel.dss.verify.api.services.util.RevocationInfoExtractor;
import io.mersel.dss.verify.api.services.util.XadesSignaturePackagingDetector;
import io.mersel.dss.verify.api.services.verification.ActivePolicyStore;
import io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StreamUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ActivePolicyControllerTest {
    final ObjectMapper json = new ObjectMapper();

    static byte[] bundled(String profile) throws Exception {
        try (InputStream in = ActivePolicyControllerTest.class.getResourceAsStream("/policy/kamusm-" + profile + "-constraint.xml")) {
            return StreamUtils.copyToByteArray(in);
        }
    }

    static AdvancedSignatureVerificationService engine(ActivePolicyStore store) {
        AdvancedSignatureVerificationService service = new AdvancedSignatureVerificationService();
        VerificationConfiguration config = new VerificationConfiguration();
        ReflectionTestUtils.setField(service, "config", config);
        ReflectionTestUtils.setField(service, "resourceLoader", new DefaultResourceLoader());
        ReflectionTestUtils.setField(service, "activePolicyStore", store);
        ReflectionTestUtils.setField(service, "dssValidationLocale", Locale.ENGLISH);
        ReflectionTestUtils.setField(service, "xadesPackagingDetector", new XadesSignaturePackagingDetector());
        ReflectionTestUtils.setField(service, "legacyTrXadesDetector", new LegacyTurkishXadesTypeUriDetector());
        ReflectionTestUtils.setField(service, "revocationInfoExtractor", new RevocationInfoExtractor());
        KamusmRootCertificateService roots = mock(KamusmRootCertificateService.class);
        when(roots.getVerificationTrustContext()).thenAnswer(call -> RequestTrustContext.server(new CommonTrustedCertificateSource()));
        ReflectionTestUtils.setField(service, "rootCertificateService", roots);
        return service;
    }

    static MockMvc mvc(ActivePolicyStore store) {
        AdvancedSignatureVerificationService service = engine(store);
        HealthController health = new HealthController();
        ReflectionTestUtils.setField(health, "verificationService", service);
        ReflectionTestUtils.setField(health, "activePolicyStore", store);
        ReflectionTestUtils.setField(health, "environment", new MockEnvironment());
        ReflectionTestUtils.setField(health, "applicationName", "mersel-dss-verify-api");
        ReflectionTestUtils.setField(health, "version", "test");
        ReflectionTestUtils.setField(health, "rootResolverType", "folder");
        UnifiedVerificationController verify = new UnifiedVerificationController();
        ReflectionTestUtils.setField(verify, "requestTrustFactory", new RequestTrustFactory(false));
        ReflectionTestUtils.setField(verify, "advancedSignatureVerificationService", service);
        return MockMvcBuilders.standaloneSetup(new ActivePolicyController(store), health, verify)
                .setControllerAdvice(new GlobalExceptionHandler()).build();
    }

    static ActivePolicyStore store(boolean enabled) {
        return new ActivePolicyStore("signer-strict", "", new DefaultResourceLoader(), ActivePolicyStore.DEFAULT_MAX_BYTES, enabled);
    }
    /** Explicit dss.policy.path that cannot be loaded (hata durumu). */
    static ActivePolicyStore broken(boolean enabled) {
        return new ActivePolicyStore("signer-strict", "file:/nonexistent/secret-dir/policy.xml", new DefaultResourceLoader(),
                ActivePolicyStore.DEFAULT_MAX_BYTES, enabled);
    }
    static MockMultipartFile unsignedDocument() {
        return new MockMultipartFile("signedDocument", "unsigned.xml", "text/xml", "<Invoice/>".getBytes(StandardCharsets.UTF_8));
    }

    JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8));
    }
    JsonNode active(MockMvc mvc) throws Exception {
        return body(mvc.perform(get("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk()));
    }
    static MockMultipartFile xml(byte[] content) {
        return new MockMultipartFile("policyXml", "policy.xml", "application/xml", content);
    }

    @Test void getReturnsTheContractShape() throws Exception {
        JsonNode policy = active(mvc(store(true)));
        assertEquals(9, policy.size(), policy.toString());
        assertTrue(policy.get("policyId").asText().endsWith(":0"));
        assertEquals("signer-strict", policy.get("profile").asText());
        assertEquals("BUILT_IN", policy.get("source").asText());
        assertEquals("CONFIGURATION", policy.get("origin").asText());
        assertEquals("KamuSM Signer Strict", policy.get("name").asText());
        assertEquals(DigestUtils.sha256Hex(bundled("signer-strict")), policy.get("sha256").asText());
        assertTrue(policy.get("activatedAt").isTextual());
        assertFalse(policy.get("fallbackApplied").asBoolean());
        assertTrue(policy.get("activationEnabled").asBoolean());
    }

    @Test void multipartActivationHappyPathsAndInfoReflectsTheActivePolicy() throws Exception {
        MockMvc mvc = mvc(store(true));
        mvc.perform(get("/api/v1/info").accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.verificationPolicy.profile").value("signer-strict"))
                .andExpect(jsonPath("$.policyCapabilities.activationSupported").value(true))
                .andExpect(jsonPath("$.policyCapabilities.activationEnabled").value(true))
                .andExpect(jsonPath("$.policyCapabilities.maxBytes").value(1048576))
                .andExpect(jsonPath("$.policyCapabilities.contentAvailable").value(true));
        String id = active(mvc).get("policyId").asText();

        JsonNode strict = body(mvc.perform(multipart("/api/v1/policy/active").param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", id).accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk()));
        assertEquals("strict", strict.get("profile").asText()); assertEquals("API", strict.get("origin").asText());
        assertNotEquals(id, strict.get("policyId").asText());
        mvc.perform(get("/api/v1/info").accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.verificationPolicy.profile").value("strict"))
                .andExpect(jsonPath("$.verificationPolicy.source").value("BUILT_IN"))
                .andExpect(jsonPath("$.verificationPolicy.fallbackApplied").value(false))
                .andExpect(jsonPath("$.verificationPolicy.length()").value(3));

        byte[] custom = bundled("strict");
        JsonNode uploaded = body(mvc.perform(multipart("/api/v1/policy/active").file(xml(custom)).param("mode", "CUSTOM_XML")
                .param("policyName", "Kurum politikası").param("expectedPolicyId", strict.get("policyId").asText())
                .accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk()));
        assertEquals("custom", uploaded.get("profile").asText()); assertEquals("CUSTOM_XML", uploaded.get("source").asText());
        assertEquals("Kurum politikası", uploaded.get("name").asText());
        assertEquals(DigestUtils.sha256Hex(custom), uploaded.get("sha256").asText());
        mvc.perform(get("/api/v1/info").accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.verificationPolicy.profile").value("custom"))
                .andExpect(jsonPath("$.verificationPolicy.source").value("CUSTOM_XML"));
        assertEquals(uploaded, active(mvc));

        JsonNode configured = body(mvc.perform(multipart("/api/v1/policy/active").param("mode", "CONFIGURED")
                .param("expectedPolicyId", uploaded.get("policyId").asText()).accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk()));
        assertEquals("CONFIGURATION", configured.get("origin").asText()); assertEquals("signer-strict", configured.get("profile").asText());
        mvc.perform(get("/api/v1/info").accept(MediaType.APPLICATION_JSON)).andExpect(jsonPath("$.verificationPolicy.profile").value("signer-strict"));
    }

    @Test void rejectionsUseTheErrorShapeAndNeverChangeState() throws Exception {
        MockMvc mvc = mvc(store(true));
        String id = active(mvc).get("policyId").asText();
        mvc.perform(multipart("/api/v1/policy/active").param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", "stale:0").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.error").value("CONFLICT")).andExpect(jsonPath("$.message").isNotEmpty())
                .andExpect(jsonPath("$.policyId").doesNotExist()).andExpect(jsonPath("$.activationEnabled").doesNotExist());
        mvc.perform(multipart("/api/v1/policy/active").file(xml("<ConstraintsParameters".getBytes(StandardCharsets.UTF_8)))
                .param("mode", "CUSTOM_XML").param("expectedPolicyId", id).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_POLICY"))
                .andExpect(jsonPath("$.path").value("/api/v1/policy/active"));
        String doctype = "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/hosts\">]><ConstraintsParameters xmlns=\"http://dss.esig.europa.eu/validation/policy\">&e;</ConstraintsParameters>";
        mvc.perform(multipart("/api/v1/policy/active").file(xml(doctype.getBytes(StandardCharsets.UTF_8)))
                .param("mode", "CUSTOM_XML").param("expectedPolicyId", id).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_POLICY"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("DOCTYPE")));
        byte[] tooBig = new byte[ActivePolicyStore.DEFAULT_MAX_BYTES + 1];
        mvc.perform(multipart("/api/v1/policy/active").file(xml(tooBig)).param("mode", "CUSTOM_XML").param("expectedPolicyId", id)
                .accept(MediaType.APPLICATION_JSON)).andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_POLICY"));
        String[][] badRequests = {
                {"mode", "OTHER", "expectedPolicyId", id},
                {"mode", "BUILT_IN", "expectedPolicyId", id},
                {"mode", "BUILT_IN", "profile", "custom", "expectedPolicyId", id},
                {"mode", "BUILT_IN", "profile", "strict"},
                {"mode", "CUSTOM_XML", "expectedPolicyId", id},
                {"mode", "CONFIGURED", "profile", "strict", "expectedPolicyId", id},
                {"mode", "CONFIGURED", "policyName", "x", "expectedPolicyId", id},
                {"profile", "strict", "expectedPolicyId", id},
        };
        for (String[] params : badRequests) {
            org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder request = multipart("/api/v1/policy/active");
            for (int i = 0; i < params.length; i += 2) request.param(params[i], params[i + 1]);
            mvc.perform(request.accept(MediaType.APPLICATION_JSON))
                    .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_POLICY"));
        }
        mvc.perform(multipart("/api/v1/policy/active").file(xml(bundled("strict"))).param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", id).accept(MediaType.APPLICATION_JSON)).andExpect(status().isBadRequest());
        JsonNode after = active(mvc);
        assertEquals(id, after.get("policyId").asText()); assertEquals("CONFIGURATION", after.get("origin").asText());
    }

    @Test void disabledServerAnswers403AndAdvertisesIt() throws Exception {
        MockMvc mvc = mvc(store(false));
        JsonNode before = active(mvc);
        assertFalse(before.get("activationEnabled").asBoolean());
        mvc.perform(get("/api/v1/info").accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.policyCapabilities.activationSupported").value(true))
                .andExpect(jsonPath("$.policyCapabilities.activationEnabled").value(false))
                .andExpect(jsonPath("$.policyCapabilities.contentAvailable").value(true));
        mvc.perform(multipart("/api/v1/policy/active").param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", before.get("policyId").asText()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("POLICY_ACTIVATION_DISABLED"));
        mvc.perform(multipart("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden());
        assertEquals(before, active(mvc));
    }

    @Test void failedConfigurationAnswers503WithTheRevisionNeededToRecover() throws Exception {
        MockMvc mvc = mvc(broken(true));
        JsonNode failed = body(mvc.perform(get("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable()));
        List<String> fields = new ArrayList<>();
        failed.fieldNames().forEachRemaining(fields::add);
        assertEquals(Arrays.asList("error", "message", "details", "policyId", "activationEnabled", "timestamp", "path"), fields);
        assertEquals("POLICY_UNAVAILABLE", failed.get("error").asText());
        String failedId = failed.get("policyId").asText();
        assertTrue(failedId.endsWith(":0"), failedId);
        assertTrue(failed.get("activationEnabled").asBoolean());
        assertEquals("/api/v1/policy/active", failed.get("path").asText());
        assertFalse(failed.toString().contains("secret-dir"), "The configured path is never echoed");

        // Fail-fast: no verification runs with a silently substituted policy.
        mvc.perform(multipart("/api/v1/verify/signature").file(unsignedDocument()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("VERIFICATION_ERROR"));
        // CONFIGURED while the file is still broken: 503 with the same revision.
        mvc.perform(multipart("/api/v1/policy/active").param("mode", "CONFIGURED").param("expectedPolicyId", failedId)
                .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.error").value("POLICY_UNAVAILABLE"))
                .andExpect(jsonPath("$.policyId").value(failedId)).andExpect(jsonPath("$.activationEnabled").value(true));
        mvc.perform(multipart("/api/v1/policy/active").param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", "stale:0").accept(MediaType.APPLICATION_JSON)).andExpect(status().isConflict());
        mvc.perform(get("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.policyId").value(failedId));

        JsonNode recovered = body(mvc.perform(multipart("/api/v1/policy/active").param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", failedId).accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk()));
        assertEquals("strict", recovered.get("profile").asText()); assertEquals("API", recovered.get("origin").asText());
        assertNotEquals(failedId, recovered.get("policyId").asText());
        assertEquals(recovered, active(mvc));
        mvc.perform(multipart("/api/v1/verify/signature").file(unsignedDocument()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policyContext.policyId").value(recovered.get("policyId").asText()))
                .andExpect(jsonPath("$.policyContext.profile").value("strict"));
        mvc.perform(get("/api/v1/info").accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.verificationPolicy.profile").value("strict"))
                .andExpect(jsonPath("$.verificationPolicy.source").value("BUILT_IN"));
    }

    @Test void failedConfigurationCanBeReplacedWithCustomXmlOverHttp() throws Exception {
        MockMvc mvc = mvc(broken(true));
        String failedId = body(mvc.perform(get("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable())).get("policyId").asText();
        JsonNode custom = body(mvc.perform(multipart("/api/v1/policy/active").file(xml(bundled("signer-strict"))).param("mode", "CUSTOM_XML")
                .param("policyName", "Acil durum").param("expectedPolicyId", failedId).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()));
        assertEquals("CUSTOM_XML", custom.get("source").asText()); assertEquals("Acil durum", custom.get("name").asText());
        assertEquals(custom, active(mvc));
        mvc.perform(multipart("/api/v1/verify/signature").file(unsignedDocument()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()).andExpect(jsonPath("$.policyContext.source").value("CUSTOM_XML"));
    }

    @Test void failedConfigurationOnADisabledServerSays503AndActivationIsOff() throws Exception {
        MockMvc mvc = mvc(broken(false));
        JsonNode failed = body(mvc.perform(get("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable()));
        assertFalse(failed.get("activationEnabled").asBoolean());
        mvc.perform(multipart("/api/v1/policy/active").param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", failed.get("policyId").asText()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("POLICY_ACTIVATION_DISABLED"));
        mvc.perform(get("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.policyId").value(failed.get("policyId").asText()));
    }

    @Test void signatureResponsesCarryThePolicyContextOfTheirSnapshot() throws Exception {
        ActivePolicyStore store = store(true);
        MockMvc mvc = mvc(store);
        MockMultipartFile document = new MockMultipartFile("signedDocument", "unsigned.xml", "text/xml", "<Invoice/>".getBytes(StandardCharsets.UTF_8));
        JsonNode first = body(mvc.perform(multipart("/api/v1/verify/signature").file(document).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()));
        JsonNode policy = active(mvc);
        JsonNode context = first.get("policyContext");
        assertEquals(5, context.size(), context.toString());
        for (String field : new String[]{"policyId", "profile", "source", "name", "sha256"}) assertEquals(policy.get(field), context.get(field), field);

        String id = policy.get("policyId").asText();
        mvc.perform(multipart("/api/v1/policy/active").file(xml(bundled("strict"))).param("mode", "CUSTOM_XML")
                .param("expectedPolicyId", id).accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk());
        mvc.perform(multipart("/api/v1/verify/signature").file(document).accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.policyContext.profile").value("custom"))
                .andExpect(jsonPath("$.policyContext.source").value("CUSTOM_XML"))
                .andExpect(jsonPath("$.policyContext.sha256").value(DigestUtils.sha256Hex(bundled("strict"))));
    }

    @Test void oneVerificationReadsTheActivePolicyOnceEvenIfItChangesMidRequest() throws Exception {
        ActivePolicyStore store = spy(store(true));
        AtomicReference<ActivePolicyStore.Snapshot> taken = new AtomicReference<>();
        doAnswer(call -> {
            ActivePolicyStore.Snapshot snapshot = (ActivePolicyStore.Snapshot) call.callRealMethod();
            if (taken.compareAndSet(null, snapshot)) store.activateBuiltIn(snapshot.getPolicyId(), "strict"); // concurrent activation
            return snapshot;
        }).when(store).snapshot();
        MockMultipartFile document = new MockMultipartFile("signedDocument", "unsigned.xml", "text/xml", "<Invoice/>".getBytes(StandardCharsets.UTF_8));
        VerificationResult result = engine(store).verifySignature(document, null, VerificationLevel.SIMPLE, false);
        verify(store, times(1)).snapshot();
        assertEquals(taken.get().getPolicyId(), result.getPolicyContext().getPolicyId());
        assertEquals("signer-strict", result.getPolicyContext().getProfile());
        assertEquals("strict", store.current().getProfile());
    }

    static final String XML = "/api/v1/policy/active/xml";

    /** Bundled strict policy plus Turkish text, BOM-less UTF-8 (what the UI editor uploads). */
    static byte[] turkishCustom(String marker) throws Exception {
        String xml = new String(bundled("strict"), StandardCharsets.UTF_8)
                .replaceFirst("\\?>", "?>\n<!-- " + marker + ": İmzacı sertifikası ğüşıöç ĞÜŞİÖÇ -->");
        return xml.getBytes(StandardCharsets.UTF_8);
    }

    static MockHttpServletResponse policyXml(MockMvc mvc) throws Exception {
        return mvc.perform(get(XML).accept(MediaType.APPLICATION_XML)).andExpect(status().isOk()).andReturn().getResponse();
    }

    static void assertContent(MockHttpServletResponse response, byte[] expected, String policyId, String fileName) {
        assertArrayEquals(expected, response.getContentAsByteArray());
        String sha256 = DigestUtils.sha256Hex(expected);
        assertEquals("application/xml;charset=UTF-8", response.getHeader("Content-Type"));
        assertEquals(policyId, response.getHeader("X-Policy-Id"));
        assertEquals(sha256, response.getHeader("X-Policy-Sha256"));
        assertEquals("\"" + sha256 + "\"", response.getHeader("ETag"));
        assertEquals("no-store", response.getHeader("Cache-Control"));
        assertEquals("inline; filename=\"" + fileName + "\"", response.getHeader("Content-Disposition"));
        assertEquals("default-src 'none'; sandbox", response.getHeader("Content-Security-Policy"));
    }

    @Test void xmlServesTheExactBuiltInBytesWithTheMetadataOfTheSameRevision() throws Exception {
        for (boolean enabled : new boolean[]{false, true}) { // reading is independent of activation-enabled
            MockMvc mvc = mvc(store(enabled));
            JsonNode policy = active(mvc);
            MockHttpServletResponse response = policyXml(mvc);
            assertContent(response, bundled("signer-strict"), policy.get("policyId").asText(), "kamusm-signer-strict-constraint.xml");
            assertEquals(policy.get("sha256").asText(), response.getHeader("X-Policy-Sha256"));
            // No content negotiation: the policy is XML whatever the client accepts.
            assertArrayEquals(bundled("signer-strict"), mvc.perform(get(XML)).andExpect(status().isOk())
                    .andReturn().getResponse().getContentAsByteArray());
        }
        MockMvc strict = mvc(new ActivePolicyStore("strict", "", new DefaultResourceLoader(), ActivePolicyStore.DEFAULT_MAX_BYTES, false));
        assertContent(policyXml(strict), bundled("strict"), active(strict).get("policyId").asText(), "kamusm-strict-constraint.xml");
    }

    @Test void xmlEditRoundTripReturnsTheUploadedBytesExactlyAndConfiguredRestoresTheBuiltIn() throws Exception {
        MockMvc mvc = mvc(store(true));
        String builtInId = policyXml(mvc).getHeader("X-Policy-Id");

        byte[] uploaded = turkishCustom("Kurum politikası");
        assertEquals('<', uploaded[0], "BOM-less UTF-8");
        JsonNode custom = body(mvc.perform(multipart("/api/v1/policy/active").file(xml(uploaded)).param("mode", "CUSTOM_XML")
                .param("policyName", "Mersel KamuSM Signer-Strict Policy").param("expectedPolicyId", builtInId)
                .accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk()));
        MockHttpServletResponse served = policyXml(mvc);
        assertContent(served, uploaded, custom.get("policyId").asText(), "Mersel-KamuSM-Signer-Strict-Policy.xml");
        assertEquals(custom.get("sha256").asText(), served.getHeader("X-Policy-Sha256"));
        assertTrue(served.getContentAsString(StandardCharsets.UTF_8).contains("İmzacı sertifikası ğüşıöç ĞÜŞİÖÇ"));

        // Edit what the server serves and save it against the revision it was read from.
        byte[] edited = served.getContentAsString(StandardCharsets.UTF_8)
                .replace("Kurum politikası:", "Düzenlendi:").getBytes(StandardCharsets.UTF_8);
        JsonNode saved = body(mvc.perform(multipart("/api/v1/policy/active").file(xml(edited)).param("mode", "CUSTOM_XML")
                .param("policyName", "Mersel KamuSM Signer-Strict Policy").param("expectedPolicyId", served.getHeader("X-Policy-Id"))
                .accept(MediaType.APPLICATION_JSON)).andExpect(status().isOk()));
        assertContent(policyXml(mvc), edited, saved.get("policyId").asText(), "Mersel-KamuSM-Signer-Strict-Policy.xml");
        // A second editor still holding the old revision cannot overwrite it.
        mvc.perform(multipart("/api/v1/policy/active").file(xml(uploaded)).param("mode", "CUSTOM_XML")
                .param("expectedPolicyId", served.getHeader("X-Policy-Id")).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isConflict());
        assertArrayEquals(edited, policyXml(mvc).getContentAsByteArray());

        mvc.perform(multipart("/api/v1/policy/active").file(xml(uploaded)).param("mode", "CUSTOM_XML")
                .param("expectedPolicyId", saved.get("policyId").asText()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
        assertEquals("inline; filename=\"active-policy.xml\"", policyXml(mvc).getHeader("Content-Disposition"));

        JsonNode configured = body(mvc.perform(multipart("/api/v1/policy/active").param("mode", "CONFIGURED")
                .param("expectedPolicyId", active(mvc).get("policyId").asText()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()));
        assertContent(policyXml(mvc), bundled("signer-strict"), configured.get("policyId").asText(), "kamusm-signer-strict-constraint.xml");
    }

    @Test void xmlInTheFailedStateAnswersTheSame503AsTheMetadata() throws Exception {
        MockMvc mvc = mvc(broken(true));
        JsonNode metadata = body(mvc.perform(get("/api/v1/policy/active").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isServiceUnavailable()));
        ResultActions failed = mvc.perform(get(XML).accept(MediaType.APPLICATION_XML))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().doesNotExist("X-Policy-Id"))
                .andExpect(header().doesNotExist("ETag"));
        JsonNode xmlError = body(failed);
        List<String> fields = new ArrayList<>();
        xmlError.fieldNames().forEachRemaining(fields::add);
        assertEquals(Arrays.asList("error", "message", "details", "policyId", "activationEnabled", "timestamp", "path"), fields);
        for (String field : new String[]{"error", "message", "details", "policyId", "activationEnabled"}) {
            assertEquals(metadata.get(field), xmlError.get(field), field);
        }
        assertEquals("POLICY_UNAVAILABLE", xmlError.get("error").asText());
        assertEquals(XML, xmlError.get("path").asText());
        assertFalse(xmlError.toString().contains("secret-dir"), "The configured path is never echoed");

        JsonNode recovered = body(mvc.perform(multipart("/api/v1/policy/active").param("mode", "BUILT_IN").param("profile", "strict")
                .param("expectedPolicyId", xmlError.get("policyId").asText()).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk()));
        assertContent(policyXml(mvc), bundled("strict"), recovered.get("policyId").asText(), "kamusm-strict-constraint.xml");
    }

    @Test void xmlBodyAndHeadersComeFromOneSnapshotEvenIfThePolicyChangesMidRequest() throws Exception {
        ActivePolicyStore store = spy(store(true));
        AtomicReference<ActivePolicyStore.Snapshot> taken = new AtomicReference<>();
        doAnswer(call -> {
            ActivePolicyStore.Snapshot snapshot = (ActivePolicyStore.Snapshot) call.callRealMethod();
            if (taken.compareAndSet(null, snapshot)) store.activateBuiltIn(snapshot.getPolicyId(), "strict"); // concurrent activation
            return snapshot;
        }).when(store).currentSnapshot();
        MockMvc mvc = mvc(store);
        MockHttpServletResponse response = policyXml(mvc);
        verify(store, times(1)).currentSnapshot();
        assertContent(response, bundled("signer-strict"), taken.get().getPolicyId(), "kamusm-signer-strict-constraint.xml");
        JsonNode now = active(mvc);
        assertEquals("strict", now.get("profile").asText());
        assertNotEquals(now.get("policyId").asText(), response.getHeader("X-Policy-Id"));
        assertContent(policyXml(mvc), bundled("strict"), now.get("policyId").asText(), "kamusm-strict-constraint.xml");
    }

    @Test void corsLetsBrowserClientsReadThePolicyContentHeaders() {
        class Registry extends CorsRegistry {
            Map<String, CorsConfiguration> configurations() { return getCorsConfigurations(); }
        }
        Registry registry = new Registry();
        new SecurityConfiguration().addCorsMappings(registry);
        List<String> exposed = registry.configurations().get("/**").getExposedHeaders();
        assertNotNull(exposed);
        assertTrue(exposed.containsAll(Arrays.asList("X-Policy-Id", "X-Policy-Sha256", "ETag", "Content-Disposition")), exposed.toString());
    }
}
