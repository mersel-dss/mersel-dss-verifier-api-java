package io.mersel.dss.verify.api.services.verification;

import io.mersel.dss.verify.api.exceptions.PolicyActivationException;
import io.mersel.dss.verify.api.exceptions.VerificationException;
import io.mersel.dss.verify.api.models.ActivePolicy;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.http.HttpStatus;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.*;

class ActivePolicyStoreTest {
    static final String NS = "http://dss.esig.europa.eu/validation/policy";

    static ActivePolicyStore store(String profile, String path, boolean enabled) {
        return new ActivePolicyStore(profile, path, new DefaultResourceLoader(), ActivePolicyStore.DEFAULT_MAX_BYTES, enabled);
    }
    static byte[] bundled(String profile) throws Exception {
        try (InputStream in = ActivePolicyStoreTest.class.getResourceAsStream("/policy/kamusm-" + profile + "-constraint.xml")) {
            return StreamUtils.copyToByteArray(in);
        }
    }
    static byte[] bytes(ActivePolicyStore.Snapshot snapshot) throws Exception {
        try (InputStream in = snapshot.openStream()) { return StreamUtils.copyToByteArray(in); }
    }
    static PolicyActivationException rejected(String error, Executable call) {
        PolicyActivationException e = assertThrows(PolicyActivationException.class, call);
        assertEquals(error, e.getError(), e.getMessage());
        return e;
    }

    @Test void initialisesFromConfiguredProfileWithoutOpeningItForInfo() throws Exception {
        ActivePolicyStore store = store(" STRICT ", "", true);
        Map<String, Object> info = store.describe();
        assertEquals("strict", info.get("profile")); assertEquals("BUILT_IN", info.get("source")); assertEquals(false, info.get("fallbackApplied"));
        ActivePolicy active = store.current();
        assertEquals("strict", active.getProfile()); assertEquals("BUILT_IN", active.getSource());
        assertEquals("CONFIGURATION", active.getOrigin()); assertEquals("KamuSM Strict", active.getName());
        assertEquals(DigestUtils.sha256Hex(bundled("strict")), active.getSha256());
        assertTrue(active.getPolicyId().endsWith(":0")); assertFalse(active.isFallbackApplied()); assertTrue(active.isActivationEnabled());
        assertNotNull(java.time.Instant.parse(active.getActivatedAt()));
        assertArrayEquals(bundled("strict"), bytes(store.snapshot()));
        assertEquals(store.snapshot().getPolicyId(), store.current().getPolicyId(), "Reading does not create revisions");
    }

    @Test void unknownProfileFallsBackVisiblyAndConfiguredPathIsCustom() throws Exception {
        ActivePolicyStore typo = store("typo", " ", false);
        assertEquals(true, typo.describe().get("fallbackApplied"));
        assertEquals("signer-strict", typo.current().getProfile()); assertTrue(typo.current().isFallbackApplied());
        assertEquals("KamuSM Signer Strict", typo.current().getName());

        ActivePolicyStore custom = store("strict", "classpath:policy/kamusm-signer-strict-constraint.xml", false);
        assertEquals("custom", custom.describe().get("profile"));
        ActivePolicy active = custom.current();
        assertEquals("custom", active.getProfile()); assertEquals("CUSTOM_XML", active.getSource());
        assertEquals("CONFIGURATION", active.getOrigin()); assertEquals("Özel politika", active.getName());
        assertEquals(DigestUtils.sha256Hex(bundled("signer-strict")), active.getSha256());
        assertFalse(active.isFallbackApplied()); assertFalse(active.isActivationEnabled());
    }

    @Test void misconfiguredExplicitPathFailsFastWithoutFallbackOrLeakingThePath() {
        ActivePolicyStore store = store("strict", "file:/nonexistent/secret-dir/policy.xml", true);
        assertEquals("custom", store.describe().get("profile"), "Status does not load the configured resource");
        VerificationException failure = assertThrows(VerificationException.class, store::snapshot);
        assertTrue(failure.getMessage().contains("dss.policy.path olarak verilen kaynak bulunamadı"));
        PolicyActivationException unavailable = rejected("POLICY_UNAVAILABLE", store::current);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, unavailable.getStatus());
        assertFalse(unavailable.getMessage().contains("secret-dir"));
        assertThrows(VerificationException.class, store::snapshot, "Every verification keeps failing; no silent default");
    }

    static final String BROKEN_PATH = "file:/nonexistent/secret-dir/policy.xml";

    @Test void failedConfigurationReportsItsRevisionAndBuiltInActivationRecovers() throws Exception {
        ActivePolicyStore store = store("strict", BROKEN_PATH, true);
        PolicyActivationException unavailable = rejected("POLICY_UNAVAILABLE", store::current);
        String failedId = unavailable.getPolicyId();
        assertNotNull(failedId); assertTrue(failedId.endsWith(":0"), failedId);
        assertEquals(Boolean.TRUE, unavailable.getActivationEnabled());
        assertTrue(unavailable.getMessage().contains("başka bir politika etkinleştirilene kadar"), unavailable.getMessage());
        assertFalse(unavailable.getMessage().contains("secret-dir"));
        assertEquals(failedId, rejected("POLICY_UNAVAILABLE", store::current).getPolicyId(), "Failing reads create no revisions");

        // Still broken: CONFIGURED answers 503 with the same revision and changes nothing.
        PolicyActivationException restore = rejected("POLICY_UNAVAILABLE", () -> store.restoreConfiguration(failedId));
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, restore.getStatus()); assertEquals(failedId, restore.getPolicyId());
        // Normal rules still apply in the failed state.
        rejected("CONFLICT", () -> store.activateBuiltIn("other-instance:0", "strict"));
        rejected("CONFLICT", () -> store.restoreConfiguration(null));
        rejected("INVALID_POLICY", () -> store.activateCustom(failedId, "<x/>".getBytes(StandardCharsets.UTF_8), null));
        rejected("INVALID_POLICY", () -> store.activateBuiltIn(failedId, "custom"));
        assertThrows(VerificationException.class, store::snapshot, "Verifications keep failing fast until an explicit choice");
        assertEquals(failedId, rejected("POLICY_UNAVAILABLE", store::current).getPolicyId());

        ActivePolicy recovered = store.activateBuiltIn(failedId, "signer-strict");
        assertEquals("signer-strict", recovered.getProfile()); assertEquals("BUILT_IN", recovered.getSource());
        assertEquals("API", recovered.getOrigin()); assertTrue(recovered.getPolicyId().endsWith(":1"));
        assertFalse(recovered.isFallbackApplied()); assertTrue(recovered.isActivationEnabled());
        assertEquals(recovered.getPolicyId(), store.current().getPolicyId());
        assertEquals(recovered.getPolicyId(), store.snapshot().getPolicyId());
        assertArrayEquals(bundled("signer-strict"), bytes(store.snapshot()));
        assertEquals("signer-strict", store.describe().get("profile"));
        rejected("CONFLICT", () -> store.activateBuiltIn(failedId, "strict"));

        // CONFIGURED with the file still broken now keeps the working policy (503 carries the current revision).
        PolicyActivationException kept = rejected("POLICY_UNAVAILABLE", () -> store.restoreConfiguration(recovered.getPolicyId()));
        assertEquals(recovered.getPolicyId(), kept.getPolicyId());
        assertTrue(kept.getMessage().contains("etkin politika değişmedi"), kept.getMessage());
        assertEquals(recovered.getPolicyId(), store.current().getPolicyId()); assertEquals("API", store.current().getOrigin());
    }

    @Test void failedConfigurationCanBeReplacedWithCustomXml() throws Exception {
        ActivePolicyStore store = store("signer-strict", BROKEN_PATH, true);
        String failedId = rejected("POLICY_UNAVAILABLE", store::current).getPolicyId();
        ActivePolicy custom = store.activateCustom(failedId, bundled("strict"), "Acil durum politikası");
        assertEquals("custom", custom.getProfile()); assertEquals("CUSTOM_XML", custom.getSource());
        assertEquals("API", custom.getOrigin()); assertEquals("Acil durum politikası", custom.getName());
        assertEquals(DigestUtils.sha256Hex(bundled("strict")), custom.getSha256());
        assertNotEquals(failedId, custom.getPolicyId());
        assertArrayEquals(bundled("strict"), bytes(store.snapshot()));
    }

    @Test void failedConfigurationIsRestoredWithConfiguredOnceTheFileIsFixed(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("policy.xml");
        ActivePolicyStore store = store("signer-strict", file.toUri().toString(), true);
        String failedId = rejected("POLICY_UNAVAILABLE", store::current).getPolicyId();
        rejected("POLICY_UNAVAILABLE", () -> store.restoreConfiguration(failedId));
        Files.write(file, bundled("strict"));

        ActivePolicy restored = store.restoreConfiguration(failedId);
        assertEquals("CONFIGURATION", restored.getOrigin()); assertEquals("custom", restored.getProfile());
        assertEquals("CUSTOM_XML", restored.getSource()); assertEquals("Özel politika", restored.getName());
        assertEquals(DigestUtils.sha256Hex(bundled("strict")), restored.getSha256());
        assertTrue(restored.getPolicyId().endsWith(":1"), restored.getPolicyId());
        assertEquals(restored.getPolicyId(), store.snapshot().getPolicyId());
        assertArrayEquals(bundled("strict"), bytes(store.snapshot()));
    }

    @Test void aFileFixedBehindTheClientsBackGetsANewRevisionSoStaleRecoveryConflicts(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("policy.xml");
        ActivePolicyStore store = store("signer-strict", file.toUri().toString(), true);
        String failedId = rejected("POLICY_UNAVAILABLE", store::current).getPolicyId();
        assertThrows(VerificationException.class, store::snapshot);
        Files.write(file, bundled("strict"));

        ActivePolicyStore.Snapshot loaded = store.snapshot(); // next verification picks the fixed file up
        assertNotEquals(failedId, loaded.getPolicyId()); assertTrue(loaded.getPolicyId().endsWith(":1"));
        assertEquals("CONFIGURATION", loaded.getOrigin());
        assertEquals(loaded.getPolicyId(), store.current().getPolicyId());
        rejected("CONFLICT", () -> store.activateBuiltIn(failedId, "signer-strict"));
        assertEquals(loaded.getPolicyId(), store.current().getPolicyId());

        // A configuration that loads at once keeps revision 0.
        assertTrue(store("signer-strict", file.toUri().toString(), true).current().getPolicyId().endsWith(":0"));
    }

    @Test void failedConfigurationOnADisabledServerAdvertisesThatActivationIsOff() {
        ActivePolicyStore store = store("signer-strict", BROKEN_PATH, false);
        PolicyActivationException unavailable = rejected("POLICY_UNAVAILABLE", store::current);
        assertEquals(Boolean.FALSE, unavailable.getActivationEnabled());
        assertNotNull(unavailable.getPolicyId());
        assertFalse(unavailable.getMessage().contains("başka bir politika"), unavailable.getMessage());
        rejected("POLICY_ACTIVATION_DISABLED", () -> store.activateBuiltIn(unavailable.getPolicyId(), "strict"));
        rejected("POLICY_ACTIVATION_DISABLED", () -> store.restoreConfiguration(unavailable.getPolicyId()));
        assertThrows(VerificationException.class, store::snapshot);
    }

    @Test void activatesBuiltInCustomAndConfiguredWithNewRevisionsEachTime() throws Exception {
        ActivePolicyStore store = store("signer-strict", "", true);
        ActivePolicy initial = store.current();

        ActivePolicy strict = store.activateBuiltIn(initial.getPolicyId(), "strict");
        assertEquals("strict", strict.getProfile()); assertEquals("BUILT_IN", strict.getSource()); assertEquals("API", strict.getOrigin());
        assertEquals("KamuSM Strict", strict.getName()); assertNotEquals(initial.getPolicyId(), strict.getPolicyId());
        assertArrayEquals(bundled("strict"), bytes(store.snapshot()));
        assertEquals("strict", store.describe().get("profile"));

        byte[] xml = bundled("strict");
        ActivePolicy custom = store.activateCustom(strict.getPolicyId(), xml, "  Kurum politikası v2 ");
        assertEquals("custom", custom.getProfile()); assertEquals("CUSTOM_XML", custom.getSource()); assertEquals("API", custom.getOrigin());
        assertEquals("Kurum politikası v2", custom.getName()); assertEquals(DigestUtils.sha256Hex(xml), custom.getSha256());
        assertFalse(custom.isFallbackApplied());
        xml[0] = 'X'; // caller's buffer is not shared with the active policy
        assertArrayEquals(bundled("strict"), bytes(store.snapshot()));
        assertEquals("CUSTOM_XML", store.describe().get("source"));
        assertEquals("Özel politika", store.activateCustom(custom.getPolicyId(), bundled("strict"), "  ").getName());

        ActivePolicy configured = store.restoreConfiguration(store.current().getPolicyId());
        assertEquals("signer-strict", configured.getProfile()); assertEquals("CONFIGURATION", configured.getOrigin());
        assertEquals(initial.getSha256(), configured.getSha256());
        assertNotEquals(initial.getPolicyId(), configured.getPolicyId());
        assertTrue(configured.getPolicyId().endsWith(":4"));
    }

    @Test void staleOrForeignIdsAreRejectedWithoutChangingState() {
        ActivePolicyStore store = store("signer-strict", "", true);
        String original = store.current().getPolicyId();
        String active = store.activateBuiltIn(original, "strict").getPolicyId();
        PolicyActivationException conflict = rejected("CONFLICT", () -> store.activateBuiltIn(original, "signer-strict"));
        assertEquals(HttpStatus.CONFLICT, conflict.getStatus());
        rejected("CONFLICT", () -> store.activateCustom(original, "<x/>".getBytes(StandardCharsets.UTF_8), null));
        rejected("CONFLICT", () -> store.restoreConfiguration(null));
        assertEquals(active, store.current().getPolicyId()); assertEquals("strict", store.current().getProfile());

        ActivePolicyStore restarted = store("signer-strict", "", true);
        assertNotEquals(store.current().getPolicyId(), restarted.current().getPolicyId());
        assertEquals("CONFIGURATION", restarted.current().getOrigin());
        rejected("CONFLICT", () -> restarted.activateBuiltIn(active, "strict"));
    }

    @Test void inFlightSnapshotKeepsItsPolicyAcrossActivation() throws Exception {
        ActivePolicyStore store = store("signer-strict", "", true);
        ActivePolicyStore.Snapshot inFlight = store.snapshot();
        store.activateBuiltIn(inFlight.getPolicyId(), "strict");
        assertArrayEquals(bundled("signer-strict"), bytes(inFlight));
        assertEquals("signer-strict", inFlight.context().getProfile());
        assertEquals(DigestUtils.sha256Hex(bundled("signer-strict")), inFlight.context().getSha256());
        assertNotEquals(inFlight.getPolicyId(), store.snapshot().getPolicyId());
    }

    @Test void concurrentReadersSeeCompleteOldOrNewSnapshots() throws Exception {
        ActivePolicyStore store = store("signer-strict", "", true);
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            for (int i = 0; i < 3; i++) tasks.add(() -> {
                for (int n = 0; n < 200; n++) {
                    ActivePolicyStore.Snapshot snapshot = store.snapshot();
                    byte[] xml = bytes(snapshot);
                    if (!DigestUtils.sha256Hex(xml).equals(snapshot.context().getSha256())) return false;
                    if (!snapshot.getPolicyId().equals(snapshot.context().getPolicyId())) return false;
                    if (!java.util.Arrays.equals(xml, bundled(snapshot.getProfile()))) return false;
                }
                return true;
            });
            tasks.add(() -> {
                for (int n = 0; n < 50; n++) store.activateBuiltIn(store.current().getPolicyId(), n % 2 == 0 ? "strict" : "signer-strict");
                return true;
            });
            for (Future<Boolean> result : pool.invokeAll(tasks)) assertTrue(result.get());
        } finally { pool.shutdownNow(); }
    }

    @Test void invalidCustomXmlIsRejectedWithClearMessagesAndNoStateChange() throws Exception {
        ActivePolicyStore store = store("signer-strict", "", true);
        String id = store.current().getPolicyId();
        String malformed = "<ConstraintsParameters xmlns=\"" + NS + "\"><SignatureConstraints>";
        assertTrue(rejected("INVALID_POLICY", () -> store.activateCustom(id, malformed.getBytes(StandardCharsets.UTF_8), null))
                .getMessage().contains("iyi biçimlendirilmemiş"));
        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE ConstraintsParameters [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<ConstraintsParameters Name=\"&xxe;\" xmlns=\"" + NS + "\"/>";
        PolicyActivationException dtd = rejected("INVALID_POLICY", () -> store.activateCustom(id, xxe.getBytes(StandardCharsets.UTF_8), null));
        assertTrue(dtd.getMessage().contains("DOCTYPE/ENTITY"), dtd.getMessage());
        assertFalse(dtd.getMessage().contains("root:"), "No external entity content may leak");
        String wrongRoot = "<Policy xmlns=\"urn:other\"/>";
        assertTrue(rejected("INVALID_POLICY", () -> store.activateCustom(id, wrongRoot.getBytes(StandardCharsets.UTF_8), null))
                .getMessage().contains("ConstraintsParameters"));
        String wrongSchema = new String(bundled("strict"), StandardCharsets.UTF_8)
                .replaceFirst("<SignatureConstraints>", "<SignatureConstraints><UnknownConstraint Level=\"FAIL\"/>");
        PolicyActivationException schema = rejected("INVALID_POLICY", () -> store.activateCustom(id, wrongSchema.getBytes(StandardCharsets.UTF_8), null));
        assertTrue(schema.getMessage().contains("ConstraintsParameters şeması"), schema.getMessage());
        assertTrue(schema.getMessage().contains("UnknownConstraint"), schema.getMessage());
        rejected("INVALID_POLICY", () -> store.activateCustom(id, new byte[0], null));
        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 121; i++) longName.append('a');
        rejected("INVALID_POLICY", () -> store.activateCustom(id, bundled("strict"), longName.toString()));
        rejected("INVALID_POLICY", () -> store.activateCustom(id, bundled("strict"), "satır\nkırılımı"));
        rejected("INVALID_POLICY", () -> store.activateBuiltIn(id, "custom"));
        rejected("INVALID_POLICY", () -> store.activateBuiltIn(id, null));

        ActivePolicyStore small = new ActivePolicyStore("signer-strict", "", new DefaultResourceLoader(), 1024, true);
        PolicyActivationException tooBig = rejected("INVALID_POLICY",
                () -> small.activateCustom(small.current().getPolicyId(), bundled("strict"), null));
        assertTrue(tooBig.getMessage().contains("1024"));
        assertEquals(1024, small.capabilities().get("maxBytes"));

        assertEquals(id, store.current().getPolicyId()); assertEquals("CONFIGURATION", store.current().getOrigin());
        assertEquals(HttpStatus.BAD_REQUEST, dtd.getStatus());
    }

    @Test void disabledActivationIsForbiddenAndAdvertised() throws Exception {
        ActivePolicyStore store = store("signer-strict", "", false);
        String id = store.current().getPolicyId();
        PolicyActivationException off = rejected("POLICY_ACTIVATION_DISABLED", () -> store.activateBuiltIn(id, "strict"));
        assertEquals(HttpStatus.FORBIDDEN, off.getStatus());
        rejected("POLICY_ACTIVATION_DISABLED", () -> store.activateCustom(id, bundled("strict"), null));
        rejected("POLICY_ACTIVATION_DISABLED", () -> store.restoreConfiguration(id));
        assertEquals(id, store.current().getPolicyId());
        Map<String, Object> capabilities = store.capabilities();
        assertEquals(true, capabilities.get("activationSupported"));
        assertEquals(false, capabilities.get("activationEnabled"));
        assertEquals(1048576, capabilities.get("maxBytes"));
        assertEquals(true, capabilities.get("contentAvailable"));
        assertThrows(IllegalArgumentException.class, () -> new ActivePolicyStore("strict", "", new DefaultResourceLoader(), 0, true));
    }

    /** Bundled strict policy plus Turkish text, BOM-less UTF-8 (what the UI editor uploads). */
    static byte[] turkishCustom() throws Exception {
        String xml = new String(bundled("strict"), StandardCharsets.UTF_8)
                .replaceFirst("\\?>", "?>\n<!-- Kurum politikası: İmzacı sertifikası ğüşıöç ĞÜŞİÖÇ -->");
        return xml.getBytes(StandardCharsets.UTF_8);
    }

    @Test void builtInContentIsTheBundledResourceUnderItsResourceName() throws Exception {
        for (String profile : new String[]{"signer-strict", "strict"}) {
            ActivePolicyStore store = store(profile, "", false); // reading never needs activation
            ActivePolicyStore.Snapshot content = store.currentSnapshot();
            assertArrayEquals(bundled(profile), content.xml());
            assertEquals(DigestUtils.sha256Hex(bundled(profile)), content.getSha256());
            assertEquals(store.current().getPolicyId(), content.getPolicyId());
            assertEquals(store.current().getSha256(), content.getSha256());
            assertEquals("kamusm-" + profile + "-constraint.xml", content.getFileName());
            assertEquals(StandardCharsets.UTF_8, content.getCharset());
            byte[] copy = content.xml();
            copy[0] = 'X';
            assertArrayEquals(bundled(profile), content.xml(), "Callers get a copy, never the live buffer");
            assertArrayEquals(bundled(profile), bytes(store.snapshot()), "Same bytes that DSS validates with");
        }
        assertEquals("kamusm-signer-strict-constraint.xml", store("typo", "", false).currentSnapshot().getFileName());
    }

    @Test void customContentIsExactlyTheUploadedBytesUntilConfiguredIsRestored() throws Exception {
        ActivePolicyStore store = store("signer-strict", "", true);
        byte[] uploaded = turkishCustom();
        assertEquals('<', uploaded[0], "BOM-less UTF-8");
        ActivePolicy custom = store.activateCustom(store.current().getPolicyId(), uploaded, "Mersel KamuSM Signer-Strict Policy");
        ActivePolicyStore.Snapshot content = store.currentSnapshot();
        assertArrayEquals(uploaded, content.xml());
        assertTrue(new String(content.xml(), StandardCharsets.UTF_8).contains("İmzacı sertifikası ğüşıöç ĞÜŞİÖÇ"));
        assertEquals(DigestUtils.sha256Hex(uploaded), content.getSha256());
        assertEquals(custom.getPolicyId(), content.getPolicyId());
        assertEquals(custom.getSha256(), content.getSha256());
        assertEquals("Mersel-KamuSM-Signer-Strict-Policy.xml", content.getFileName());
        assertEquals(StandardCharsets.UTF_8, content.getCharset());
        uploaded[0] = 'X';
        assertEquals('<', store.currentSnapshot().xml()[0], "The caller's upload buffer is not shared");

        store.activateCustom(custom.getPolicyId(), turkishCustom(), null);
        assertEquals("active-policy.xml", store.currentSnapshot().getFileName(), "No name: generic file name");

        ActivePolicy configured = store.restoreConfiguration(store.current().getPolicyId());
        ActivePolicyStore.Snapshot restored = store.currentSnapshot();
        assertArrayEquals(bundled("signer-strict"), restored.xml());
        assertEquals(configured.getPolicyId(), restored.getPolicyId());
        assertEquals("CONFIGURATION", restored.getOrigin());
        assertEquals("kamusm-signer-strict-constraint.xml", restored.getFileName());
    }

    @Test void configuredFileIsServedVerbatimUnderAGenericNameNeverItsPath(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("secret-dir-kurum.xml");
        byte[] xml = turkishCustom();
        Files.write(file, xml);
        ActivePolicyStore.Snapshot content = store("signer-strict", file.toUri().toString(), false).currentSnapshot();
        assertArrayEquals(xml, content.xml());
        assertEquals("active-policy.xml", content.getFileName());
        assertEquals("CUSTOM_XML", content.getSource());
        assertEquals("CONFIGURATION", content.getOrigin());
    }

    @Test void failedConfigurationHasNoContentAndAnswersTheSame503AsTheMetadata() {
        ActivePolicyStore store = store("signer-strict", BROKEN_PATH, false);
        PolicyActivationException metadata = rejected("POLICY_UNAVAILABLE", store::current);
        PolicyActivationException content = rejected("POLICY_UNAVAILABLE", store::currentSnapshot);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, content.getStatus());
        assertEquals(metadata.getPolicyId(), content.getPolicyId());
        assertEquals(metadata.getMessage(), content.getMessage());
        assertEquals(Boolean.FALSE, content.getActivationEnabled());
        assertFalse(content.getMessage().contains("secret-dir"));
    }

    @Test void safeFileNamesAreAsciiAndNeverPaths() {
        assertEquals("Mersel-KamuSM-Signer-Strict-Policy.xml", ActivePolicyStore.safeFileName("Mersel KamuSM Signer-Strict Policy"));
        assertEquals("Kurum-politikasi-Ozel-Imza-Cg-su.xml", ActivePolicyStore.safeFileName("Kurum politikası Özel İmza Çğ şü"));
        assertEquals("etc-passwd.xml", ActivePolicyStore.safeFileName("../../etc/passwd"));
        assertEquals("C-policies-kurum.xml", ActivePolicyStore.safeFileName("C:\\policies\\kurum.xml"));
        assertEquals("policy.xml", ActivePolicyStore.safeFileName("policy.XML"));
        assertEquals("kurum-v2.xml", ActivePolicyStore.safeFileName("kurum.v2"));
        assertEquals("a-b-c.xml", ActivePolicyStore.safeFileName("a\"b;c"));
        for (String empty : new String[]{null, "", "!!!", "日本語", ".xml", "--"}) {
            assertEquals("active-policy.xml", ActivePolicyStore.safeFileName(empty), String.valueOf(empty));
        }
        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 120; i++) longName.append('ş');
        String trimmed = ActivePolicyStore.safeFileName(longName.toString());
        assertEquals(ActivePolicyStore.MAX_FILE_NAME_BASE_LENGTH + ".xml".length(), trimmed.length());
        assertTrue(trimmed.matches("[A-Za-z0-9_-]+\\.xml"), trimmed);
    }

    @Test void contentCharsetIsTheDocumentsOwnEncoding() throws Exception {
        assertEquals(StandardCharsets.UTF_8, ActivePolicyStore.declaredCharset(bundled("strict")));
        assertEquals(StandardCharsets.UTF_8, ActivePolicyStore.declaredCharset("<ConstraintsParameters/>".getBytes(StandardCharsets.UTF_8)));
        assertEquals(Charset.forName("ISO-8859-9"), ActivePolicyStore.declaredCharset(
                "<?xml version='1.0' encoding='iso-8859-9'?><x/>".getBytes(StandardCharsets.ISO_8859_1)));
        assertEquals(StandardCharsets.UTF_8, ActivePolicyStore.declaredCharset(
                "<?xml version=\"1.0\" encoding=\"no-such-charset\"?><x/>".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(StandardCharsets.UTF_8, ActivePolicyStore.declaredCharset(
                "<?xml version=\"1.0\" encoding=\"UTF-16\"?><x/>".getBytes(StandardCharsets.US_ASCII)), "ASCII bytes contradict UTF-16");
        ByteArrayOutputStream bom = new ByteArrayOutputStream();
        bom.write(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF});
        bom.write("<?xml version=\"1.0\" encoding=\"windows-1254\"?><x/>".getBytes(StandardCharsets.US_ASCII));
        assertEquals(StandardCharsets.UTF_8, ActivePolicyStore.declaredCharset(bom.toByteArray()), "The BOM wins");
        assertEquals(StandardCharsets.UTF_16, ActivePolicyStore.declaredCharset("<x/>".getBytes(StandardCharsets.UTF_16)));

        // A policy uploaded in ISO-8859-9 is kept byte for byte and served with its own charset.
        ActivePolicyStore store = store("signer-strict", "", true);
        Charset latin5 = Charset.forName("ISO-8859-9");
        byte[] xml = new String(turkishCustom(), StandardCharsets.UTF_8)
                .replaceFirst("encoding=\"UTF-8\"", "encoding=\"ISO-8859-9\"").getBytes(latin5);
        store.activateCustom(store.current().getPolicyId(), xml, null);
        ActivePolicyStore.Snapshot content = store.currentSnapshot();
        assertArrayEquals(xml, content.xml());
        assertEquals(latin5, content.getCharset());
        assertTrue(new String(content.xml(), latin5).contains("İmzacı sertifikası ğüşıöç ĞÜŞİÖÇ"));
    }

    @Test void concurrentContentReadersAlwaysGetBytesAndIdentityFromOneSnapshot() throws Exception {
        ActivePolicyStore store = store("signer-strict", "", true);
        byte[] custom = turkishCustom();
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            for (int i = 0; i < 3; i++) tasks.add(() -> {
                for (int n = 0; n < 300; n++) {
                    ActivePolicyStore.Snapshot content = store.currentSnapshot();
                    byte[] xml = content.xml();
                    if (!DigestUtils.sha256Hex(xml).equals(content.getSha256())) return false;
                    boolean builtIn = "BUILT_IN".equals(content.getSource());
                    byte[] expected = builtIn ? bundled(content.getProfile()) : custom;
                    String fileName = builtIn ? "kamusm-" + content.getProfile() + "-constraint.xml" : "Kurum-politikasi.xml";
                    if (!java.util.Arrays.equals(expected, xml) || !fileName.equals(content.getFileName())) return false;
                    if (!content.getPolicyId().equals(content.context().getPolicyId())) return false;
                }
                return true;
            });
            tasks.add(() -> {
                for (int n = 0; n < 60; n++) {
                    String id = store.current().getPolicyId();
                    if (n % 3 == 0) store.activateBuiltIn(id, "strict");
                    else if (n % 3 == 1) store.activateCustom(id, custom, "Kurum politikası");
                    else store.activateBuiltIn(id, "signer-strict");
                }
                return true;
            });
            for (Future<Boolean> result : pool.invokeAll(tasks)) assertTrue(result.get());
        } finally { pool.shutdownNow(); }
    }
}
