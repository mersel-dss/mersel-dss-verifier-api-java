package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SignatureInfo#getRootCause()} / {@link SignatureInfo#setRootCause(FailedConstraint)}
 * modeli için kontrat testleri. {@code failedConstraints: List<FailedConstraint>}
 * alanından {@code rootCause: FailedConstraint} tek nesne alanına geçişi
 * koruma altına alır — DSS pipeline'ının pipeline-side-effect satırlarını
 * (XCV-top roll-up + SAV/CV cascade) filtreleyip yalnız tek kök neden
 * dönmesi UX kontratı backend tarafında garantilenir.
 *
 * <p>Filter algoritması ve fallback davranışı için bkz.
 * {@link io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationServiceFailedConstraintTest}.
 * Buradaki testler yalnız model serialization kontratını korur.</p>
 */
class SignatureInfoRootCauseTest {

    @Test
    void rootCause_setter_andGetter_roundTrip() {
        FailedConstraint fc = new FailedConstraint("BBB_XCV_ISCGKU",
                "İmzacı sertifikası, beklenen anahtar kullanım alanına (KeyUsage) sahip değil!");
        SignatureInfo info = new SignatureInfo();

        info.setRootCause(fc);

        assertEquals(fc, info.getRootCause(),
                "setRootCause/getRootCause aynı objeyi taşımalı.");
    }

    @Test
    void rootCause_isNull_byDefault() {
        SignatureInfo info = new SignatureInfo();

        assertNull(info.getRootCause(),
                "Yeni SignatureInfo objesinde rootCause null olmalı (NON_NULL JSON için).");
    }

    @Test
    void jsonSerialization_emitsRootCause_whenSet() throws Exception {
        SignatureInfo info = new SignatureInfo();
        info.setRootCause(new FailedConstraint("BBB_XCV_ISCGKU", "msg"));

        String json = new ObjectMapper().writeValueAsString(info);

        assertTrue(json.contains("\"rootCause\""),
                "rootCause set edildiğinde JSON'da görünmeli. JSON: " + json);
        assertTrue(json.contains("\"BBB_XCV_ISCGKU\""), "Alan değeri serialize edilmeli.");
    }

    @Test
    void jsonSerialization_omitsRootCause_whenNull_perNonNullInclude() throws Exception {
        SignatureInfo info = new SignatureInfo();
        // rootCause null kalır

        String json = new ObjectMapper().writeValueAsString(info);

        assertFalse(json.contains("rootCause"),
                "Null rootCause @JsonInclude(NON_NULL) ile JSON'a yazılmamalı; "
                        + "frontend kontratı: alan görünmez = problem yok. JSON: " + json);
    }

    // -------------------------------------------------------------------------
    // failedConstraints alanı — opt-in kategorize liste
    // -------------------------------------------------------------------------

    @Test
    void failedConstraints_isNull_byDefault() {
        SignatureInfo info = new SignatureInfo();

        assertNull(info.getFailedConstraints(),
                "Yeni SignatureInfo objesinde failedConstraints null olmalı — opt-in alan, "
                        + "default davranış: kapalı.");
    }

    @Test
    void failedConstraints_setter_andGetter_roundTrip() {
        FailedConstraint root = new FailedConstraint(
                "BBB_XCV_ISCGKU", "KeyUsage uygunsuz", FailureCategory.ROOT_CAUSE);
        FailedConstraint derived = new FailedConstraint(
                "BBB_XCV_SUB", "Roll-up", FailureCategory.DERIVED);
        SignatureInfo info = new SignatureInfo();
        List<FailedConstraint> list = Arrays.asList(root, derived);

        info.setFailedConstraints(list);

        assertEquals(list, info.getFailedConstraints(),
                "setFailedConstraints/getFailedConstraints aynı listeyi taşımalı.");
    }

    @Test
    void jsonSerialization_omitsFailedConstraints_whenNull_perNonNullInclude() throws Exception {
        // Default davranış: opt-in flag verilmediği için service alanı null
        // bırakır. Frontend response'ta bu alanı görmemeli.
        SignatureInfo info = new SignatureInfo();
        info.setRootCause(new FailedConstraint("BBB_XCV_ISCGKU", "msg"));
        // failedConstraints null bırakılır

        String json = new ObjectMapper().writeValueAsString(info);

        assertFalse(json.contains("failedConstraints"),
                "Null failedConstraints @JsonInclude(NON_NULL) ile JSON'a yazılmamalı; "
                        + "default davranışta alan hiç görünmez. JSON: " + json);
    }

    @Test
    void jsonSerialization_emitsFailedConstraints_whenSet() throws Exception {
        // Opt-in davranış: service ?includeFailedConstraints=true ile çağrıldığında
        // listeyi doldurur; her satır kendi kategorisini taşır.
        SignatureInfo info = new SignatureInfo();
        info.setFailedConstraints(Arrays.asList(
                new FailedConstraint(
                        "BBB_XCV_ISCGKU", "KeyUsage", FailureCategory.ROOT_CAUSE),
                new FailedConstraint(
                        "BBB_XCV_SUB", "Roll-up", FailureCategory.DERIVED),
                new FailedConstraint(
                        "BBB_SAV_ISQPMDOSPP", "Cascade", FailureCategory.CASCADE)));

        String json = new ObjectMapper().writeValueAsString(info);

        assertTrue(json.contains("\"failedConstraints\""),
                "failedConstraints set edildiğinde JSON'da görünmeli. JSON: " + json);
        assertTrue(json.contains("\"ROOT_CAUSE\"")
                        && json.contains("\"DERIVED\"")
                        && json.contains("\"CASCADE\""),
                "Her üç kategori de JSON'da UPPER_CASE (enum sabit adı) görünmeli — "
                        + "tüm API enum'larıyla aynı convention. JSON: " + json);
    }
}
