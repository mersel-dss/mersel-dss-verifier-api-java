package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link FailedConstraint} POJO sözleşme testleri.
 *
 * <p>Bu sınıf, frontend ve audit pipeline'ları için stabil bir DTO
 * (DSS DetailedReport içindeki <code>&lt;Constraint Status="NOT_OK"&gt;</code>
 * elementlerinin yapısal sunumu); davranışlarının regresyona karşı
 * kilitlenmesi gerek:</p>
 *
 * <ul>
 *   <li>{@code key} her zaman DSS i18n bundle anahtarı (ör. {@code BBB_XCV_ISCGKU})
 *       olarak çıkmalı — locale değişse bile aynı.</li>
 *   <li>{@code message} configured locale'de doldurulmuş insan-okur metin.</li>
 *   <li>{@code @JsonInclude(NON_NULL)} sayesinde {@code null} alanlar JSON'a
 *       sızmamalı (frontend kontratı: alan yoksa zaten yokmuş gibi davranır).</li>
 *   <li>{@code equals}/{@code hashCode}: dedup için
 *       {@code AdvancedSignatureVerificationService} bu sözleşmeye doğrudan
 *       güveniyor (LinkedHashSet üzerinden compound key kuruyor; ama nesne
 *       seviyesinde eşitlik doğru olmalı ki testler ve ileride başka tüketiciler
 *       deterministik karşılaştırma yapabilsin).</li>
 * </ul>
 */
class FailedConstraintTest {

    // -------------------------------------------------------------------------
    // Constructor + accessor
    // -------------------------------------------------------------------------

    @Test
    void noArgConstructor_leavesFieldsNull_forJacksonDeserialization() {
        FailedConstraint d = new FailedConstraint();

        assertNull(d.getKey(), "Key alanı default olarak null olmalı.");
        assertNull(d.getMessage(), "Message alanı default olarak null olmalı.");
    }

    @Test
    void allArgsConstructor_storesKeyAndMessage() {
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU",
                "Sertifika beklenen anahtar kullanım alanına sahip değil!");

        assertEquals("BBB_XCV_ISCGKU", d.getKey());
        assertEquals("Sertifika beklenen anahtar kullanım alanına sahip değil!",
                d.getMessage());
    }

    @Test
    void setters_updateValues() {
        FailedConstraint d = new FailedConstraint();
        d.setKey("BBB_SAV_ISQPMDOSPP");
        d.setMessage("Ne message-digest ne de SignedProperties bulunuyor!");

        assertEquals("BBB_SAV_ISQPMDOSPP", d.getKey());
        assertEquals("Ne message-digest ne de SignedProperties bulunuyor!",
                d.getMessage());
    }

    // -------------------------------------------------------------------------
    // equals / hashCode contract
    // -------------------------------------------------------------------------

    @Test
    void equals_returnsTrue_forSameKeyAndMessage() {
        FailedConstraint a = new FailedConstraint("BBB_XCV_ISCGKU", "msg");
        FailedConstraint b = new FailedConstraint("BBB_XCV_ISCGKU", "msg");

        assertEquals(a, b, "Aynı (key,message) çifti equals'ta true dönmeli.");
        assertEquals(a.hashCode(), b.hashCode(),
                "equals true ise hashCode da eşit olmalı (Java sözleşmesi).");
    }

    @Test
    void equals_returnsFalse_whenKeyDiffers() {
        FailedConstraint a = new FailedConstraint("BBB_XCV_ISCGKU", "msg");
        FailedConstraint b = new FailedConstraint("BBB_XCV_CCCBB", "msg");

        assertNotEquals(a, b);
    }

    @Test
    void equals_returnsFalse_whenMessageDiffers() {
        FailedConstraint a = new FailedConstraint("BBB_XCV_ISCGKU", "Türkçe mesaj");
        FailedConstraint b = new FailedConstraint("BBB_XCV_ISCGKU", "English message");

        assertNotEquals(a, b,
                "Aynı key + farklı message: locale farklı çevirilerin her ikisi "
                        + "de korunmalı; frontend ikisini de listeleyebilir.");
    }

    @Test
    void equals_returnsFalse_forNullAndOtherType() {
        FailedConstraint a = new FailedConstraint("BBB_XCV_ISCGKU", "msg");

        assertNotEquals(null, a);
        assertNotEquals("BBB_XCV_ISCGKU", a);
    }

    @Test
    void equals_handlesNullFieldsSymmetrically() {
        FailedConstraint a = new FailedConstraint();
        FailedConstraint b = new FailedConstraint();

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void hashCode_isDeterministicAcrossInvocations() {
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU", "msg");
        int first = d.hashCode();

        assertEquals(first, d.hashCode(),
                "hashCode aynı obje için her çağrıda aynı olmalı.");
    }

    // -------------------------------------------------------------------------
    // toString — diagnostic friendliness
    // -------------------------------------------------------------------------

    @Test
    void toString_includesBothFields_forEasyDebugging() {
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU",
                "Sertifika beklenen anahtar kullanım alanına sahip değil!");

        String s = d.toString();

        assertTrue(s.contains("BBB_XCV_ISCGKU"),
                "toString key'i içermeli (log'larda kolay arama).");
        assertTrue(s.contains("Sertifika beklenen anahtar"),
                "toString message'ın bir kısmını içermeli.");
    }

    // -------------------------------------------------------------------------
    // Jackson serialization — frontend kontratı
    // -------------------------------------------------------------------------

    @Test
    void jsonSerialization_emitsKeyAndMessageFields() throws Exception {
        FailedConstraint d = new FailedConstraint("TRUSTED_SERVICE_STATUS",
                "Güven hizmeti durumu : http://uri.etsi.org/TrstSvc/Svcstatus/granted");

        String json = new ObjectMapper().writeValueAsString(d);

        assertTrue(json.contains("\"key\":\"TRUSTED_SERVICE_STATUS\""),
                "JSON'da 'key' alanı doğru serileşmeli.");
        assertTrue(json.contains("\"message\":\"G"),
                "JSON'da 'message' alanı doğru serileşmeli (UTF-8 ile başlamalı).");
    }

    @Test
    void jsonSerialization_omitsNullFields_perJsonIncludeNonNull() throws Exception {
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU", null);

        String json = new ObjectMapper().writeValueAsString(d);

        assertTrue(json.contains("\"key\":\"BBB_XCV_ISCGKU\""));
        assertFalse(json.contains("message"),
                "Null message alanı NON_NULL include politikasıyla JSON'a yazılmamalı; "
                        + "FailedConstraint @JsonInclude(NON_NULL) ile annotated.");
    }

    @Test
    void jsonInclude_annotation_isPresent_andSetToNonNull() {
        JsonInclude annotation = FailedConstraint.class.getAnnotation(JsonInclude.class);

        assertNotNull(annotation, "FailedConstraint @JsonInclude annotation'ı taşımalı.");
        assertEquals(JsonInclude.Include.NON_NULL, annotation.value(),
                "Frontend kontratı NON_NULL: null alanlar JSON'da hiç görünmemeli.");
    }

    // -------------------------------------------------------------------------
    // category alanı — opt-in failedConstraints listesi için
    // -------------------------------------------------------------------------

    @Test
    void threeArgConstructor_storesCategory() {
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU",
                "KeyUsage uygunsuz", FailureCategory.ROOT_CAUSE);

        assertEquals("BBB_XCV_ISCGKU", d.getKey());
        assertEquals("KeyUsage uygunsuz", d.getMessage());
        assertEquals(FailureCategory.ROOT_CAUSE, d.getCategory());
    }

    @Test
    void twoArgConstructor_leavesCategory_null_forRootCauseField() {
        // 2-arg constructor SignatureInfo.rootCause alanı için kullanılır;
        // o alan zaten her zaman ROOT_CAUSE olduğu için kategori taşımaz —
        // null kalır ve NON_NULL ile JSON'a yazılmaz.
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU", "msg");

        assertNull(d.getCategory(),
                "2-arg constructor category'yi null bırakır.");
    }

    @Test
    void categorySetter_andGetter_roundTrip() {
        FailedConstraint d = new FailedConstraint();
        d.setCategory(FailureCategory.DERIVED);

        assertEquals(FailureCategory.DERIVED, d.getCategory());
    }

    @Test
    void equals_returnsFalse_whenCategoryDiffers() {
        FailedConstraint root = new FailedConstraint(
                "BBB_XCV_ISCGKU", "msg", FailureCategory.ROOT_CAUSE);
        FailedConstraint derived = new FailedConstraint(
                "BBB_XCV_ISCGKU", "msg", FailureCategory.DERIVED);

        assertNotEquals(root, derived,
                "Aynı key+message + farklı category: eşit değil (category eşitlik "
                        + "kontratının parçası).");
    }

    @Test
    void jsonSerialization_emitsCategory_asUpperCaseEnumName() throws Exception {
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU",
                "KeyUsage uygunsuz", FailureCategory.ROOT_CAUSE);

        String json = new ObjectMapper().writeValueAsString(d);

        assertTrue(json.contains("\"category\":\"ROOT_CAUSE\""),
                "category enum'u Jackson default davranışıyla enum sabit adı "
                        + "(UPPER_CASE) olarak serialize edilmeli — diğer API "
                        + "enum'larıyla (SignatureType, SignaturePackaging, "
                        + "ChainRevocationStatus, ...) tek convention. JSON: " + json);
    }

    @Test
    void jsonSerialization_omitsCategory_whenNull_perNonNull() throws Exception {
        FailedConstraint d = new FailedConstraint("BBB_XCV_ISCGKU", "msg");
        // category null — rootCause alanı için kullanılan 2-arg constructor

        String json = new ObjectMapper().writeValueAsString(d);

        assertFalse(json.contains("category"),
                "Null category NON_NULL ile JSON'a yazılmamalı (rootCause alanı için "
                        + "kategori taşımaya gerek yok — UX tek nesne). JSON: " + json);
    }
}
