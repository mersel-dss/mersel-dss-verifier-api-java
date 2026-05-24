package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RevocationInfo}'nun POJO ve JSON davranışlarını doğrular.
 *
 * <p>Bu model API response'una yeni eklenmiş zengin iptal detayı taşıyıcısıdır.
 * Tüm alanlar opsiyoneldir; ayarlanmayanlar JSON'da görünmemelidir
 * ({@code @JsonInclude(NON_NULL)}).</p>
 */
class RevocationInfoTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("Tum alanlar set / get round-trip dogru calisir")
    void allFields_setterGetterRoundTrip() {
        RevocationInfo info = new RevocationInfo();

        Date now = new Date();
        Date thisUpdate = new Date(now.getTime() - 60_000);
        Date nextUpdate = new Date(now.getTime() + 3_600_000);
        Date revoked = new Date(now.getTime() - 86_400_000);

        info.setSource("OCSP");
        info.setStatus("REVOKED");
        info.setRevocationDate(revoked);
        info.setRevocationReason("keyCompromise");
        info.setProducedAt(now);
        info.setThisUpdate(thisUpdate);
        info.setNextUpdate(nextUpdate);
        info.setResponderUrl("http://ocsp.example.com");
        info.setOrigin("EXTERNAL");

        assertEquals("OCSP", info.getSource());
        assertEquals("REVOKED", info.getStatus());
        assertEquals(revoked, info.getRevocationDate());
        assertEquals("keyCompromise", info.getRevocationReason());
        assertEquals(now, info.getProducedAt());
        assertEquals(thisUpdate, info.getThisUpdate());
        assertEquals(nextUpdate, info.getNextUpdate());
        assertEquals("http://ocsp.example.com", info.getResponderUrl());
        assertEquals("EXTERNAL", info.getOrigin());
    }

    @Test
    @DisplayName("Default constructor'da tum alanlar null")
    void defaultConstructor_allFieldsNull() {
        RevocationInfo info = new RevocationInfo();

        assertNull(info.getSource());
        assertNull(info.getStatus());
        assertNull(info.getRevocationDate());
        assertNull(info.getRevocationReason());
        assertNull(info.getProducedAt());
        assertNull(info.getThisUpdate());
        assertNull(info.getNextUpdate());
        assertNull(info.getResponderUrl());
        assertNull(info.getOrigin());
    }

    @Test
    @DisplayName("JSON: dolu alanlar GOOD durumu icin dogru yazilir")
    void jsonSerialization_goodStatus() throws Exception {
        RevocationInfo info = new RevocationInfo();
        info.setSource("OCSP");
        info.setStatus("GOOD");
        info.setResponderUrl("http://ocsp.kamusm.gov.tr");
        info.setOrigin("EXTERNAL");

        String json = mapper.writeValueAsString(info);

        assertTrue(json.contains("\"source\":\"OCSP\""), "source eksik: " + json);
        assertTrue(json.contains("\"status\":\"GOOD\""), "status eksik: " + json);
        assertTrue(json.contains("\"responderUrl\":\"http://ocsp.kamusm.gov.tr\""),
                "responderUrl eksik: " + json);
        assertTrue(json.contains("\"origin\":\"EXTERNAL\""), "origin eksik: " + json);
        assertFalse(json.contains("revocationDate"),
                "GOOD durumunda revocationDate yazilmamali: " + json);
        assertFalse(json.contains("revocationReason"),
                "GOOD durumunda revocationReason yazilmamali: " + json);
    }

    @Test
    @DisplayName("JSON: REVOKED durumunda iptal tarihi ve nedeni yazilir")
    void jsonSerialization_revokedStatus() throws Exception {
        RevocationInfo info = new RevocationInfo();
        info.setSource("CRL");
        info.setStatus("REVOKED");
        info.setRevocationDate(new Date(0));
        info.setRevocationReason("keyCompromise");

        String json = mapper.writeValueAsString(info);

        assertTrue(json.contains("\"status\":\"REVOKED\""));
        assertTrue(json.contains("\"revocationReason\":\"keyCompromise\""));
        assertTrue(json.contains("\"source\":\"CRL\""));
        assertTrue(json.contains("revocationDate"), "REVOKED'da revocationDate yazilmali: " + json);
    }

    @Test
    @DisplayName("JSON: bos POJO sadece {} doner (NON_NULL)")
    void jsonSerialization_emptyPojoBecomesEmptyObject() throws Exception {
        String json = mapper.writeValueAsString(new RevocationInfo());

        assertEquals("{}", json,
                "Hicbir alan set edilmemisse JSON bos obje olmali: " + json);
    }

    @Test
    @DisplayName("JSON: deserialization round-trip butun alanlari korur")
    void jsonSerialization_roundTrip() throws Exception {
        RevocationInfo original = new RevocationInfo();
        original.setSource("OCSP");
        original.setStatus("GOOD");
        original.setResponderUrl("http://ocsp.kamusm.gov.tr");
        original.setOrigin("CACHED");
        original.setProducedAt(new Date(1700000000000L));
        original.setThisUpdate(new Date(1700000000000L));
        original.setNextUpdate(new Date(1700003600000L));

        String json = mapper.writeValueAsString(original);
        RevocationInfo restored = mapper.readValue(json, RevocationInfo.class);

        assertNotNull(restored);
        assertEquals(original.getSource(), restored.getSource());
        assertEquals(original.getStatus(), restored.getStatus());
        assertEquals(original.getResponderUrl(), restored.getResponderUrl());
        assertEquals(original.getOrigin(), restored.getOrigin());
        assertEquals(original.getProducedAt(), restored.getProducedAt());
        assertEquals(original.getThisUpdate(), restored.getThisUpdate());
        assertEquals(original.getNextUpdate(), restored.getNextUpdate());
    }
}
