package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.verify.api.models.enums.ChainRevocationStatus;
import io.mersel.dss.verify.api.models.enums.SignaturePackaging;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SignatureInfo}'nun paketleme alanını doğrular.
 *
 * <p>{@code signaturePackaging} alanı set edilmişse W3C XMLDSig sabit adıyla
 * JSON'a yazılır; null ise hiç çıkmaz ({@code @JsonInclude(NON_NULL)}).</p>
 */
class SignatureInfoTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("setSignaturePackaging / getSignaturePackaging round-trip")
    void signaturePackaging_setterGetterRoundTrip() {
        SignatureInfo info = new SignatureInfo();

        info.setSignaturePackaging(SignaturePackaging.ENVELOPED);
        assertEquals(SignaturePackaging.ENVELOPED, info.getSignaturePackaging());

        info.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        assertEquals(SignaturePackaging.ENVELOPING, info.getSignaturePackaging());

        info.setSignaturePackaging(SignaturePackaging.DETACHED);
        assertEquals(SignaturePackaging.DETACHED, info.getSignaturePackaging());
    }

    @Test
    @DisplayName("Paketleme default'ta null (CAdES/PAdES için)")
    void signaturePackaging_isNullByDefault() {
        SignatureInfo info = new SignatureInfo();

        assertNull(info.getSignaturePackaging());
    }

    @Test
    @DisplayName("JSON: paketleme set ise W3C enum sabit adıyla yazılır")
    void jsonSerialization_writesEnumName() throws Exception {
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("test-sig-1");
        info.setSignaturePackaging(SignaturePackaging.ENVELOPED);

        String json = mapper.writeValueAsString(info);

        assertTrue(json.contains("\"signaturePackaging\":\"ENVELOPED\""),
                "Paketleme W3C enum adıyla raporlanmalı: " + json);
    }

    @Test
    @DisplayName("JSON: paketleme null ise alan JSON'a düşmez (NON_NULL)")
    void jsonSerialization_omitsFieldWhenNull() throws Exception {
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("test-sig-2");

        String json = mapper.writeValueAsString(info);

        assertFalse(json.contains("signaturePackaging"),
                "Paketleme null'sa JSON'a basılmamalı: " + json);
    }

    @Test
    @DisplayName("chainRevocationStatus set/get round-trip")
    void chainRevocationStatus_setterGetterRoundTrip() {
        SignatureInfo info = new SignatureInfo();

        info.setChainRevocationStatus(ChainRevocationStatus.ALL_GOOD);
        assertEquals(ChainRevocationStatus.ALL_GOOD, info.getChainRevocationStatus());

        info.setChainRevocationStatus(ChainRevocationStatus.LEAF_REVOKED);
        assertEquals(ChainRevocationStatus.LEAF_REVOKED, info.getChainRevocationStatus());
    }

    @Test
    @DisplayName("chainRevocationStatus default'ta null")
    void chainRevocationStatus_isNullByDefault() {
        SignatureInfo info = new SignatureInfo();

        assertNull(info.getChainRevocationStatus());
    }

    @Test
    @DisplayName("JSON: chainRevocationStatus set ise enum adiyla yazilir")
    void jsonSerialization_writesChainStatusEnumName() throws Exception {
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("test-sig-3");
        info.setChainRevocationStatus(ChainRevocationStatus.LEAF_GOOD_CA_REVOKED);

        String json = mapper.writeValueAsString(info);

        assertTrue(json.contains("\"chainRevocationStatus\":\"LEAF_GOOD_CA_REVOKED\""),
                "chainRevocationStatus enum adiyla raporlanmali: " + json);
    }

    @Test
    @DisplayName("JSON: chainRevocationStatus null ise alan JSON'a dusmez (NON_NULL)")
    void jsonSerialization_omitsChainStatusWhenNull() throws Exception {
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("test-sig-4");

        String json = mapper.writeValueAsString(info);

        assertFalse(json.contains("chainRevocationStatus"),
                "chainRevocationStatus null'sa JSON'a basilmamali: " + json);
    }
}
