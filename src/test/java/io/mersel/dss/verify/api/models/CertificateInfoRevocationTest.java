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
 * {@link CertificateInfo}'ya eklenen {@code revocation} alanının dış API
 * sözleşmesini doğrular. Geriye dönük alanlar ({@code revoked},
 * {@code revocationReason}, vb.) korunmaya devam eder.
 */
class CertificateInfoRevocationTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    @DisplayName("revocation field set/get round-trip dogru calisir")
    void revocationField_setterGetterRoundTrip() {
        CertificateInfo cert = new CertificateInfo();
        RevocationInfo rev = new RevocationInfo();
        rev.setSource("OCSP");
        rev.setStatus("GOOD");

        cert.setRevocation(rev);

        assertNotNull(cert.getRevocation());
        assertEquals("OCSP", cert.getRevocation().getSource());
        assertEquals("GOOD", cert.getRevocation().getStatus());
    }

    @Test
    @DisplayName("revocation default'ta null'dur")
    void revocationField_isNullByDefault() {
        CertificateInfo cert = new CertificateInfo();

        assertNull(cert.getRevocation());
    }

    @Test
    @DisplayName("JSON: revocation set ise alt nesne olarak yazilir")
    void jsonSerialization_writesNestedRevocation() throws Exception {
        CertificateInfo cert = new CertificateInfo();
        cert.setCommonName("CN=Signer");

        RevocationInfo rev = new RevocationInfo();
        rev.setSource("OCSP");
        rev.setStatus("REVOKED");
        rev.setRevocationReason("keyCompromise");
        rev.setRevocationDate(new Date(0));
        rev.setResponderUrl("http://ocsp.kamusm.gov.tr");
        rev.setOrigin("EXTERNAL");
        cert.setRevocation(rev);
        cert.setRevoked(true);
        cert.setRevocationReason("keyCompromise");
        cert.setRevocationDate(new Date(0));

        String json = mapper.writeValueAsString(cert);

        assertTrue(json.contains("\"revocation\":{"),
                "revocation alt nesne olarak gozukmeli: " + json);
        assertTrue(json.contains("\"status\":\"REVOKED\""), "status REVOKED gozukmeli");
        assertTrue(json.contains("\"source\":\"OCSP\""), "source OCSP gozukmeli");
        assertTrue(json.contains("\"responderUrl\":\"http://ocsp.kamusm.gov.tr\""),
                "responderUrl gozukmeli");
        assertTrue(json.contains("\"origin\":\"EXTERNAL\""), "origin gozukmeli");

        // Geriye donuk alanlar da korunuyor
        assertTrue(json.contains("\"revoked\":true"), "geriye donuk revoked alani gozukmeli");
    }

    @Test
    @DisplayName("JSON: revocation null ise alt nesne JSON'a dusmez (NON_NULL)")
    void jsonSerialization_omitsRevocationWhenNull() throws Exception {
        CertificateInfo cert = new CertificateInfo();
        cert.setCommonName("CN=Signer");

        String json = mapper.writeValueAsString(cert);

        assertFalse(json.contains("\"revocation\":"),
                "revocation null'sa JSON'a basilmamali: " + json);
    }
}
