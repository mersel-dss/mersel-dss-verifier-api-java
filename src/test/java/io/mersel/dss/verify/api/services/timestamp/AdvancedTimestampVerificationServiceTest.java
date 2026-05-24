package io.mersel.dss.verify.api.services.timestamp;

import io.mersel.dss.verify.api.models.CertificateInfo;
import io.mersel.dss.verify.api.models.RevocationInfo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AdvancedTimestampVerificationService#applyRevocationToCertInfo(CertificateInfo, RevocationInfo)}
 * static helper'inin davranisini sinar.
 *
 * <p>Bu helper hem advanced ({@code /timestamp/verify/advanced}) hem simple
 * ({@code /timestamp/verify}) endpoint'lerinde TSA sertifikasi response'una
 * revocation bilgisini tutarli bicimde yansitmak icin kullanilir. Onceki
 * davranis: hardcoded {@code setRevoked(false)} — REVOKED TSA cert'i bile
 * "iptal degil" gorunuyordu. Yeni davranis: revocation token'a gore gercek
 * durum yansir.
 */
class AdvancedTimestampVerificationServiceTest {

    @Test
    @DisplayName("applyRevocationToCertInfo: null cert info no-op (NPE atmamali)")
    void apply_nullCertInfoIsNoOp() {
        AdvancedTimestampVerificationService.applyRevocationToCertInfo(null, new RevocationInfo());
        // hicbir exception olmamali; bu test sadece guvenli no-op'u dogrular
    }

    @Test
    @DisplayName("applyRevocationToCertInfo: null RevocationInfo cert info'yu degistirmez")
    void apply_nullRevocationInfoLeavesCertUntouched() {
        CertificateInfo cert = new CertificateInfo();
        cert.setRevoked(false);
        cert.setValid(true);

        AdvancedTimestampVerificationService.applyRevocationToCertInfo(cert, null);

        assertFalse(cert.isRevoked());
        assertTrue(cert.isValid());
        assertNull(cert.getRevocation());
        assertNull(cert.getRevocationDate());
        assertNull(cert.getRevocationReason());
    }

    @Test
    @DisplayName("applyRevocationToCertInfo: GOOD durumda revocation set, revoked=false korunur, valid degisme")
    void apply_goodStatus_setsRevocationButLeavesValidFlag() {
        CertificateInfo cert = new CertificateInfo();
        cert.setValid(true);

        RevocationInfo info = new RevocationInfo();
        info.setSource("OCSP");
        info.setStatus("GOOD");
        info.setResponderUrl("http://ocsp.example.com");

        AdvancedTimestampVerificationService.applyRevocationToCertInfo(cert, info);

        assertSame(info, cert.getRevocation());
        assertFalse(cert.isRevoked(), "GOOD durumda revoked=false kalmali");
        assertTrue(cert.isValid(), "GOOD durumda valid degistirilmemeli");
        assertNull(cert.getRevocationDate());
        assertNull(cert.getRevocationReason());
    }

    @Test
    @DisplayName("applyRevocationToCertInfo: REVOKED durumda revoked=true, valid=false, tum tarihler senkron")
    void apply_revokedStatus_setsAllFields() {
        Date revokedAt = new Date(1_600_000_000_000L);
        CertificateInfo cert = new CertificateInfo();
        cert.setValid(true); // baslangicta valid

        RevocationInfo info = new RevocationInfo();
        info.setSource("OCSP");
        info.setStatus("REVOKED");
        info.setRevocationDate(revokedAt);
        info.setRevocationReason("KEY_COMPROMISE");

        AdvancedTimestampVerificationService.applyRevocationToCertInfo(cert, info);

        assertSame(info, cert.getRevocation());
        assertTrue(cert.isRevoked(), "REVOKED durumda revoked=true olmali");
        assertFalse(cert.isValid(), "REVOKED durumda valid false'a dusurulmeli");
        assertEquals(revokedAt, cert.getRevocationDate());
        assertEquals(revokedAt, cert.getRevocationTime(), "legacy revocationTime de set edilmeli");
        assertEquals("KEY_COMPROMISE", cert.getRevocationReason());
    }

    @Test
    @DisplayName("applyRevocationToCertInfo: UNKNOWN durumda revoked=false, geriye donuk alanlar null")
    void apply_unknownStatus_isNeutral() {
        CertificateInfo cert = new CertificateInfo();
        cert.setValid(true);

        RevocationInfo info = new RevocationInfo();
        info.setSource("OCSP");
        info.setStatus("UNKNOWN");

        AdvancedTimestampVerificationService.applyRevocationToCertInfo(cert, info);

        assertSame(info, cert.getRevocation());
        assertFalse(cert.isRevoked());
        assertTrue(cert.isValid(), "UNKNOWN durumda valid degisme");
        assertNull(cert.getRevocationDate());
        assertNull(cert.getRevocationReason());
    }
}
