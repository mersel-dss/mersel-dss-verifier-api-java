package io.mersel.dss.verify.api.models.enums;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * {@link SignaturePackaging} enum'unun sabit isimlerini ve DSS upstream
 * uyumunu doğrular.
 *
 * <p>Regresyon kritik: enum sabit isimleri JSON sözleşmesinin parçasıdır
 * ({@code "ENVELOPED"} / {@code "ENVELOPING"} / {@code "DETACHED"}) ve
 * istemcide bu string'lerle eşleşir; ayrıca DSS upstream
 * {@code eu.europa.esig.dss.enumerations.SignaturePackaging} ile birebir
 * aynı tutulur ki interop'ta mapping gerektirmesin.</p>
 */
class SignaturePackagingTest {

    @Test
    @DisplayName("Enum sabit isimleri W3C XMLDSig terminolojisiyle uyumlu (DSS upstream ile aynı)")
    void enumNames_matchW3cAndDssUpstream() {
        assertEquals("ENVELOPED", SignaturePackaging.ENVELOPED.name());
        assertEquals("ENVELOPING", SignaturePackaging.ENVELOPING.name());
        assertEquals("DETACHED", SignaturePackaging.DETACHED.name());
    }

    @Test
    @DisplayName("Enum'da tam olarak 3 sabit var (kazara yeni sabit eklenirse test kırılır)")
    void enum_hasExactlyThreeConstants() {
        assertEquals(3, SignaturePackaging.values().length,
                "Yeni paketleme tipi eklemek API kontrat değişikliğidir, dikkatli olunsun");
    }
}
