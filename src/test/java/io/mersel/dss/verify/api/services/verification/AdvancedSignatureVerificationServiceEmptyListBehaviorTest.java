package io.mersel.dss.verify.api.services.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mersel.dss.verify.api.models.FailedConstraint;
import io.mersel.dss.verify.api.models.SignatureInfo;
import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code includeFailedConstraints=true} ama imza VALID (FAIL constraint
 * yok) durumunda alanın <em>boş array</em> olarak görünmesi kontratı.
 *
 * <p>Tasarım kararı: opt-in flag verildiyse alan deterministik olarak
 * set edilir — boş bile olsa. Bu sayede frontend "opt-in onaylandı mı?"
 * sınamasını basitçe "alan var mı?" üzerinden yapar; null vs `[]` ayrımı
 * boş listede de güvenilir.</p>
 *
 * <p>Mevcut filter algoritması ve sınıflandırma için bkz.
 * {@link AdvancedSignatureVerificationServiceFailedConstraintTest}.
 * Bu sınıf yalnız <em>kontrat yüzeyi</em> davranışını koruma altına alır.</p>
 */
class AdvancedSignatureVerificationServiceEmptyListBehaviorTest {

    @Test
    void emptyFailedConstraints_isStillSerialized_asEmptyArray() throws Exception {
        // Service stub: imza VALID, hiç FAIL constraint yok. Ama
        // includeFailedConstraints=true ile çağrıldığı için service
        // boş listeyi yine de set eder.
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("S-VALID");
        info.setValid(true);
        info.setFailedConstraints(Collections.<FailedConstraint>emptyList());

        String json = new ObjectMapper().writeValueAsString(info);

        assertTrue(json.contains("\"failedConstraints\":[]"),
                "Boş liste JSON'da '[]' olarak görünmeli — opt-in onayını taşır. "
                        + "JSON: " + json);
    }

    @Test
    void nullFailedConstraints_isOmitted_perNonNull() throws Exception {
        // Default davranış: includeFailedConstraints verilmedi → service
        // alan null bıraktı → JSON'da hiç görünmez.
        SignatureInfo info = new SignatureInfo();
        info.setSignatureId("S-VALID");
        info.setValid(true);
        // setFailedConstraints çağrılmadı

        String json = new ObjectMapper().writeValueAsString(info);

        assertTrue(!json.contains("failedConstraints"),
                "Null failedConstraints @JsonInclude(NON_NULL) ile JSON'a sızmamalı. "
                        + "JSON: " + json);
    }

    @Test
    void emptyVsNull_areDistinguishable_inJson() throws Exception {
        // İki imza, biri opt-in açık (boş array), biri opt-in kapalı (null).
        SignatureInfo withOpt = new SignatureInfo();
        withOpt.setFailedConstraints(Collections.<FailedConstraint>emptyList());
        SignatureInfo withoutOpt = new SignatureInfo();

        String withOptJson = new ObjectMapper().writeValueAsString(withOpt);
        String withoutOptJson = new ObjectMapper().writeValueAsString(withoutOpt);

        assertNotNull(withOptJson);
        assertNotNull(withoutOptJson);
        assertEquals(true, withOptJson.contains("failedConstraints"),
                "Opt-in açıkken alan görünür (boş array bile). JSON: " + withOptJson);
        assertEquals(false, withoutOptJson.contains("failedConstraints"),
                "Opt-in kapalıyken alan görünmez. JSON: " + withoutOptJson);
    }
}
