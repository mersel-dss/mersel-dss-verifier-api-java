package io.mersel.dss.verify.api.services.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Çalışma anında politika etkinleştirme bir feature flag'tir: gerçek
 * {@code application.properties} / {@code application-evaluation.properties} ile
 * varsayılan kapalıdır ve yalnız {@code POLICY_ACTIVATION_ENABLED=true} açar.
 * Prod ortamında kullanılmaz; TÜBİTAK Uyum Değerlendirme deployment'ları içindir.
 */
class PolicyActivationFeatureFlagTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(ActivePolicyStore.class);

    @Test
    @DisplayName("Varsayılan: kapalı")
    void disabledByDefault() {
        runner.run(context -> assertFalse(context.getBean(ActivePolicyStore.class).isActivationEnabled()));
    }

    @Test
    @DisplayName("REQUEST_TRUST_ENABLED=true politika etkinleştirmeyi açmaz")
    void requestTrustDoesNotEnableActivation() {
        runner.withPropertyValues("REQUEST_TRUST_ENABLED=true")
                .run(context -> assertFalse(context.getBean(ActivePolicyStore.class).isActivationEnabled()));
    }

    @Test
    @DisplayName("evaluation profili politika etkinleştirmeyi açmaz")
    void evaluationProfileDoesNotEnableActivation() {
        runner.withPropertyValues("spring.profiles.active=evaluation")
                .run(context -> {
                    // Profil gerçekten yüklendi: request trust açık, politika etkinleştirme kapalı.
                    assertEquals(Boolean.TRUE, context.getEnvironment()
                            .getProperty("verification.request-trust.enabled", Boolean.class));
                    assertFalse(context.getBean(ActivePolicyStore.class).isActivationEnabled());
                });
    }

    @Test
    @DisplayName("POLICY_ACTIVATION_ENABLED=true açar")
    void enabledOnlyByEnv() {
        runner.withPropertyValues("POLICY_ACTIVATION_ENABLED=true")
                .run(context -> assertTrue(context.getBean(ActivePolicyStore.class).isActivationEnabled()));
    }
}
