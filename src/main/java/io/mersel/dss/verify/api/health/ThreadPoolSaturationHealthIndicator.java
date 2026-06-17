package io.mersel.dss.verify.api.health;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Tomcat worker thread havuzunun doygunluğunu izleyen sağlık göstergesi.
 *
 * <p><strong>Neden var?</strong> Bu serviste klasik arıza paterni şudur:
 * KamuSM OCSP/CRL yavaşlayınca revocation fetch'leri uzar, verifier
 * thread'leri blokede birikir ve Tomcat havuzu (default 200) dolar. Sığ
 * sağlık kontrolleri ({@code /actuator/health} veya her zaman UP dönen
 * {@code /api/v1/health}) bunu görmediği için Kubernetes doygun pod'a
 * trafik atmaya devam eder; yük sırayla tüm pod'ları boğar (kademeli
 * brownout, self-heal yok).</p>
 *
 * <p>Bu gösterge {@code tomcat.threads.busy} / {@code tomcat.threads.config.max}
 * oranını okur; eşik aşılınca <strong>OUT_OF_SERVICE</strong> döner. Yalnız
 * <em>readiness</em> grubuna eklenmelidir — böylece doygun pod LB'den
 * düşer (trafik sağlıklı pod'lara kayar) ama <em>liveness</em> etkilenmez
 * (k8s pod'u ÖLDÜRMEZ; yük azalınca pod kendiliğinden tekrar hazır olur).
 * Liveness'a eklemek spike anında restart fırtınası yaratırdı.</p>
 *
 * <p>Bean adı {@code verifierThreadPool}.</p>
 */
@Component("verifierThreadPool")
public class ThreadPoolSaturationHealthIndicator implements HealthIndicator {

    private static final Logger logger =
            LoggerFactory.getLogger(ThreadPoolSaturationHealthIndicator.class);

    private static final String BUSY_METRIC = "tomcat.threads.busy";
    private static final String MAX_METRIC = "tomcat.threads.config.max";

    private final ObjectProvider<MeterRegistry> registryProvider;

    /**
     * Doygunluk eşiği (0–1). busy/max bu oranı aşarsa readiness OUT_OF_SERVICE.
     * Default 0.95 — havuzun %95'i meşgulse yeni trafiği başka pod'a yönlendir.
     */
    @Value("${verification.health.thread-pool-saturation-threshold:0.95}")
    private double saturationThreshold;

    public ThreadPoolSaturationHealthIndicator(ObjectProvider<MeterRegistry> registryProvider) {
        this.registryProvider = registryProvider;
    }

    @Override
    public Health health() {
        MeterRegistry registry = registryProvider != null ? registryProvider.getIfAvailable() : null;
        if (registry == null) {
            // Metrik altyapısı yoksa doygunluk ölçülemez; readiness'i bloke
            // etmemek için UNKNOWN dön (UP gibi davranılmaz ama DOWN da değil).
            return Health.unknown().withDetail("reason", "MeterRegistry yok").build();
        }

        Double busy = gaugeValue(registry, BUSY_METRIC);
        Double max = gaugeValue(registry, MAX_METRIC);

        if (busy == null || max == null || max <= 0) {
            // Tomcat metrikleri henüz bağlanmamış (örn. startup'ın ilk anları).
            return Health.unknown()
                    .withDetail("reason", "Tomcat thread metrikleri henüz yok")
                    .build();
        }

        double ratio = busy / max;
        Health.Builder builder = ratio >= saturationThreshold
                ? Health.outOfService()
                : Health.up();

        return builder
                .withDetail("busyThreads", busy.intValue())
                .withDetail("maxThreads", max.intValue())
                .withDetail("utilization", String.format("%.2f", ratio))
                .withDetail("saturationThreshold", saturationThreshold)
                .build();
    }

    private Double gaugeValue(MeterRegistry registry, String name) {
        try {
            Gauge gauge = registry.find(name).gauge();
            if (gauge == null) {
                return null;
            }
            double v = gauge.value();
            return Double.isNaN(v) ? null : v;
        } catch (RuntimeException e) {
            logger.debug("Gauge okunamadı ({}): {}", name, e.getMessage());
            return null;
        }
    }
}
