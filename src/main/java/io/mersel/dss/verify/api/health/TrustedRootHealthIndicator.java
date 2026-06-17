package io.mersel.dss.verify.api.health;

import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Güven deposu (KamuSM kök sertifikaları) sağlık göstergesi.
 *
 * <p>Bu doğrulayıcı, güven deposunda en az bir kök sertifika olmadan
 * hiçbir imzayı doğrulayamaz — her doğrulama trust chain kuramayıp
 * INDETERMINATE/untrusted döner. Bu yüzden depo <strong>boşsa</strong>
 * pod "hazır değil" sayılmalıdır: readiness grubuna eklenince
 * ({@code management.endpoint.health.group.readiness.include})
 * Kubernetes bu pod'a trafik yönlendirmeyi durdurur ve depo
 * (PostConstruct {@code refreshTrustedRoots} veya cron ile) dolunca
 * otomatik tekrar hazır olur.</p>
 *
 * <p>Bean adı {@code trustedRootStore} — {@code /actuator/health}
 * altında bu anahtarla görünür.</p>
 */
@Component("trustedRootStore")
public class TrustedRootHealthIndicator implements HealthIndicator {

    private static final Logger logger = LoggerFactory.getLogger(TrustedRootHealthIndicator.class);

    private final KamusmRootCertificateService rootCertificateService;

    public TrustedRootHealthIndicator(KamusmRootCertificateService rootCertificateService) {
        this.rootCertificateService = rootCertificateService;
    }

    @Override
    public Health health() {
        try {
            List<X509Certificate> roots = rootCertificateService.getTrustedRoots();
            int count = roots != null ? roots.size() : 0;
            if (count <= 0) {
                return Health.down()
                        .withDetail("trustedRoots", 0)
                        .withDetail("reason", "Güven deposunda kök sertifika yok; "
                                + "doğrulama trust chain kuramaz")
                        .build();
            }
            return Health.up()
                    .withDetail("trustedRoots", count)
                    .build();
        } catch (Exception e) {
            // Sağlık kontrolü hatası akışı bozmaz; readiness DOWN raporlanır.
            logger.warn("TrustedRoot health check başarısız: {}", e.toString());
            return Health.down(e).build();
        }
    }
}
