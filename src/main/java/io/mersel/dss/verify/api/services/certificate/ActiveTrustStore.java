package io.mersel.dss.verify.api.services.certificate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import io.mersel.dss.verify.api.exceptions.TrustConflictException;
import org.springframework.stereotype.Component;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

/** Process-local active trust. A request keeps its immutable snapshot across later activations. */
@Component
public class ActiveTrustStore {
    private final String instanceId = UUID.randomUUID().toString();
    private long revision;
    private String activatedAt = Instant.now().toString();
    // null is standard resolver; non-null empty CUSTOM is deliberately no trust.
    private RequestTrustContext override;

    public synchronized RequestTrustContext snapshot(Supplier<CommonTrustedCertificateSource> standard) {
        RequestTrustContext context = override == null ? RequestTrustContext.server(standard.get()) : override;
        return context.activated(id(), activatedAt);
    }
    public synchronized RequestTrustContext replace(String expectedId, RequestTrustContext uploaded,
            Collection<String> retained, Supplier<CommonTrustedCertificateSource> standard) {
        requireCurrent(expectedId);
        if (retained.size() > RequestTrustFactory.MAX_CERTIFICATES) throw new IllegalArgumentException("En fazla 100 kök korunabilir");
        if (uploaded == null) {
            if (!retained.isEmpty()) throw new IllegalArgumentException("Standart depoya dönüşte kök listesi gönderilemez");
            // Snapshot first: a failing resolver read must not partially reset activation.
            RequestTrustContext server = RequestTrustContext.server(standard.get());
            override = null;
            revision++; activatedAt = Instant.now().toString();
            return server.activated(id(), activatedAt);
        }
        List<CertificateToken> tokens = new ArrayList<>(uploaded.newSource().getCertificates());
        if (!retained.isEmpty()) {
            RequestTrustContext baseline = override == null ? RequestTrustContext.server(standard.get()) : override;
            tokens.addAll(baseline.retain(retained));
        }
        RequestTrustContext replacement = new RequestTrustContext("CUSTOM", tokens);
        List<CertificateToken> unique = replacement.newSource().getCertificates();
        long bytes = 0;
        for (CertificateToken token : unique) bytes += token.getEncoded().length;
        if (unique.size() > RequestTrustFactory.MAX_CERTIFICATES || bytes > RequestTrustFactory.MAX_BYTES)
            throw new IllegalArgumentException("Etkin küme en fazla 100 sertifika ve 1 MB olabilir");
        override = replacement;
        revision++; activatedAt = Instant.now().toString();
        return replacement.activated(id(), activatedAt);
    }
    private String id() { return instanceId + ":" + revision; }
    private void requireCurrent(String expected) {
        if (!id().equals(expected)) throw new TrustConflictException();
    }
}
