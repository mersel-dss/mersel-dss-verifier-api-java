package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.models.TrustEvidence;
import io.mersel.dss.verify.api.services.certificate.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.util.*;

@RestController
@RequestMapping("/api/v1/trust/active")
public class ActiveTrustController {
    private final ActiveTrustStore store;
    private final KamusmRootCertificateService roots;
    private final RequestTrustFactory factory;
    private final boolean online;
    public ActiveTrustController(ActiveTrustStore store, KamusmRootCertificateService roots, RequestTrustFactory factory,
            @Value("${verification.online-validation-enabled:true}") boolean online) {
        this.store = store; this.roots = roots; this.factory = factory; this.online = online;
    }
    @GetMapping
    public TrustEvidence current() { return roots.getVerificationTrustContext().evidence(online); }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public TrustEvidence activate(@RequestParam("mode") String mode,
            @RequestParam("expectedTrustId") String expectedTrustId,
            @RequestParam(value = "retainSha256", required = false) List<String> retained,
            @RequestParam(value = "trustedCertificates", required = false) List<MultipartFile> files) {
        if (!factory.isEnabled()) throw new IllegalArgumentException("Aktif kök değişimi kapalı; evaluation profili veya REQUEST_TRUST_ENABLED=true gerekir");
        RequestTrustContext uploaded = factory.resolve(mode, files);
        return store.replace(expectedTrustId, uploaded, retained == null ? Collections.emptyList() : retained,
                roots::getConfiguredCertificateSource).evidence(online);
    }
}
