package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.exceptions.PolicyActivationException;
import io.mersel.dss.verify.api.models.ActivePolicy;
import io.mersel.dss.verify.api.services.verification.ActivePolicyStore;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

/**
 * Sunucunun etkin doğrulama politikası. Etkinleştirme globaldir (sonraki tüm imza doğrulamaları),
 * bellek içidir (yeniden başlatma yapılandırmaya döner) ve yalnız {@code POLICY_ACTIVATION_ENABLED=true}
 * feature flag'i ile açılır. Okuma (meta veri ve {@code /xml} içeriği) her zaman açıktır.
 *
 * <p><b>Prod ortamında kesinlikle kullanmayın.</b> Etkinleştirme (POST) yalnız TÜBİTAK Uyum
 * Değerlendirme sürecindeki deployment'lar için geliştirilmiştir.</p>
 */
@RestController
@RequestMapping("/api/v1/policy/active")
@Tag(name = "Validation Policy", description = "Etkin DSS doğrulama politikası")
public class ActivePolicyController {
    /** GET /xml: gövdenin ait olduğu revizyon (düzenleyip kaydederken {@code expectedPolicyId}). */
    public static final String HEADER_POLICY_ID = "X-Policy-Id";
    /** GET /xml: gövde byte'larının küçük harfli onaltılık SHA-256'sı (= ActivePolicy.sha256). */
    public static final String HEADER_POLICY_SHA256 = "X-Policy-Sha256";
    /** Kullanıcı XML'i API kökeninden tarayıcıda açılırsa (xml-stylesheet vb.) hiçbir şey çalıştırılmaz. */
    static final String CONTENT_SECURITY_POLICY = "default-src 'none'; sandbox";

    private final ActivePolicyStore store;

    public ActivePolicyController(ActivePolicyStore store) {
        this.store = store;
    }

    @GetMapping
    @Operation(summary = "Etkin doğrulama politikası",
            description = "Sonraki imza doğrulamalarının kullanacağı politika (kimlik, kaynak, SHA-256). "
                    + "Yapılandırmadaki dss.policy.path yüklenemiyorsa 503 POLICY_UNAVAILABLE; gövdedeki policyId "
                    + "ile POST (BUILT_IN / CUSTOM_XML / CONFIGURED) kurtarma yapılabilir.")
    public ActivePolicy current() {
        return store.current();
    }

    @GetMapping("/xml")
    @Operation(summary = "Etkin doğrulama politikasının XML'i",
            description = "Sonraki imza doğrulamalarının DSS'e verdiği politika XML'inin byte'ları (yerleşik profil, "
                    + "arayüzden yüklenen özel XML veya dss.policy.path), yeniden kodlanmadan. Gövde ve X-Policy-Id / "
                    + "X-Policy-Sha256 / ETag başlıkları aynı snapshot'tandır; düzenleyip kaydetmek için X-Policy-Id "
                    + "değerini POST mode=CUSTOM_XML isteğinde expectedPolicyId olarak gönderin. Okuma "
                    + "dss.policy.activation-enabled'dan bağımsızdır; sunucu yolu yazılmaz. Yapılandırmadaki "
                    + "dss.policy.path yüklenemiyorsa GET /api/v1/policy/active ile aynı 503 POLICY_UNAVAILABLE.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Etkin politika XML'i",
                            content = @Content(mediaType = "application/xml", schema = @Schema(type = "string", format = "binary")),
                            headers = {
                                    @Header(name = HEADER_POLICY_ID, description = "Gövdenin ait olduğu policyId"),
                                    @Header(name = HEADER_POLICY_SHA256, description = "Gövdenin SHA-256'sı (hex)"),
                                    @Header(name = "ETag", description = "\"<sha256>\""),
                                    @Header(name = "Content-Disposition", description = "inline; filename=\"<ascii>.xml\"")
                            }),
                    @ApiResponse(responseCode = "503", description = "POLICY_UNAVAILABLE (gövdede kurtarma için policyId)",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = io.mersel.dss.verify.api.models.PolicyErrorResponse.class)))
            })
    public ResponseEntity<byte[]> xml() {
        // Tek okuma: gövde ve tüm başlıklar aynı değişmez snapshot'tan (eşzamanlı etkinleştirme karışmaz).
        ActivePolicyStore.Snapshot policy = store.currentSnapshot();
        return ResponseEntity.ok()
                .contentType(new MediaType("application", "xml", policy.getCharset()))
                .header(HEADER_POLICY_ID, policy.getPolicyId())
                .header(HEADER_POLICY_SHA256, policy.getSha256())
                .eTag("\"" + policy.getSha256() + "\"")
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.inline().filename(policy.getFileName()).build().toString())
                // X-Content-Type-Options: nosniff zaten WebSecurityHeadersConfiguration filtresinden gelir.
                .header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
                .body(policy.xml());
    }

    @PostMapping
    @Operation(summary = "Doğrulama politikasını etkinleştir",
            description = "multipart/form-data. BUILT_IN: paketle gelen profil; CUSTOM_XML: XSD ile doğrulanan "
                    + "özel XML; CONFIGURED: başlangıç yapılandırmasına dönüş. expectedPolicyId güncel policyId "
                    + "olmalıdır (aksi halde 409); politika yüklenemiyorken 503 gövdesindeki policyId kullanılır. "
                    + "CONFIGURED, dosya hâlâ yüklenemiyorsa 503 POLICY_UNAVAILABLE döner. "
                    + "Feature flag: yalnız POLICY_ACTIVATION_ENABLED=true ile açılır, kapalıysa 403 "
                    + "POLICY_ACTIVATION_DISABLED. UYARI: Prod ortamında kesinlikle kullanmayın; yalnız TÜBİTAK "
                    + "Uyum Değerlendirme sürecindeki deployment'lar için geliştirilmiştir.")
    public ActivePolicy activate(
            @Parameter(schema = @Schema(allowableValues = {"BUILT_IN", "CUSTOM_XML", "CONFIGURED"}))
            @RequestParam(value = "mode", required = false) String mode,
            @Parameter(description = "mode=BUILT_IN iken zorunlu", schema = @Schema(allowableValues = {"signer-strict", "strict"}))
            @RequestParam(value = "profile", required = false) String profile,
            @Parameter(description = "mode=CUSTOM_XML iken zorunlu politika XML dosyası")
            @RequestParam(value = "policyXml", required = false) MultipartFile policyXml,
            @Parameter(description = "mode=CUSTOM_XML için görünen ad (en fazla 120 karakter)")
            @RequestParam(value = "policyName", required = false) String policyName,
            @Parameter(description = "İstemcinin gördüğü güncel policyId")
            @RequestParam(value = "expectedPolicyId", required = false) String expectedPolicyId) {
        store.requireActivationEnabled();
        if (expectedPolicyId == null || expectedPolicyId.isEmpty()) {
            throw PolicyActivationException.invalid("expectedPolicyId zorunludur; önce GET /api/v1/policy/active ile güncel policyId'yi okuyun.");
        }
        boolean hasFile = policyXml != null;
        if ("BUILT_IN".equals(mode)) {
            rejectExtras(hasFile, policyName, "BUILT_IN");
            return store.activateBuiltIn(expectedPolicyId, profile);
        }
        if ("CUSTOM_XML".equals(mode)) {
            if (profile != null) throw PolicyActivationException.invalid("mode=CUSTOM_XML ile profile gönderilemez.");
            if (!hasFile) throw PolicyActivationException.invalid("mode=CUSTOM_XML için policyXml dosyası zorunludur.");
            return store.activateCustom(expectedPolicyId, read(policyXml), policyName);
        }
        if ("CONFIGURED".equals(mode)) {
            if (profile != null) throw PolicyActivationException.invalid("mode=CONFIGURED ile profile gönderilemez.");
            rejectExtras(hasFile, policyName, "CONFIGURED");
            return store.restoreConfiguration(expectedPolicyId);
        }
        throw PolicyActivationException.invalid("mode BUILT_IN, CUSTOM_XML veya CONFIGURED olmalıdır.");
    }

    private static void rejectExtras(boolean hasFile, String policyName, String mode) {
        if (hasFile) throw PolicyActivationException.invalid("mode=" + mode + " ile policyXml gönderilemez.");
        if (policyName != null) throw PolicyActivationException.invalid("policyName yalnız mode=CUSTOM_XML ile gönderilebilir.");
    }

    private byte[] read(MultipartFile file) {
        // Boyut sınırı byte'lar belleğe alınmadan önce uygulanır.
        if (file.getSize() > store.getMaxBytes()) throw store.tooLarge();
        try {
            return file.getBytes();
        } catch (IOException e) {
            throw PolicyActivationException.invalid("policyXml dosyası okunamadı.");
        }
    }
}
