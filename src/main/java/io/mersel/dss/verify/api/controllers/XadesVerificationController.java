package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.verification.SignatureVerificationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * XAdES (XML) imza doğrulama controller
 */
@RestController
@RequestMapping("/api/v1/verify/xades")
@Tag(name = "XAdES Verification", description = "XML imza doğrulama işlemleri")
public class XadesVerificationController {

    private static final Logger logger = LoggerFactory.getLogger(XadesVerificationController.class);

    @Autowired
    private SignatureVerificationService verificationService;

    @PostMapping(value = "/simple", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Basit XAdES doğrulama",
            description = "İmzalı XML dokümanını basit seviyede doğrular. Sadece imza geçerliliğini kontrol eder.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Doğrulama başarılı",
                            content = @Content(schema = @Schema(implementation = VerificationResult.class))
                    ),
                    @ApiResponse(responseCode = "400", description = "Geçersiz istek"),
                    @ApiResponse(responseCode = "500", description = "Sunucu hatası")
            }
    )
    public ResponseEntity<VerificationResult> verifySimple(
            @Parameter(description = "İmzalı XML dokümanı", required = true)
            @RequestParam("signedDocument") MultipartFile signedDocument,

            @Parameter(description = "Orijinal doküman (detached signature için)", required = false)
            @RequestParam(value = "originalDocument", required = false) MultipartFile originalDocument,

            @Parameter(description = "Doğrulama seviyesi", required = false)
            @RequestParam(value = "level", defaultValue = "SIMPLE") VerificationLevel level) {

        logger.info("Simple XAdES verification request received for: {}", signedDocument.getOriginalFilename());

        VerificationResult result = verificationService.verifySignature(
                signedDocument,
                originalDocument,
                level
        );

        return ResponseEntity.ok(result);
    }
}
