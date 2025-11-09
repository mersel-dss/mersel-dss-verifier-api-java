package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.dtos.TimestampVerificationResponseDto;
import io.mersel.dss.verify.api.services.timestamp.TimestampVerificationService;
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
 * Zaman damgası doğrulama controller
 */
@RestController
@RequestMapping("/api/v1/verify/timestamp")
@Tag(name = "Timestamp Verification", description = "Zaman damgası doğrulama işlemleri")
public class TimestampVerificationController {

    private static final Logger logger = LoggerFactory.getLogger(TimestampVerificationController.class);

    @Autowired
    private TimestampVerificationService timestampVerificationService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
        summary = "Zaman damgası doğrulama",
        description = "Zaman damgası token'ını doğrular. İsteğe bağlı olarak orijinal veri ile message imprint doğrulaması yapar.",
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Doğrulama başarılı",
                content = @Content(schema = @Schema(implementation = TimestampVerificationResponseDto.class))
            ),
            @ApiResponse(responseCode = "400", description = "Geçersiz istek"),
            @ApiResponse(responseCode = "500", description = "Sunucu hatası")
        }
    )
    public ResponseEntity<TimestampVerificationResponseDto> verifyTimestamp(
            @Parameter(description = "Zaman damgası token dosyası (.tst veya .ts)", required = true)
            @RequestParam("timestampToken") MultipartFile timestampToken,
            
            @Parameter(description = "Orijinal veri (message imprint doğrulaması için)", required = false)
            @RequestParam(value = "originalData", required = false) MultipartFile originalData,
            
            @Parameter(description = "TSA sertifikası doğrulaması yapılsın mı", required = false)
            @RequestParam(value = "validateCertificate", defaultValue = "true") boolean validateCertificate) {

        logger.info("Timestamp verification request received for: {}", timestampToken.getOriginalFilename());

        TimestampVerificationResponseDto result = timestampVerificationService.verifyTimestamp(
            timestampToken,
            originalData,
            validateCertificate
        );

        return ResponseEntity.ok(result);
    }
}

