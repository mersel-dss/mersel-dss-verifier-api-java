package io.mersel.dss.verify.api.controllers;

import io.mersel.dss.verify.api.dtos.TimestampVerificationResponseDto;
import io.mersel.dss.verify.api.models.VerificationResult;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.timestamp.AdvancedTimestampVerificationService;
import io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService;
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
 * Birleşik doğrulama controller'ı
 * - Tüm imza formatlarını destekler (XAdES-BES, XAdES-A, PAdES, CAdES)
 * - Zaman damgası doğrulaması
 * - Simple ve Comprehensive modları
 */
@RestController
@RequestMapping("/api/v1/verify")
@Tag(name = "Unified Verification", description = "Birleşik imza ve zaman damgası doğrulama API")
public class UnifiedVerificationController {

    private static final Logger logger = LoggerFactory.getLogger(UnifiedVerificationController.class);

    @Autowired
    private AdvancedSignatureVerificationService advancedSignatureVerificationService;

    @Autowired
    private AdvancedTimestampVerificationService advancedTimestampVerificationService;

    /**
     * İmza doğrulama - Tüm formatları destekler
     * XAdES: BES, EPES, T, C, X, XL, A
     * PAdES: B-B, B-T, B-LT, B-LTA
     * CAdES: BES, EPES, T, C, X, XL, A
     */
    @PostMapping(value = "/signature", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
        summary = "İmza doğrulama",
        description = "Dijital imzalı dokümanı doğrular. Tüm XAdES, PAdES ve CAdES formatlarını destekler. " +
                      "Simple mod temel doğrulama, Comprehensive mod detaylı analiz sağlar.",
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
    public ResponseEntity<VerificationResult> verifySignature(
            @Parameter(description = "İmzalı doküman dosyası (XML, PDF vb.)", required = true)
            @RequestParam("signedDocument") MultipartFile signedDocument,
            
            @Parameter(description = "Orijinal doküman (detached signature için)")
            @RequestParam(value = "originalDocument", required = false) MultipartFile originalDocument,
            
            @Parameter(description = "Doğrulama seviyesi: SIMPLE (basit) veya COMPREHENSIVE (kapsamlı)", 
                      schema = @Schema(allowableValues = {"SIMPLE", "COMPREHENSIVE"}))
            @RequestParam(value = "level", defaultValue = "SIMPLE") String level) {

        logger.info("Unified signature verification request received. Level: {}, File: {}", 
                level, signedDocument.getOriginalFilename());

        VerificationLevel verificationLevel = parseVerificationLevel(level);
        
        VerificationResult result = advancedSignatureVerificationService.verifySignature(
                signedDocument,
                originalDocument,
                verificationLevel
        );

        logger.info("Verification completed. Valid: {}, Type: {}", 
                result.isValid(), result.getSignatureType());

        return ResponseEntity.ok(result);
    }

    /**
     * Zaman damgası doğrulama
     */
    @PostMapping(value = "/timestamp", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
        summary = "Zaman damgası doğrulama",
        description = "RFC 3161 uyumlu zaman damgasını doğrular. TSA sertifika zinciri, " +
                      "message imprint ve revocation kontrollerini içerir.",
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
            @Parameter(description = "Zaman damgası dosyası (.tsr)", required = true)
            @RequestParam("timestampFile") MultipartFile timestampFile,
            
            @Parameter(description = "Orijinal veri dosyası (message imprint doğrulaması için)")
            @RequestParam(value = "originalData", required = false) MultipartFile originalData,
            
            @Parameter(description = "TSA sertifika doğrulaması yapılsın mı")
            @RequestParam(value = "validateCertificate", defaultValue = "true") boolean validateCertificate) {

        logger.info("Timestamp verification request received. ValidateCert: {}, File: {}", 
                validateCertificate, timestampFile.getOriginalFilename());

        TimestampVerificationResponseDto result = advancedTimestampVerificationService.verifyTimestamp(
                timestampFile,
                originalData,
                validateCertificate
        );

        logger.info("Timestamp verification completed. Valid: {}", result.isValid());

        return ResponseEntity.ok(result);
    }

    /**
     * XAdES imza doğrulama (eski endpoint - geriye uyumluluk için)
     */
    @PostMapping(value = "/xades", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
        summary = "XAdES imza doğrulama",
        description = "XAdES formatındaki dijital imzayı doğrular. Tüm XAdES seviyelerini destekler: " +
                      "BES, EPES, T, C, X, XL, A",
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Doğrulama başarılı",
                content = @Content(schema = @Schema(implementation = VerificationResult.class))
            )
        }
    )
    public ResponseEntity<VerificationResult> verifyXAdES(
            @RequestParam("signedDocument") MultipartFile signedDocument,
            @RequestParam(value = "originalDocument", required = false) MultipartFile originalDocument,
            @RequestParam(value = "level", defaultValue = "SIMPLE") String level) {

        logger.info("XAdES verification request (legacy endpoint)");
        return verifySignature(signedDocument, originalDocument, level);
    }

    /**
     * PAdES imza doğrulama (eski endpoint - geriye uyumluluk için)
     */
    @PostMapping(value = "/pades", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
        summary = "PAdES imza doğrulama",
        description = "PAdES formatındaki PDF imzasını doğrular. Tüm PAdES seviyelerini destekler: " +
                      "B-B, B-T, B-LT, B-LTA",
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Doğrulama başarılı",
                content = @Content(schema = @Schema(implementation = VerificationResult.class))
            )
        }
    )
    public ResponseEntity<VerificationResult> verifyPAdES(
            @RequestParam("signedDocument") MultipartFile signedDocument,
            @RequestParam(value = "level", defaultValue = "SIMPLE") String level) {

        logger.info("PAdES verification request (legacy endpoint)");
        return verifySignature(signedDocument, null, level);
    }

    /**
     * CAdES imza doğrulama
     */
    @PostMapping(value = "/cades", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
        summary = "CAdES imza doğrulama",
        description = "CAdES formatındaki dijital imzayı doğrular. Tüm CAdES seviyelerini destekler: " +
                      "BES, EPES, T, C, X, XL, A",
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Doğrulama başarılı",
                content = @Content(schema = @Schema(implementation = VerificationResult.class))
            )
        }
    )
    public ResponseEntity<VerificationResult> verifyCAdES(
            @RequestParam("signedDocument") MultipartFile signedDocument,
            @RequestParam(value = "originalDocument", required = false) MultipartFile originalDocument,
            @RequestParam(value = "level", defaultValue = "SIMPLE") String level) {

        logger.info("CAdES verification request");
        return verifySignature(signedDocument, originalDocument, level);
    }

    /**
     * Verification level parser
     */
    private VerificationLevel parseVerificationLevel(String level) {
        try {
            return VerificationLevel.valueOf(level.toUpperCase());
        } catch (Exception e) {
            logger.warn("Invalid verification level: {}, using SIMPLE", level);
            return VerificationLevel.SIMPLE;
        }
    }
}

