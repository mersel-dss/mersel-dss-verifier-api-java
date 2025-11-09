package io.mersel.dss.verify.api.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Health check controller
 */
@RestController
@RequestMapping("/api/v1")
@Tag(name = "Health", description = "Servis sağlık durumu kontrolü")
public class HealthController {

    @Value("${spring.application.name}")
    private String applicationName;

    @Value("${info.app.version:unknown}")
    private String version;

    @GetMapping("/health")
    @Operation(
        summary = "Sağlık kontrolü",
        description = "Servisin sağlık durumunu kontrol eder"
    )
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("application", applicationName);
        health.put("version", version);
        health.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(health);
    }

    @GetMapping("/info")
    @Operation(
        summary = "Servis bilgisi",
        description = "Servis hakkında genel bilgileri döner"
    )
    public ResponseEntity<Map<String, Object>> info() {
        Map<String, Object> info = new HashMap<>();
        info.put("name", applicationName);
        info.put("version", version);
        info.put("description", "Mersel DSS Verify API - Dijital İmza Doğrulama Servisi");
        info.put("features", new String[]{
            "PAdES Verification",
            "XAdES Verification",
            "Timestamp Verification",
            "Certificate Chain Validation",
            "OCSP/CRL Revocation Check"
        });
        
        return ResponseEntity.ok(info);
    }
}

