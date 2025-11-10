package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;

/**
 * DSS Validation Report Logger
 * Detaylı DSS validation raporlarını loglar
 */
public class ValidationReportLogger {

    private static final Logger logger = LoggerFactory.getLogger(ValidationReportLogger.class);

    public static void logDetailedReport(Reports reports, String filename) {
        logger.info("╔════════════════════════════════════════════════════════════════════");
        logger.info("║ DSS VALIDATION REPORT - {}", filename);
        logger.info("╠════════════════════════════════════════════════════════════════════");
        
        SimpleReport simpleReport = reports.getSimpleReport();
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        
        // 1. SIGNATURE SUMMARY
        logSignatureSummary(simpleReport);
        
        // 2. CERTIFICATE CHAIN
        logCertificateChain(diagnosticData);
        
        // 3. TRUSTED CERTIFICATES
        logTrustedCertificates(diagnosticData);
        
        // 4. VALIDATION DETAILS
        logValidationDetails(simpleReport);
        
        // 5. DIAGNOSTIC DATA
        logDiagnosticData(diagnosticData);
        
        // 6. DETAILED REPORT - NEDEN BAŞARISIZ?
        logDetailedReportConclusion(reports);
        
        logger.info("╚════════════════════════════════════════════════════════════════════");
    }
    
    private static void logDetailedReportConclusion(Reports reports) {
        logger.info("║");
        logger.info("║ 6. DETAILED REPORT ANALYSIS");
        logger.info("║ ────────────────────────────");
        
        try {
            eu.europa.esig.dss.detailedreport.DetailedReport detailedReport = reports.getDetailedReport();
            List<String> signatureIds = reports.getSimpleReport().getSignatureIdList();
            
            for (String sigId : signatureIds) {
                logger.info("║");
                logger.info("║   Signature: {}", sigId);
                
                // Basic Building Blocks
                logger.info("║   Basic Building Blocks:");
                
                // XCV (X.509 Certificate Validation)
                try {
                    eu.europa.esig.dss.enumerations.Indication xcvResult = 
                            detailedReport.getBasicBuildingBlocksIndication(sigId);
                    eu.europa.esig.dss.enumerations.SubIndication xcvSubResult = 
                            detailedReport.getBasicBuildingBlocksSubIndication(sigId);
                    
                    logger.info("║   ├─ BBB Result: {} / {}", xcvResult, xcvSubResult);
                } catch (Exception e) {
                    logger.debug("Could not get BBB: {}", e.getMessage());
                }
                
                // Conclusion
                eu.europa.esig.dss.enumerations.Indication conclusion = 
                        detailedReport.getFinalIndication(sigId);
                eu.europa.esig.dss.enumerations.SubIndication subConclusion = 
                        detailedReport.getFinalSubIndication(sigId);
                
                logger.info("║   └─ Final: {} / {}", conclusion, subConclusion);
                
                // Errors ve Warnings - DSS 6.x'te List<Message> döner
                try {
                    List<eu.europa.esig.dss.jaxb.object.Message> errors = 
                            detailedReport.getAdESValidationErrors(sigId);
                    if (errors != null && !errors.isEmpty()) {
                        logger.info("║");
                        logger.info("║   ❌ AdES Validation Errors:");
                        for (eu.europa.esig.dss.jaxb.object.Message error : errors) {
                            logger.info("║      - {}", error.getValue());
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Could not get errors: {}", e.getMessage());
                }
                
                try {
                    List<eu.europa.esig.dss.jaxb.object.Message> warnings = 
                            detailedReport.getAdESValidationWarnings(sigId);
                    if (warnings != null && !warnings.isEmpty()) {
                        logger.info("║");
                        logger.info("║   ⚠️  AdES Validation Warnings:");
                        for (eu.europa.esig.dss.jaxb.object.Message warning : warnings) {
                            logger.info("║      - {}", warning.getValue());
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Could not get warnings: {}", e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.error("║   ❌ Failed to get detailed report: {}", e.getMessage());
        }
    }

    private static void logSignatureSummary(SimpleReport simpleReport) {
        logger.info("║");
        logger.info("║ 1. SIGNATURE SUMMARY");
        logger.info("║ ────────────────────");
        
        List<String> signatureIds = simpleReport.getSignatureIdList();
        logger.info("║   Signature Count: {}", signatureIds.size());
        
        for (String sigId : signatureIds) {
            Indication indication = simpleReport.getIndication(sigId);
            SubIndication subIndication = simpleReport.getSubIndication(sigId);
            
            logger.info("║");
            logger.info("║   Signature ID: {}", sigId);
            logger.info("║   ├─ Valid: {}", simpleReport.isValid(sigId));
            logger.info("║   ├─ Indication: {}", indication);
            logger.info("║   ├─ SubIndication: {}", subIndication);
            logger.info("║   ├─ Format: {}", simpleReport.getSignatureFormat(sigId));
            logger.info("║   └─ Signing Time: {}", simpleReport.getBestSignatureTime(sigId));
        }
    }

    private static void logCertificateChain(DiagnosticData diagnosticData) {
        logger.info("║");
        logger.info("║ 2. CERTIFICATE CHAIN");
        logger.info("║ ────────────────────");
        
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        if (signatures == null || signatures.isEmpty()) {
            logger.info("║   ⚠️  No signatures found!");
            return;
        }
        
        for (SignatureWrapper signature : signatures) {
            logger.info("║   Signature: {}", signature.getId());
            
            CertificateWrapper signingCert = signature.getSigningCertificate();
            if (signingCert == null) {
                logger.info("║   ❌ No signing certificate found!");
                continue;
            }
            
            logger.info("║");
            logger.info("║   Certificate Chain:");
            
            // Signing certificate (end-entity)
            logCertificate(signingCert, "END-ENTITY", 1);
            
            // Chain'i takip et
            int level = 2;
            CertificateWrapper current = signingCert;
            Set<String> visited = new java.util.HashSet<>();
            visited.add(current.getId());
            
            while (current != null && level <= 10) {
                CertificateWrapper issuer = current.getSigningCertificate();
                
                if (issuer == null) {
                    logger.info("║   │");
                    logger.info("║   └─ ❌ CHAIN BROKEN: Issuer not found!");
                    logger.info("║       Expected Issuer: {}", current.getCertificateIssuerDN());
                    break;
                }
                
                if (visited.contains(issuer.getId())) {
                    logger.info("║   └─ ✅ CHAIN COMPLETE (self-signed root)");
                    break;
                }
                
                visited.add(issuer.getId());
                
                boolean isSelfSigned = issuer.isSelfSigned();
                String certType = isSelfSigned ? "ROOT" : "INTERMEDIATE";
                
                logCertificate(issuer, certType, level);
                
                if (isSelfSigned) {
                    logger.info("║   └─ ✅ CHAIN COMPLETE");
                    break;
                }
                
                current = issuer;
                level++;
            }
            
            if (level > 10) {
                logger.info("║   └─ ⚠️  Chain too deep (max 10 levels)");
            }
        }
    }

    private static void logCertificate(CertificateWrapper cert, String type, int level) {
        String prefix = level == 1 ? "║   ┌─" : (level == 2 ? "║   ├─" : "║   │  ├─");
        
        logger.info("║   │");
        logger.info("{}【{}】", prefix, type);
        logger.info("║   │  │  Subject: {}", cert.getCertificateDN());
        logger.info("║   │  │  Issuer:  {}", cert.getCertificateIssuerDN());
        logger.info("║   │  │  Serial:  {}", cert.getSerialNumber());
        logger.info("║   │  │  Trusted: {}", cert.isTrusted());
        logger.info("║   │  │  Self-Signed: {}", cert.isSelfSigned());
        logger.info("║   │  │  Valid: {} to {}", 
                cert.getNotBefore(), cert.getNotAfter());
        
        // AIA URLs - DSS 6.x'te farklı API
        try {
            if (cert.getCertificateExtensions() != null) {
                logger.info("║   │  │  Extensions: {} extensions found", 
                        cert.getCertificateExtensions().size());
            }
        } catch (Exception e) {
            // Ignore
        }
    }

    private static void logTrustedCertificates(DiagnosticData diagnosticData) {
        logger.info("║");
        logger.info("║ 3. TRUSTED & USED CERTIFICATES");
        logger.info("║ ───────────────────────────────");
        
        List<CertificateWrapper> allCerts = diagnosticData.getUsedCertificates();
        logger.info("║   Total Used Certificates: {}", allCerts.size());
        
        int trustedCount = 0;
        int untrustedCount = 0;
        
        for (CertificateWrapper cert : allCerts) {
            if (cert.isTrusted()) {
                trustedCount++;
                logger.info("║   ✅ TRUSTED: {}", cert.getReadableCertificateName());
            } else {
                untrustedCount++;
                logger.info("║   ❌ NOT TRUSTED: {}", cert.getReadableCertificateName());
            }
        }
        
        logger.info("║   Summary: {} trusted, {} untrusted", trustedCount, untrustedCount);
    }

    private static void logValidationDetails(SimpleReport simpleReport) {
        logger.info("║");
        logger.info("║ 4. VALIDATION DETAILS");
        logger.info("║ ─────────────────────");
        
        List<String> signatureIds = simpleReport.getSignatureIdList();
        for (String sigId : signatureIds) {
            logger.info("║");
            logger.info("║   Signature: {}", sigId);
            
            Indication indication = simpleReport.getIndication(sigId);
            SubIndication subIndication = simpleReport.getSubIndication(sigId);
            
            logger.info("║   ├─ Indication: {}", indication);
            logger.info("║   ├─ SubIndication: {}", subIndication);
            logger.info("║   └─ Qualification: {}", simpleReport.getSignatureQualification(sigId));
        }
    }

    private static void logDiagnosticData(DiagnosticData diagnosticData) {
        logger.info("║");
        logger.info("║ 5. DIAGNOSTIC DATA");
        logger.info("║ ──────────────────");
        
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        if (signatures == null || signatures.isEmpty()) {
            logger.info("║   ⚠️  No signatures in diagnostic data");
            return;
        }
        
        for (SignatureWrapper sig : signatures) {
            logger.info("║");
            logger.info("║   Signature: {}", sig.getId());
            logger.info("║   ├─ Signature Valid: {}", sig.isSignatureIntact());
            logger.info("║   ├─ Signature Value: {}", sig.getSignatureValue() != null ? 
                    "Present" : "N/A");
            
            // Certificate chain
            logger.info("║   └─ Certificate Chain:");
            if (sig.getCertificateChain() != null && !sig.getCertificateChain().isEmpty()) {
                logger.info("║        Chain Length: {}", sig.getCertificateChain().size());
                for (CertificateWrapper cert : sig.getCertificateChain()) {
                    logger.info("║        - {} (Trusted: {})", 
                            cert.getReadableCertificateName(), cert.isTrusted());
                }
            } else {
                logger.info("║        ❌ No certificate chain found in signature!");
            }
        }
        
        // All certificates
        logger.info("║");
        logger.info("║   ALL CERTIFICATES IN VALIDATION:");
        List<CertificateWrapper> allCerts = diagnosticData.getUsedCertificates();
        logger.info("║   Total: {}", allCerts.size());
        for (CertificateWrapper cert : allCerts) {
            logger.info("║   - {} (Trusted: {}, Self-Signed: {})", 
                    cert.getReadableCertificateName(), 
                    cert.isTrusted(),
                    cert.isSelfSigned());
        }
    }
}

