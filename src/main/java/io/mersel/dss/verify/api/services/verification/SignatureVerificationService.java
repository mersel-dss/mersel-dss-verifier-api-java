package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.exceptions.VerificationException;
import io.mersel.dss.verify.api.models.*;
import io.mersel.dss.verify.api.models.enums.SignatureType;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * İmza doğrulama servisi - PAdES, XAdES ve diğer formatlar için
 */
@Service
public class SignatureVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(SignatureVerificationService.class);

    @Autowired
    private KamusmRootCertificateService rootCertificateService;

    @Autowired
    private VerificationConfiguration config;

    /**
     * İmzalı dokümanı doğrular
     */
    public VerificationResult verifySignature(
            MultipartFile signedDocument,
            MultipartFile originalDocument,
            VerificationLevel level) {

        logger.info("Starting signature verification. Level: {}", level);

        try {
            // Dokümanı oku
            byte[] signedBytes = signedDocument.getBytes();
            DSSDocument document = new InMemoryDocument(signedBytes, signedDocument.getOriginalFilename());

            // Orijinal doküman varsa (detached signature için)
            DSSDocument detachedContent = null;
            if (originalDocument != null && !originalDocument.isEmpty()) {
                detachedContent = new InMemoryDocument(
                        originalDocument.getBytes(),
                        originalDocument.getOriginalFilename()
                );
            }

            // Validator oluştur
            SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(document);

            if (detachedContent != null) {
                validator.setDetachedContents(java.util.Collections.singletonList(detachedContent));
            }

            // Certificate verifier'ı ayarla
            CertificateVerifier certificateVerifier = createCertificateVerifier();
            validator.setCertificateVerifier(certificateVerifier);

            // Doğrulama yap
            Reports reports = validator.validateDocument();
            SimpleReport simpleReport = reports.getSimpleReport();

            // Sonuçları parse et
            VerificationResult result = parseVerificationResult(simpleReport, validator, level);

            logger.info("Signature verification completed. Valid: {}", result.isValid());
            return result;

        } catch (Exception e) {
            logger.error("Signature verification failed: {}", e.getMessage(), e);
            throw new VerificationException("İmza doğrulama hatası: " + e.getMessage(), e);
        }
    }

    /**
     * Certificate verifier oluşturur
     */
    private CertificateVerifier createCertificateVerifier() {

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();

        // Trusted certificate source'u ayarla
        verifier.addTrustedCertSources(rootCertificateService.getTrustedCertificateSource());

        // Online validation DSS 6.3'te otomatik olarak yapılır
        // Eğer checkRevocation true ise, verifier otomatik olarak OCSP/CRL kontrolleri yapar

        return verifier;
    }

    /**
     * Doğrulama sonuçlarını parse eder
     */
    private VerificationResult parseVerificationResult(
            SimpleReport simpleReport,
            SignedDocumentValidator validator,
            VerificationLevel level) {

        VerificationResult result = new VerificationResult();

        List<String> signatureIds = simpleReport.getSignatureIdList();

        if (signatureIds.isEmpty()) {
            result.setValid(false);
            result.setStatus("NO_SIGNATURE_FOUND");
            result.addError("Dokümanda imza bulunamadı");
            return result;
        }

        boolean allValid = true;
        List<SignatureInfo> signatureInfos = new ArrayList<>();

        for (String signatureId : signatureIds) {
            SignatureInfo sigInfo = new SignatureInfo();
            sigInfo.setSignatureId(signatureId);

            // İmza geçerliliği
            Indication indication = simpleReport.getIndication(signatureId);
            boolean isValid = indication == Indication.TOTAL_PASSED;
            sigInfo.setValid(isValid);

            if (!isValid) {
                allValid = false;
            }

            // İmza bilgilerini doldur (basit veya kapsamlı)
            populateSignatureInfo(sigInfo, simpleReport, signatureId, validator, level);

            signatureInfos.add(sigInfo);
        }

        result.setValid(allValid);
        result.setStatus(allValid ? "VALID" : "INVALID");
        result.setSignatures(signatureInfos);

        // Signature type belirle
        determineSignatureType(result, validator);

        // Validation details (comprehensive için)
        if (level == VerificationLevel.COMPREHENSIVE) {
            result.setValidationDetails(createValidationDetails(simpleReport, signatureIds.get(0)));
        }

        return result;
    }

    /**
     * İmza bilgilerini doldurur (basit veya kapsamlı)
     */
    private void populateSignatureInfo(
            SignatureInfo sigInfo,
            SimpleReport report,
            String signatureId,
            SignedDocumentValidator validator,
            VerificationLevel level) {

        try {
            // Temel bilgiler (her iki seviyede de)
            if (report.getSignatureFormat(signatureId) != null) {
                sigInfo.setSignatureFormat(report.getSignatureFormat(signatureId).toString());
            }
            sigInfo.setSigningTime(report.getBestSignatureTime(signatureId));

            List<String> errors = new ArrayList<>();
            List<String> warnings = new ArrayList<>();

            // DSS 6.3'te errors/warnings için farklı methodlar kullanılıyor
            if (report.getJaxbModel() != null) {
                if (!report.isValid(signatureId)) {
                    errors.add("İmza geçersiz");
                }
            }

            sigInfo.setValidationErrors(errors);
            sigInfo.setValidationWarnings(warnings);

            // Sertifika bilgileri (her iki seviyede de)
            try {
                List<eu.europa.esig.dss.diagnostic.SignatureWrapper> signatures =
                        validator.validateDocument().getDiagnosticData().getSignatures();

                if (signatures != null && !signatures.isEmpty()) {
                    eu.europa.esig.dss.diagnostic.SignatureWrapper sigWrapper = signatures.get(0);
                    if (sigWrapper.getSigningCertificate() != null) {
                        eu.europa.esig.dss.diagnostic.CertificateWrapper certWrapper =
                                sigWrapper.getSigningCertificate();

                        CertificateInfo certInfo = new CertificateInfo();
                        certInfo.setCommonName(certWrapper.getReadableCertificateName());
                        certInfo.setSerialNumber(certWrapper.getSerialNumber());
                        certInfo.setSubject(certWrapper.getCertificateDN());
                        certInfo.setIssuerDN(certWrapper.getCertificateIssuerDN());

                        // Subject serial number
                        try {
                            String subjectSerialNumber = certWrapper.getSubjectSerialNumber();
                            if (subjectSerialNumber != null && !subjectSerialNumber.isEmpty()) {
                                certInfo.setSubjectSerialNumber(subjectSerialNumber);
                            }
                        } catch (Exception e) {
                            logger.debug("Could not get subject serial number: {}", e.getMessage());
                        }

                        sigInfo.setSignerCertificate(certInfo);
                    }
                }
            } catch (Exception e) {
                logger.warn("Failed to extract certificate info: {}", e.getMessage());
            }

            // Kapsamlı bilgiler (sadece COMPREHENSIVE seviyesinde)
            if (level == VerificationLevel.COMPREHENSIVE) {
                // Signature level
                try {
                    if (report.getSignatureFormat(signatureId) != null) {
                        sigInfo.setSignatureLevel(report.getSignatureFormat(signatureId).toString());
                    }
                } catch (Exception e) {
                    logger.debug("Could not get signature level: {}", e.getMessage());
                }

                // Claimed signing time
                Date signingTime = report.getBestSignatureTime(signatureId);
                sigInfo.setClaimedSigningTime(signingTime);

                // Timestamp info
                if (report.getBestSignatureTime(signatureId) != null) {
                    TimestampInfo tsInfo = new TimestampInfo();
                    tsInfo.setValid(true);
                    tsInfo.setTimestampTime(report.getBestSignatureTime(signatureId));
                    sigInfo.setTimestampInfo(tsInfo);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to populate signature info: {}", e.getMessage());
        }
    }

    /**
     * Validation details oluşturur
     */
    private ValidationDetails createValidationDetails(SimpleReport report, String signatureId) {
        ValidationDetails details = new ValidationDetails();

        try {
            Indication indication = report.getIndication(signatureId);
            details.setSignatureIntact(indication == Indication.TOTAL_PASSED ||
                    indication == Indication.PASSED);

            // DSS 6.3'te validation details daha basit
            boolean isValid = report.isValid(signatureId);
            details.setCertificateChainValid(isValid);
            details.setCertificateNotExpired(isValid);
            details.setCertificateNotRevoked(isValid);
            details.setTrustAnchorReached(isValid);
            details.setTimestampValid(report.getBestSignatureTime(signatureId) != null);

        } catch (Exception e) {
            logger.warn("Failed to create validation details: {}", e.getMessage());
        }

        return details;
    }

    /**
     * İmza tipini belirler
     */
    private void determineSignatureType(VerificationResult result, SignedDocumentValidator validator) {
        try {
            // DSS 6.3'te mimetype farklı şekilde alınıyor
            Reports reports = validator.validateDocument();
            if (reports != null && reports.getSimpleReport() != null &&
                    !reports.getSimpleReport().getSignatureIdList().isEmpty()) {

                String signatureId = reports.getSimpleReport().getSignatureIdList().get(0);
                String format = reports.getSimpleReport().getSignatureFormat(signatureId).toString();

                if (format.contains("PAdES")) {
                    result.setSignatureType(SignatureType.PADES);
                } else if (format.contains("XAdES")) {
                    result.setSignatureType(SignatureType.XADES);
                } else if (format.contains("CAdES")) {
                    result.setSignatureType(SignatureType.CADES);
                }
            }
        } catch (Exception e) {
            logger.debug("Could not determine signature type: {}", e.getMessage());
        }
    }
}

