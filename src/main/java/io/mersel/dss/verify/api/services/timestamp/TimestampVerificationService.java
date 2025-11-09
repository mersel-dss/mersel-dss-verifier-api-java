package io.mersel.dss.verify.api.services.timestamp;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.model.x509.CertificateToken;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.dtos.TimestampVerificationResponseDto;
import io.mersel.dss.verify.api.exceptions.TimestampException;
import io.mersel.dss.verify.api.models.CertificateInfo;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import io.mersel.dss.verify.api.services.util.CertificateInfoExtractor;
import org.bouncycastle.tsp.TimeStampResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;

/**
 * Zaman damgası doğrulama servisi
 */
@Service
public class TimestampVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(TimestampVerificationService.class);

    @Autowired
    private KamusmRootCertificateService rootCertificateService;

    @Autowired
    private VerificationConfiguration config;

    @Autowired
    private CertificateInfoExtractor certificateInfoExtractor;

    /**
     * Zaman damgasını doğrular
     */
    public TimestampVerificationResponseDto verifyTimestamp(
            MultipartFile timestampFile,
            MultipartFile originalDataFile,
            boolean validateCertificate) {

        logger.info("Starting timestamp verification");

        try {
            // Timestamp token'ı oku
            byte[] timestampBytes = timestampFile.getBytes();
            TimestampToken timestampToken = parseTimestampToken(timestampBytes);

            TimestampVerificationResponseDto response = new TimestampVerificationResponseDto();
            response.setTimestampTime(timestampToken.getGenerationTime());
            
            List<String> errors = new ArrayList<>();
            List<String> warnings = new ArrayList<>();

            // 1. Timestamp formatını kontrol et
            if (timestampToken == null) {
                errors.add("Geçersiz zaman damgası formatı");
                response.setValid(false);
                response.setStatus("INVALID_FORMAT");
                response.setErrors(errors);
                return response;
            }

            // 2. Timestamp'in bütünlüğünü kontrol et
            boolean tokenValid = verifyTimestampIntegrity(timestampToken, timestampBytes);
            if (!tokenValid) {
                errors.add("Zaman damgası bütünlüğü bozulmuş");
            }

            // 3. Orijinal veri varsa, message imprint'i doğrula
            if (originalDataFile != null && !originalDataFile.isEmpty()) {
                boolean imprintValid = verifyMessageImprint(timestampToken, originalDataFile.getBytes());
                if (!imprintValid) {
                    errors.add("Message imprint doğrulaması başarısız");
                } else {
                    logger.info("Message imprint validation successful");
                }
            }

            // 4. TSA sertifikasını doğrula
            if (validateCertificate && timestampToken.getCertificates() != null 
                    && !timestampToken.getCertificates().isEmpty()) {
                
                CertificateToken tsaCert = timestampToken.getCertificates().get(0);
                CertificateInfo certInfo = certificateInfoExtractor.extractCertificateInfo(tsaCert);
                response.setTsaCertificate(certInfo);
                response.setTsaName(tsaCert.getSubject().getPrettyPrintRFC2253());

                // Sertifika geçerlilik kontrolü
                Date now = new Date();
                if (now.before(tsaCert.getNotBefore()) || now.after(tsaCert.getNotAfter())) {
                    errors.add("TSA sertifikası geçerlilik süresi dışında");
                }

                // Güvenilir root kontrolü
                if (!isCertificateTrusted(tsaCert)) {
                    warnings.add("TSA sertifikası güvenilir bir root'a zincirlenemiyor");
                }
            }

            // 5. Digest algoritması bilgisi
            if (timestampToken.getArchiveTimestampType() != null) {
                response.setDigestAlgorithm(timestampToken.getArchiveTimestampType().name());
            }

            // 6. Message imprint'i Base64 olarak ekle
            if (timestampToken.getMessageImprint() != null) {
                response.setMessageImprint(
                    Base64.getEncoder().encodeToString(timestampToken.getMessageImprint().getValue())
                );
            }

            // Sonuç
            boolean isValid = errors.isEmpty();
            response.setValid(isValid);
            response.setStatus(isValid ? "VALID" : "INVALID");
            response.setErrors(errors);
            response.setWarnings(warnings);

            logger.info("Timestamp verification completed. Valid: {}", isValid);
            return response;

        } catch (Exception e) {
            logger.error("Timestamp verification failed: {}", e.getMessage(), e);
            throw new TimestampException("Zaman damgası doğrulama hatası: " + e.getMessage(), e);
        }
    }

    /**
     * Timestamp token'ı parse eder
     */
    private TimestampToken parseTimestampToken(byte[] timestampBytes) {
        try {
            DSSDocument timestampDoc = new InMemoryDocument(timestampBytes);
            return new TimestampToken(timestampBytes, null);
        } catch (Exception e) {
            logger.error("Failed to parse timestamp token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Timestamp bütünlüğünü doğrular
     */
    private boolean verifyTimestampIntegrity(TimestampToken token, byte[] timestampBytes) {
        try {
            TimeStampResponse response = new TimeStampResponse(timestampBytes);
            response.validate(null); // Basic validation
            return true;
        } catch (Exception e) {
            logger.error("Timestamp integrity check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Message imprint'i doğrular
     */
    private boolean verifyMessageImprint(TimestampToken token, byte[] originalData) {
        try {
            // DSS 6.3'te message imprint doğrulaması daha basit
            if (token.getMessageImprint() != null && token.getMessageImprint().getValue() != null) {
                byte[] expectedImprint = token.getMessageImprint().getValue();
                
                // Digest algoritmasını al - DSS 6.3'te farklı
                String digestAlg = "SHA-256"; // Default
                try {
                    if (token.getArchiveTimestampType() != null) {
                        digestAlg = token.getArchiveTimestampType().name().replace("_", "-");
                    }
                } catch (Exception ignored) {
                    // Varsayılan kullan
                }
                
                // Orijinal verinin hash'ini hesapla
                MessageDigest md = MessageDigest.getInstance(digestAlg);
                byte[] calculatedImprint = md.digest(originalData);
                
                // Karşılaştır
                return Arrays.equals(expectedImprint, calculatedImprint);
            }
            return false;
            
        } catch (Exception e) {
            logger.error("Message imprint verification failed: {}", e.getMessage());
            return false;
        }
    }


    /**
     * Sertifikanın güvenilir olup olmadığını kontrol eder
     */
    private boolean isCertificateTrusted(CertificateToken certificate) {
        try {
            return rootCertificateService.isTrusted(certificate);
        } catch (Exception e) {
            logger.error("Failed to check certificate trust: {}", e.getMessage());
            return false;
        }
    }
}

