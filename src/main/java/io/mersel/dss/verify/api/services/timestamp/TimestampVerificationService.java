package io.mersel.dss.verify.api.services.timestamp;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.CRLToken;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OCSPToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.model.x509.CertificateToken;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.dtos.TimestampVerificationResponseDto;
import io.mersel.dss.verify.api.exceptions.TimestampException;
import io.mersel.dss.verify.api.models.CertificateInfo;
import io.mersel.dss.verify.api.models.RevocationInfo;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import io.mersel.dss.verify.api.services.util.CertificateInfoExtractor;
import io.mersel.dss.verify.api.services.util.RevocationInfoExtractor;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
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

    @Autowired
    private RevocationInfoExtractor revocationInfoExtractor;

    /**
     * Caffeine cache + retry sarmali OCSP source. Optional ({@code required=false})
     * — {@code verification.online-validation-enabled=false} iken context'te
     * bulunmaz, basit timestamp dogrulamasi yine de calismaya devam eder
     * (revocation kontrolu sessizce atlanir).
     */
    @Autowired(required = false)
    private OCSPSource ocspSource;

    @Autowired(required = false)
    private CRLSource crlSource;

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
                
                List<CertificateToken> tsaChain = timestampToken.getCertificates();
                CertificateToken tsaCert = tsaChain.get(0);
                CertificateInfo certInfo = certificateInfoExtractor.extractCertificateInfo(tsaCert);
                response.setTsaCertificate(certInfo);
                response.setTsaName(tsaCert.getSubject().getPrettyPrintRFC2253());

                // Sertifika geçerlilik kontrolü
                Date now = new Date();
                if (now.before(tsaCert.getNotBefore()) || now.after(tsaCert.getNotAfter())) {
                    errors.add("TSA sertifikası geçerlilik süresi dışında");
                }

                // Güvenilir root kontrolü — birebir uyelik degil, zincir kurma.
                // (Detayli aciklama: KamusmRootCertificateService.isChainTrusted)
                boolean trusted = isCertificateTrusted(tsaCert, tsaChain);
                certInfo.setTrusted(trusted);
                if (!trusted) {
                    warnings.add("TSA sertifikası güvenilir bir root'a zincirlenemiyor");
                }

                // Revocation kontrolu — online validation acikken yapilir.
                // Ham TSA cert'i icin DSS DiagnosticData yok, dolayisiyla
                // OCSPSource/CRLSource'tan direkt token cekiyor ve
                // RevocationInfo'ya ceviriyoruz. Onceden bu adim eksik oldugu
                // icin tsaCertificate.revoked her zaman default false
                // gorunuyordu.
                if (config.isOnlineValidationEnabled()) {
                    enrichTsaRevocation(certInfo, tsaCert, tsaChain, warnings);
                }

                // Tum kontroller sonrasi TSA sertifikasinin nihai gecerliligi
                // (trusted + suresi gecerli + iptal edilmemis).
                certInfo.setValid(trusted && !certInfo.isExpired() && !certInfo.isRevoked());
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
     * Timestamp bütünlüğünü doğrular.
     *
     * <p>Ciplak {@code TimeStampToken} (.tsq/.tst) veya tam {@code TimeStampResponse}
     * (.tsr) girdisini destekler ve token'in gomulu TSA sertifikasi ile RFC 3161
     * imzasini gercekten dogrular. (Detayli aciklama: ayni adli metot —
     * {@code AdvancedTimestampVerificationService}.)
     */
    private boolean verifyTimestampIntegrity(TimestampToken token, byte[] timestampBytes) {
        TimeStampToken bcToken = extractBcTimeStampToken(timestampBytes);
        if (bcToken == null) {
            logger.error("Timestamp integrity check failed: token RFC 3161 olarak parse edilemedi");
            return false;
        }

        try {
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> signerCerts =
                    bcToken.getCertificates().getMatches(bcToken.getSID());
            if (signerCerts.isEmpty()) {
                logger.warn("Timestamp token imzaci (TSA) sertifikasini gomulu tasimiyor; "
                        + "imza butunlugu dogrulanamadi");
                return false;
            }

            X509CertificateHolder signerCert = signerCerts.iterator().next();
            SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(signerCert);

            bcToken.validate(verifier);
            return true;

        } catch (Exception e) {
            logger.error("Timestamp integrity check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Ham byte dizisinden BouncyCastle {@link TimeStampToken}'i elde eder.
     * Once ciplak CMS token, olmazsa tam {@code TimeStampResponse} olarak dener.
     */
    private TimeStampToken extractBcTimeStampToken(byte[] timestampBytes) {
        try {
            return new TimeStampToken(new CMSSignedData(timestampBytes));
        } catch (Exception bareTokenFailure) {
            logger.debug("Ciplak TimeStampToken parse edilemedi, TimeStampResponse deneniyor: {}",
                    bareTokenFailure.getMessage());
        }
        try {
            return new TimeStampResponse(timestampBytes).getTimeStampToken();
        } catch (Exception responseFailure) {
            logger.debug("TimeStampResponse parse de basarisiz: {}", responseFailure.getMessage());
            return null;
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
     * Sertifikanın güvenilir bir koke zincirlenebilir olup olmadığını kontrol eder.
     * Birebir uyelik yerine zincir kurma yapar — bkz.
     * {@link KamusmRootCertificateService#isChainTrusted(CertificateToken, List)}.
     */
    private boolean isCertificateTrusted(CertificateToken certificate, List<CertificateToken> chain) {
        try {
            return rootCertificateService.isChainTrusted(certificate, chain);
        } catch (Exception e) {
            logger.error("Failed to check certificate trust: {}", e.getMessage());
            return false;
        }
    }

    /**
     * TSA sertifikasi icin OCSP/CRL sorgulayip elde edilen token'i
     * {@link RevocationInfo}'ya cevirir ve {@code certInfo}'ya yansitir.
     *
     * <p>Bu basit ({@code TimestampVerificationService}) endpoint daha once
     * hic revocation kontrolu yapmiyordu — TSA cert'i REVOKED olsa bile
     * response'da {@code revoked: false} goruluyordu. Artik gercek durum
     * yansir. Online validation kapaliysa caller bu metodu zaten cagirmaz.
     *
     * <p>OCSP/CRL kaynaklari ({@code @Autowired(required=false)}) context'te
     * yoksa (offline mod) sessizce atlanir, basit dogrulama akisi
     * bozulmadan devam eder.
     */
    private void enrichTsaRevocation(CertificateInfo certInfo,
                                     CertificateToken tsaCert,
                                     List<CertificateToken> tsaChain,
                                     List<String> warnings) {
        if (ocspSource == null && crlSource == null) {
            return;
        }

        CertificateToken issuer = resolveIssuerCertificate(tsaCert, tsaChain);
        if (issuer == null) {
            warnings.add("TSA sertifikasinin issuer'i timestamp icerisinde bulunamadi; revocation atlandi");
            return;
        }

        RevocationInfo revocationInfo = null;

        // 1) OCSP
        if (ocspSource != null) {
            try {
                OCSPToken ocsp = ocspSource.getRevocationToken(tsaCert, issuer);
                if (ocsp != null && ocsp.getStatus() != null) {
                    revocationInfo = revocationInfoExtractor.fromToken(ocsp);
                    if (ocsp.getStatus() != CertificateStatus.UNKNOWN) {
                        AdvancedTimestampVerificationService.applyRevocationToCertInfo(certInfo, revocationInfo);
                        return;
                    }
                }
            } catch (RuntimeException e) {
                logger.warn("TSA OCSP check threw (simple endpoint): {}; falling back to CRL", e.getMessage());
            }
        }

        // 2) CRL (OCSP yoksa veya UNKNOWN dondurduyse)
        if (crlSource != null) {
            try {
                CRLToken crl = crlSource.getRevocationToken(tsaCert, issuer);
                if (crl != null && crl.getStatus() != null) {
                    revocationInfo = revocationInfoExtractor.fromToken(crl);
                }
            } catch (RuntimeException e) {
                logger.warn("TSA CRL check threw (simple endpoint): {}", e.getMessage());
            }
        }

        AdvancedTimestampVerificationService.applyRevocationToCertInfo(certInfo, revocationInfo);
    }

    /**
     * Timestamp token icinde gelen sertifika listesinde TSA sertifikasinin
     * issuer'ini bulur. Issuer DN eslestirmesi ile bulunur — bazi TSA'lar
     * tam zincir gondermez, sira garanti degildir.
     */
    private CertificateToken findIssuerCertificate(CertificateToken tsaCert, List<CertificateToken> chain) {
        if (tsaCert == null || chain == null || chain.isEmpty()) {
            return null;
        }
        String issuerDn = tsaCert.getIssuer().getCanonical();
        for (CertificateToken candidate : chain) {
            if (candidate == tsaCert) {
                continue;
            }
            if (issuerDn != null && issuerDn.equals(candidate.getSubject().getCanonical())) {
                return candidate;
            }
        }
        return null;
    }

    /**
     * TSA sertifikasinin issuer'ini once token icinden, bulunamazsa guven
     * deposundan (KamuSM kokleri) cozer. KamuSM TSA token'lari genelde yalnizca
     * leaf tasidigi icin issuer cogu zaman ancak guven deposunda bulunur.
     */
    private CertificateToken resolveIssuerCertificate(CertificateToken tsaCert, List<CertificateToken> chain) {
        CertificateToken issuer = findIssuerCertificate(tsaCert, chain);
        if (issuer != null) {
            return issuer;
        }
        try {
            CommonTrustedCertificateSource trustedSource = rootCertificateService.getTrustedCertificateSource();
            if (trustedSource != null) {
                for (CertificateToken candidate : trustedSource.getBySubject(tsaCert.getIssuer())) {
                    if (tsaCert.isSignedBy(candidate)) {
                        return candidate;
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Issuer lookup from trusted source failed: {}", e.getMessage());
        }
        return null;
    }
}

