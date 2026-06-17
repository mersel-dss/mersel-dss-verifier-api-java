package io.mersel.dss.verify.api.services.timestamp;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.DSSUtils;
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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;

/**
 * Gelişmiş zaman damgası doğrulama servisi
 * - RFC 3161 uyumlu timestamp doğrulaması
 * - TSA sertifika zinciri doğrulaması
 * - OCSP/CRL ile revocation kontrolü
 * - Message imprint doğrulaması
 */
@Service
public class AdvancedTimestampVerificationService {

    private static final Logger logger = LoggerFactory.getLogger(AdvancedTimestampVerificationService.class);

    @Autowired
    private KamusmRootCertificateService rootCertificateService;

    @Autowired
    private VerificationConfiguration config;

    @Autowired
    private CertificateInfoExtractor certificateInfoExtractor;

    @Autowired
    private RevocationInfoExtractor revocationInfoExtractor;

    @Autowired(required = false)
    private io.mersel.dss.verify.api.metrics.VerificationMetrics verificationMetrics;

    /**
     * Cache + logging sarmalli OCSP source.
     * {@link io.mersel.dss.verify.api.config.RevocationServicesConfiguration}'da
     * <code>verification.online-validation-enabled=true</code> iken yaratilir;
     * kapali iken context'te yoktur, {@code required=false} ile graceful
     * inject ediliyor.
     */
    @Autowired(required = false)
    private OCSPSource ocspSource;

    /**
     * Cache + logging sarmalli CRL source. {@link #ocspSource} ile ayni
     * yasam dongusu.
     */
    @Autowired(required = false)
    private CRLSource crlSource;

    /**
     * Zaman damgasını doğrular
     * @param timestampFile Timestamp dosyası (.tsr)
     * @param originalDataFile Orijinal veri (opsiyonel)
     * @param validateCertificate Sertifika doğrulaması yapılsın mı
     * @return Doğrulama sonucu
     */
    public TimestampVerificationResponseDto verifyTimestamp(
            MultipartFile timestampFile,
            MultipartFile originalDataFile,
            boolean validateCertificate) {

        logger.info("Starting advanced timestamp verification. ValidateCert: {}", validateCertificate);

        final long tsStartNanos = System.nanoTime();

        try {
            // Timestamp token'ı oku
            byte[] timestampBytes = timestampFile.getBytes();
            TimestampToken timestampToken = parseTimestampToken(timestampBytes);

            TimestampVerificationResponseDto response = new TimestampVerificationResponseDto();
            List<String> errors = new ArrayList<>();
            List<String> warnings = new ArrayList<>();

            // 1. Timestamp formatını kontrol et
            if (timestampToken == null) {
                errors.add("Geçersiz zaman damgası formatı - RFC 3161 uyumlu değil");
                response.setValid(false);
                response.setStatus("INVALID_FORMAT");
                response.setErrors(errors);
                if (verificationMetrics != null) {
                    verificationMetrics.recordTimestamp("invalid_format", System.nanoTime() - tsStartNanos);
                }
                return response;
            }

            // Timestamp zamanını ayarla
            response.setTimestampTime(timestampToken.getGenerationTime());
            logger.info("Timestamp generation time: {}", timestampToken.getGenerationTime());

            // 2. Timestamp'in bütünlüğünü kontrol et (RFC 3161)
            boolean tokenValid = verifyTimestampIntegrity(timestampToken, timestampBytes);
            if (!tokenValid) {
                errors.add("Zaman damgası bütünlüğü bozulmuş - imza doğrulaması başarısız");
            }

            // 3. Message imprint doğrulaması
            if (originalDataFile != null && !originalDataFile.isEmpty()) {
                MessageImprintResult imprintResult = verifyMessageImprint(
                        timestampToken, 
                        originalDataFile.getBytes()
                );
                
                if (!imprintResult.isValid()) {
                    errors.add("Message imprint doğrulaması başarısız: " + imprintResult.getError());
                } else {
                    logger.info("Message imprint validation successful");
                }
                
                // Digest algorithm bilgisini ekle
                response.setDigestAlgorithm(imprintResult.getDigestAlgorithm());
            }

            // 4. Message imprint'i Base64 olarak ekle
            if (timestampToken.getMessageImprint() != null) {
                response.setMessageImprint(
                    Base64.getEncoder().encodeToString(timestampToken.getMessageImprint().getValue())
                );
            }

            // 5. TSA sertifikası ve zinciri doğrulaması
            if (validateCertificate) {
                CertificateValidationResult certResult = validateTsaCertificateChain(timestampToken);
                
                if (certResult.getCertificateInfo() != null) {
                    response.setTsaCertificate(certResult.getCertificateInfo());
                    response.setTsaName(certResult.getCertificateInfo().getCommonName());
                }
                
                errors.addAll(certResult.getErrors());
                warnings.addAll(certResult.getWarnings());
            }

            // 6. Timestamp serial number - DSS 6.3'te farklı API
            try {
                // Serial number extraction için alternatif yöntem
                logger.debug("Timestamp token processed successfully");
            } catch (Exception e) {
                logger.debug("Could not extract serial number: {}", e.getMessage());
            }

            // Sonuç
            boolean isValid = errors.isEmpty();
            response.setValid(isValid);
            response.setStatus(isValid ? "VALID" : "INVALID");
            response.setErrors(errors);
            response.setWarnings(warnings);

            logger.info("Advanced timestamp verification completed. Valid: {}", isValid);
            if (verificationMetrics != null) {
                verificationMetrics.recordTimestamp(isValid ? "valid" : "invalid",
                        System.nanoTime() - tsStartNanos);
            }
            return response;

        } catch (Exception e) {
            logger.error("Advanced timestamp verification failed: {}", e.getMessage(), e);
            if (verificationMetrics != null) {
                verificationMetrics.recordTimestamp("error", System.nanoTime() - tsStartNanos);
            }
            throw new TimestampException("Zaman damgası doğrulama hatası: " + e.getMessage(), e);
        }
    }

    /**
     * Timestamp token'ı parse eder
     */
    private TimestampToken parseTimestampToken(byte[] timestampBytes) {
        try {
            return new TimestampToken(timestampBytes, null);
        } catch (Exception e) {
            logger.error("Failed to parse timestamp token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Timestamp bütünlüğünü doğrular (RFC 3161 signature validation).
     *
     * <p><strong>Onceki hata:</strong> {@code new TimeStampResponse(bytes)} her
     * girdinin tam bir {@code TimeStampResp} (PKIStatusInfo + token) oldugunu
     * varsayiyordu. Oysa agent'in (ve cogu KamuSM aracinin) urettigi ciktilar
     * <em>ciplak</em> {@code TimeStampToken} (CMS SignedData) olabiliyor.
     * Bu durumda kurucu ASN.1 parse hatasiyla patlayip {@code false} donuyor,
     * boylece gecerli bir timestamp bile "butunlugu bozulmus" hatasi aliyordu.
     *
     * <p><strong>Yeni davranis:</strong> Once ciplak token, olmazsa tam response
     * olarak parse edip {@code TimeStampToken}'i elde ediyoruz; ardindan token'in
     * <em>kendi icine gomulu</em> TSA sertifikasi ile imzayi gercekten dogruluyoruz.
     * Bu, hem RFC 3161 imza butunlugunu dogrular hem de iki cikti bicimini de
     * (.tsq/.tst ciplak token ve .tsr response) destekler.
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

            // TSTInfo uzerindeki TSA imzasini dogrular — basarisizsa exception firlatir.
            bcToken.validate(verifier);
            return true;

        } catch (Exception e) {
            logger.error("Timestamp integrity check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Ham byte dizisinden BouncyCastle {@link TimeStampToken}'i elde eder.
     * Once ciplak CMS {@code TimeStampToken} (.tsq/.tst), olmazsa tam
     * {@code TimeStampResponse} (.tsr) olarak dener.
     */
    private TimeStampToken extractBcTimeStampToken(byte[] timestampBytes) {
        try {
            return new TimeStampToken(new CMSSignedData(timestampBytes));
        } catch (Exception bareTokenFailure) {
            logger.debug("Ciplak TimeStampToken parse edilemedi, TimeStampResponse deneniyor: {}",
                    bareTokenFailure.getMessage());
        }
        try {
            TimeStampResponse response = new TimeStampResponse(timestampBytes);
            return response.getTimeStampToken();
        } catch (Exception responseFailure) {
            logger.debug("TimeStampResponse parse de basarisiz: {}", responseFailure.getMessage());
            return null;
        }
    }

    /**
     * Message imprint'i doğrular
     */
    private MessageImprintResult verifyMessageImprint(TimestampToken token, byte[] originalData) {
        MessageImprintResult result = new MessageImprintResult();
        
        try {
            if (token.getMessageImprint() == null || token.getMessageImprint().getValue() == null) {
                result.setValid(false);
                result.setError("Timestamp'te message imprint bulunamadı");
                return result;
            }

            byte[] expectedImprint = token.getMessageImprint().getValue();
            
            // Digest algoritmasını belirle
            DigestAlgorithm digestAlgorithm = token.getMessageImprint().getAlgorithm();
            String digestAlgName = digestAlgorithm != null ? digestAlgorithm.getName() : "SHA-256";
            result.setDigestAlgorithm(digestAlgName);
            
            logger.info("Using digest algorithm: {}", digestAlgName);
            
            // Orijinal verinin hash'ini hesapla
            byte[] calculatedImprint = DSSUtils.digest(digestAlgorithm, originalData);
            
            // Karşılaştır
            boolean isValid = Arrays.equals(expectedImprint, calculatedImprint);
            result.setValid(isValid);
            
            if (!isValid) {
                result.setError("Hesaplanan hash ile timestamp hash'i eşleşmiyor");
                logger.warn("Message imprint mismatch. Expected: {}, Calculated: {}",
                        Base64.getEncoder().encodeToString(expectedImprint),
                        Base64.getEncoder().encodeToString(calculatedImprint));
            }
            
        } catch (Exception e) {
            logger.error("Message imprint verification failed: {}", e.getMessage());
            result.setValid(false);
            result.setError("Message imprint doğrulama hatası: " + e.getMessage());
        }
        
        return result;
    }

    /**
     * TSA sertifikasını ve zincirini doğrular
     */
    private CertificateValidationResult validateTsaCertificateChain(TimestampToken token) {
        CertificateValidationResult result = new CertificateValidationResult();
        List<String> errors = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        try {
            // TSA sertifikasını al
            List<CertificateToken> certificates = token.getCertificates();
            if (certificates == null || certificates.isEmpty()) {
                errors.add("TSA sertifikası bulunamadı");
                result.setErrors(errors);
                return result;
            }

            CertificateToken tsaCert = certificates.get(0);
            CertificateInfo certInfo = certificateInfoExtractor.extractCertificateInfo(tsaCert);
            result.setCertificateInfo(certInfo);

            logger.info("TSA Certificate: {}", tsaCert.getSubject().getPrettyPrintRFC2253());

            // 1. Sertifika geçerlilik süresi kontrolü
            Date now = new Date();
            if (now.before(tsaCert.getNotBefore())) {
                errors.add("TSA sertifikası henüz geçerli değil");
            }
            if (now.after(tsaCert.getNotAfter())) {
                errors.add("TSA sertifikasının geçerlilik süresi dolmuş");
            }

            // 2. Extended Key Usage kontrolü (timeStamping)
            boolean hasTimestampingEKU = false;
            try {
                X509Certificate x509Cert = tsaCert.getCertificate();
                if (x509Cert.getExtendedKeyUsage() != null) {
                    // 1.3.6.1.5.5.7.3.8 = id-kp-timeStamping
                    hasTimestampingEKU = x509Cert.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.8");
                }
            } catch (Exception e) {
                logger.debug("Could not check EKU: {}", e.getMessage());
            }
            
            if (!hasTimestampingEKU) {
                warnings.add("TSA sertifikasında timeStamping Extended Key Usage eksik");
            }

            // 3. Trust anchor kontrolü
            // Token genelde yalnizca TSA leaf sertifikasini tasir; guven deposunda
            // ise KamuSM kok (ve ara) sertifikalari bulunur. Bu yuzden birebir
            // uyelik (`isTrusted`) yerine zincir kurma (`isChainTrusted`) kullaniyoruz:
            // leaf -> issuer(kok) zincirini token icindeki sertifikalar + guven
            // deposu uzerinden dogruluyoruz. XAdES tarafindaki DSS CertificateVerifier
            // davranisinin RFC 3161 timestamp karsiligi.
            boolean isTrusted = rootCertificateService.isChainTrusted(tsaCert, certificates);
            // Response'taki tsaCertificate.trusted alanini da senkron tut — aksi
            // halde dogrulama VALID donerken sertifika "trusted: false" gorunup
            // tutarsizlik yaratiyordu.
            certInfo.setTrusted(isTrusted);

            if (!isTrusted) {
                warnings.add("TSA sertifikası güvenilir bir root'a zincirlenemiyor");
            } else {
                logger.info("TSA certificate chains to a trusted KamuSM root");
            }

            // 4. Revocation kontrolü (online validation aktifse)
            if (config.isOnlineValidationEnabled()) {
                CertificateToken issuerCert = resolveIssuerCertificate(tsaCert, certificates);
                RevocationCheckResult revocationResult = checkRevocation(tsaCert, issuerCert);
                if (!revocationResult.isValid()) {
                    errors.add(revocationResult.getError());
                }

                // Revocation token elde edildiyse TSA cert info'ya yansit.
                // `CertificateInfoExtractor.extractCertificateInfo(CertificateToken)`
                // ham token'dan revocation alani turetemedigi icin
                // (DSS DiagnosticData yok) buraya kadar `revoked=false`
                // hardcoded geliyordu — REVOKED bir TSA cert'i bile response'da
                // "iptal degil" goruluyordu. Artik gercek durumu yansitiyoruz.
                applyRevocationToCertInfo(certInfo, revocationResult.getRevocationInfo());
                if (revocationResult.getWarning() != null) {
                    warnings.add(revocationResult.getWarning());
                }
            }

            // Tum kontroller sonrasi TSA sertifikasinin nihai gecerliligi:
            // guvenilir koke zincirleniyor + suresi gecerli + iptal edilmemis.
            // (Extractor bu alani set etmez; default false kaliyordu — trusted
            // iken bile "valid: false" gorunmesi tutarsizdi.)
            certInfo.setValid(isTrusted && !certInfo.isExpired() && !certInfo.isRevoked());

        } catch (Exception e) {
            logger.error("TSA certificate validation failed: {}", e.getMessage());
            errors.add("TSA sertifika doğrulama hatası: " + e.getMessage());
        }

        result.setErrors(errors);
        result.setWarnings(warnings);
        return result;
    }

    /**
     * TSA sertifikası için revocation kontrolü yapar.
     *
     * <p><strong>Strateji (TSA-spesifik)</strong>:</p>
     * <ol>
     *   <li>Once OCSP denenir (varsa). Cogu KamuSM TSA sertifikasinda OCSP
     *       endpoint'i tanimli degildir — bu normaldir, sessiz failover.</li>
     *   <li>OCSP yoksa veya yanit alinamazsa CRL denenir. KamuSM TSA'lar icin
     *       CRL ana iptal yayinlama mekanizmasidir.</li>
     *   <li>Iki kaynak da yoksa <em>WARN</em> donulur — TSA sertifikasi
     *       iptal edildi mi belirsiz; fakat <em>error</em> degildir, cunku
     *       imzaci akisinin aksine timestamp icin signer-strict policy
     *       zaten WARN seviyesinde toleranslidir.</li>
     *   <li>Iptal edilmis (REVOKED) cevap alinirsa <em>error</em> donulur —
     *       belirsizlik degil net ret.</li>
     * </ol>
     *
     * <p>Cache + INFO logging davranisi {@link OCSPSource}/{@link CRLSource}
     * bean'lerinin sarmalindan otomatik gelir.</p>
     */
    private RevocationCheckResult checkRevocation(CertificateToken certificate, CertificateToken issuer) {
        RevocationCheckResult result = new RevocationCheckResult();
        result.setValid(true);

        String subjectLabel = certificate.getSubject().getPrettyPrintRFC2253();

        if (issuer == null) {
            logger.warn("TSA revocation skipped: issuer certificate could not be located within the timestamp token "
                    + "for subject='{}'", subjectLabel);
            result.setWarning("TSA sertifikasinin issuer'i timestamp icerisinde bulunamadi; revocation kontrolu atlandi");
            return result;
        }

        if (ocspSource == null && crlSource == null) {
            logger.warn("TSA revocation skipped: neither OCSP nor CRL source bean is available "
                    + "(verification.online-validation-enabled may be false)");
            result.setWarning("Online revocation source'lari yapilandirilmamis; TSA revocation kontrolu yapilamadi");
            return result;
        }

        // 1) OCSP
        if (ocspSource != null) {
            try {
                OCSPToken ocsp = ocspSource.getRevocationToken(certificate, issuer);
                if (ocsp != null && ocsp.getStatus() != null) {
                    CertificateStatus status = ocsp.getStatus();
                    logger.info("TSA OCSP status: subject='{}', status={}", subjectLabel, status);

                    // Token'i response'a zengin bicimde yansitmak icin
                    // RevocationInfo'ya cevir — caller bunu CertificateInfo'ya
                    // koyacak (UI/audit gorunurlugu).
                    result.setRevocationInfo(revocationInfoExtractor.fromToken(ocsp));

                    if (status == CertificateStatus.REVOKED) {
                        result.setValid(false);
                        result.setError("TSA sertifikasi OCSP'ye gore iptal edilmis (revocationDate="
                                + ocsp.getRevocationDate() + ")");
                        return result;
                    }
                    if (status == CertificateStatus.GOOD) {
                        return result; // GOOD — basari, kontrol bitti
                    }
                    // UNKNOWN — CRL'e dus
                    logger.info("TSA OCSP status UNKNOWN; falling back to CRL");
                } else {
                    logger.debug("TSA OCSP returned no token; will try CRL");
                }
            } catch (RuntimeException e) {
                logger.warn("TSA OCSP check threw: {}; will try CRL", e.getMessage());
            }
        }

        // 2) CRL
        if (crlSource != null) {
            try {
                CRLToken crl = crlSource.getRevocationToken(certificate, issuer);
                if (crl != null && crl.getStatus() != null) {
                    CertificateStatus status = crl.getStatus();
                    logger.info("TSA CRL status: subject='{}', status={}", subjectLabel, status);

                    // CRL token'i RevocationInfo'ya cevir. Eger OCSP daha
                    // once UNKNOWN dondurduyse onun yerini alir — son soyleyen
                    // kaynak (CRL) daha kesin.
                    result.setRevocationInfo(revocationInfoExtractor.fromToken(crl));

                    if (status == CertificateStatus.REVOKED) {
                        result.setValid(false);
                        result.setError("TSA sertifikasi CRL'e gore iptal edilmis (revocationDate="
                                + crl.getRevocationDate() + ")");
                        return result;
                    }
                    return result; // GOOD veya UNKNOWN — TSA katmaninda toleranslı
                } else {
                    logger.debug("TSA CRL returned no token for subject='{}'", subjectLabel);
                }
            } catch (RuntimeException e) {
                logger.warn("TSA CRL check threw: {}", e.getMessage());
            }
        }

        // Iki kaynak da islem yapamadı — WARN
        result.setWarning("TSA revocation kontrolu OCSP/CRL kaynaklarindan dogrulanamadi");
        return result;
    }

    /**
     * Timestamp token icinde gelen sertifika listesinde TSA sertifikasinin
     * issuer'ini bulur. {@code TimestampToken.getCertificates()} TSA cert'i
     * 0. indekste, issuer ve daha ust CA'lar sonraki indekslerde gelir
     * (RFC 3161). Issuer DN eslestirmesi ile bulunur — sirayla
     * guvenmiyoruz cunku bazi TSA'lar full chain gondermez.
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
     * deposundan (KamuSM kokleri) cozer.
     *
     * <p>KamuSM TSA token'lari genelde yalnizca leaf sertifikayi gomer; issuer
     * (kok) token icinde gelmez. Eskiden issuer yalnizca token icinde arandigi
     * icin bulunamiyor, revocation kontrolu komple atlaniyor ve "issuer
     * bulunamadi" uyarisi olusuyordu. Artik leaf'i gercekten imzalamis kok'u
     * guven deposundan bulup CRL/OCSP revocation kontrolune sokabiliyoruz.
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

    /**
     * Bir {@link RevocationInfo}'yu TSA {@link CertificateInfo}'sunun ilgili
     * alanlarina (revoked, revocationReason, revocationDate, revocationTime,
     * revocation, valid) tutarli bicimde yansitir.
     *
     * <p>Imzaci sertifikasi icin
     * {@code AdvancedSignatureVerificationService.extractCertificateInfo(...)}
     * icindeki ayni mantigin TSA paraleli — DRY icin static, simple timestamp
     * endpoint'i de buradan yararlanabilsin diye package-private.
     *
     * <p>{@code info} {@code null} ise (revocation kontrolu yapilmadi veya
     * basarisiz) hicbir alanı degistirmez. Bu, geriye donuk uyumlu davranis:
     * cevrimdisi modda TSA cert info eskiden oldugu gibi sade kalir.
     */
    static void applyRevocationToCertInfo(CertificateInfo certInfo, RevocationInfo info) {
        if (certInfo == null || info == null) {
            return;
        }
        certInfo.setRevocation(info);
        certInfo.setRevocationReason(info.getRevocationReason());
        certInfo.setRevocationDate(info.getRevocationDate());
        // Legacy alan — `revocationDate` ile ayni degeri tasir.
        certInfo.setRevocationTime(info.getRevocationDate());

        boolean isRevoked = "REVOKED".equals(info.getStatus());
        certInfo.setRevoked(isRevoked);
        if (isRevoked) {
            // Expired olmayan ama REVOKED bir cert'in `valid` field'i artik
            // false dondurulur — onceden hardcoded `setRevoked(false)`
            // yuzunden `valid: true` gorunuyordu.
            certInfo.setValid(false);
        }
    }

    // Inner classes for structured results
    
    private static class MessageImprintResult {
        private boolean valid;
        private String error;
        private String digestAlgorithm;

        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public String getDigestAlgorithm() { return digestAlgorithm; }
        public void setDigestAlgorithm(String digestAlgorithm) { this.digestAlgorithm = digestAlgorithm; }
    }

    private static class CertificateValidationResult {
        private CertificateInfo certificateInfo;
        private List<String> errors = new ArrayList<>();
        private List<String> warnings = new ArrayList<>();

        public CertificateInfo getCertificateInfo() { return certificateInfo; }
        public void setCertificateInfo(CertificateInfo certificateInfo) { this.certificateInfo = certificateInfo; }
        public List<String> getErrors() { return errors; }
        public void setErrors(List<String> errors) { this.errors = errors; }
        public List<String> getWarnings() { return warnings; }
        public void setWarnings(List<String> warnings) { this.warnings = warnings; }
    }

    private static class RevocationCheckResult {
        private boolean valid;
        private String error;
        private String warning;
        /**
         * Sorgulanan OCSP/CRL token'indan turetilen zengin revocation
         * bilgisi. Caller bunu {@link CertificateInfo#setRevocation(RevocationInfo)}
         * ile TSA sertifikasi response'una yansitir. Token alinamadiysa
         * {@code null}.
         */
        private RevocationInfo revocationInfo;

        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public String getWarning() { return warning; }
        public void setWarning(String warning) { this.warning = warning; }
        public RevocationInfo getRevocationInfo() { return revocationInfo; }
        public void setRevocationInfo(RevocationInfo revocationInfo) { this.revocationInfo = revocationInfo; }
    }
}

