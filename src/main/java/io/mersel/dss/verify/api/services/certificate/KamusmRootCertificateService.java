package io.mersel.dss.verify.api.services.certificate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Güvenilir kök sertifika servisi (wrapper)
 * Üç farklı resolver'ı destekler:
 * - KamuSMXmlDepoOnlineResolver: İnternet üzerinden KamuSM XML deposunu yükler
 * - KamuSMXmlDepoOfflineResolver: Yerel dosyadan KamuSM XML deposunu yükler
 * - CertificateFolderResolver: Klasördeki tüm .crt/.cer dosyalarını yükler
 */
@Service
public class KamusmRootCertificateService {

    private static final Logger logger = LoggerFactory.getLogger(KamusmRootCertificateService.class);
    
    private final TrustedRootCertificateResolver resolver;

    @Autowired
    public KamusmRootCertificateService(
            @Value("${trusted.root.resolver.type:kamusm-online}") String resolverType,
            @Qualifier("kamuSMXmlDepoOnlineResolver") TrustedRootCertificateResolver onlineResolver,
            @Qualifier("kamuSMXmlDepoOfflineResolver") TrustedRootCertificateResolver offlineResolver,
            @Qualifier("certificateFolderResolver") TrustedRootCertificateResolver folderResolver) {
        
        switch (resolverType.toLowerCase()) {
            case "kamusm-online":
                logger.info("Using KamuSM XML Depo Online Resolver");
                this.resolver = onlineResolver;
                break;
            case "kamusm-offline":
                logger.info("Using KamuSM XML Depo Offline Resolver");
                this.resolver = offlineResolver;
                break;
            case "certificate-folder":
            case "folder":
                logger.info("Using Certificate Folder Resolver");
                this.resolver = folderResolver;
                break;
            default:
                logger.warn("Unknown resolver type: {}, defaulting to kamusm-online", resolverType);
                this.resolver = onlineResolver;
        }
    }

    @PostConstruct
    public void init() {
        refreshTrustedRoots();
    }

    @Scheduled(cron = "${trusted.root.refresh-cron:0 15 3 * * *}")
    public void refreshTrustedRoots() {
        resolver.refreshTrustedRoots();
    }

    public List<X509Certificate> getTrustedRoots() {
        return resolver.getTrustedRoots();
    }

    public List<CertificateToken> getTrustedRootTokens() {
        return resolver.getTrustedRootTokens();
    }

    public CommonTrustedCertificateSource getTrustedCertificateSource() {
        return resolver.getTrustedCertificateSource();
    }

    public void addTrustedCertificate(CertificateToken certificate) {
        resolver.addTrustedCertificate(certificate);
    }

    public void addTrustedCertificate(X509Certificate certificate) {
        resolver.addTrustedCertificate(certificate);
    }

    public boolean isTrusted(CertificateToken certificate) {
        return resolver.isTrusted(certificate);
    }

    /**
     * Bir sertifikanin guvenilir bir KamuSM kokune <em>zincirlenebilir</em>
     * olup olmadigini kontrol eder.
     *
     * <p>{@link #isTrusted(CertificateToken)} yalnizca <strong>birebir uyelik</strong>
     * kontrolu yapar (sertifikanin kendisi guven deposunda mi?). Bu, imzaci/TSA
     * <em>leaf</em> sertifikalari icin neredeyse her zaman {@code false} doner —
     * cunku guven deposunda yalnizca kok (ve ara) sertifikalar bulunur, leaf'in
     * kendisi degil. XAdES tarafinda DSS {@code CertificateVerifier} bu zinciri
     * otomatik kurarken, RFC 3161 timestamp token'lari icin elle dogrulama
     * yaptigimizdan bu zincir kurma adimi eksikti; sonucta gecerli KamuSM TSA
     * sertifikalari bile "guvenilir kok'e zincirlenemiyor" uyarisi aliyordu.
     *
     * <p>Strateji: {@code certificate}'tan baslayarak issuer DN'i guven
     * deposundaki bir sertifikanin subject'i ile eslesen ve imza dogrulamasi
     * gecen bir kok bulunana kadar zinciri yukari tirmaniriz. Ara sertifikalar
     * ({@code chainCandidates}) genelde timestamp token'i icinden gelir; token
     * yalnizca leaf tasiyorsa dahi, leaf'in issuer'i (kok) depoda bulundugunda
     * trust kurulur.
     *
     * @param certificate     dogrulanacak leaf sertifika (orn. TSA sertifikasi)
     * @param chainCandidates zincir kurarken kullanilabilecek ek ara sertifikalar
     *                        (orn. token icindeki sertifikalar); {@code null} olabilir
     * @return guvenilir bir koke zincirlenebiliyorsa {@code true}
     */
    public boolean isChainTrusted(CertificateToken certificate, List<CertificateToken> chainCandidates) {
        if (certificate == null) {
            return false;
        }

        CommonTrustedCertificateSource trustedSource = resolver.getTrustedCertificateSource();
        if (trustedSource == null) {
            return false;
        }

        List<CertificateToken> pool = chainCandidates != null ? chainCandidates : Collections.emptyList();
        CertificateToken current = certificate;
        Set<CertificateToken> visited = new HashSet<>();

        // Sonsuz donguye karsi makul bir derinlik siniri.
        for (int depth = 0; current != null && depth < 16 && visited.add(current); depth++) {
            // (a) Mevcut sertifikanin issuer'i guven deposunda bir kok/ara
            //     sertifika ise ve onu gercekten imzalamissa -> trust kuruldu.
            for (CertificateToken anchor : trustedSource.getBySubject(current.getIssuer())) {
                if (current.isSignedBy(anchor)) {
                    logger.debug("Trust anchor bulundu: '{}' tarafindan imzalanmis '{}'",
                            anchor.getSubject().getPrettyPrintRFC2253(),
                            current.getSubject().getPrettyPrintRFC2253());
                    return true;
                }
            }

            // (b) Mevcut sertifikanin kendisi dogrudan guven deposundaysa
            //     (orn. self-signed kok token icine gomulu gelmis) -> trust.
            for (CertificateToken anchor : trustedSource.getBySubject(current.getSubject())) {
                if (anchor.equals(current)) {
                    return true;
                }
            }

            // Self-signed bir koke ulastik ama depoda degil -> zincir burada biter.
            if (current.isSelfSigned()) {
                break;
            }

            // (c) Aksi halde token'dan gelen ara sertifikalarla bir ust basamaga tirman.
            CertificateToken next = null;
            for (CertificateToken candidate : pool) {
                if (!candidate.equals(current) && current.isSignedBy(candidate)) {
                    next = candidate;
                    break;
                }
            }
            current = next;
        }

        return false;
    }
}
