package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import io.mersel.dss.verify.api.models.RevocationInfo;
import io.mersel.dss.verify.api.models.enums.ChainRevocationStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.List;

/**
 * DSS {@link CertificateWrapper}'dan zengin {@link RevocationInfo} çıkaran
 * yardımcı component.
 *
 * <p>Tarihsel olarak {@code AdvancedSignatureVerificationService} içinde
 * {@code isRevoked = false} ve {@code certificateNotRevoked = true} hardcoded
 * değerleri kullanılıyordu — bu, REVOKED sertifikalar için bile response'da
 * yanıltıcı "iptal değil" çıktısı üretiyordu. Bu sınıf DSS DiagnosticData
 * üzerinden gerçek revocation durumunu çıkarır ve operasyonel/audit
 * gereksinimleri için OCSP/CRL detaylarını (source, status, responder URL,
 * thisUpdate/nextUpdate, origin, vb.) {@link RevocationInfo}'ya yansıtır.
 *
 * <p>Bir sertifika için birden fazla revocation token olabilir (örn. hem OCSP
 * hem CRL, ya da farklı zamanlardaki OCSP cevapları). Seçim politikası:
 * <ol>
 *   <li>Eğer en az bir token {@code REVOKED} ise — bu güvenlik öncelikli
 *       sonuçtur, REVOKED'lar arasında en güncel {@code productionDate}'e
 *       sahip olan seçilir.</li>
 *   <li>Aksi halde en güncel {@code productionDate}'e sahip token tercih
 *       edilir.</li>
 * </ol>
 *
 * <p>Tüm DSS exception'ları yutulur (defensive) — revocation çıkarımının
 * sertifika çıkarım pipeline'ını bloklamasına izin verilmez.
 */
@Component
public class RevocationInfoExtractor {

    private static final Logger logger = LoggerFactory.getLogger(RevocationInfoExtractor.class);

    /**
     * Verilen sertifika için en uygun revocation token'ı seçer ve
     * {@link RevocationInfo}'ya çevirir. Hiç revocation verisi yoksa
     * {@code null} döner.
     */
    public RevocationInfo extractFor(CertificateWrapper certWrapper) {
        if (certWrapper == null) {
            return null;
        }

        List<CertificateRevocationWrapper> revocations;
        try {
            revocations = certWrapper.getCertificateRevocationData();
        } catch (Exception e) {
            logger.debug("Sertifika icin revocation data alinirken hata: {}", e.getMessage());
            return null;
        }

        if (revocations == null || revocations.isEmpty()) {
            return null;
        }

        CertificateRevocationWrapper selected = selectMostRelevantRevocation(revocations);
        if (selected == null) {
            return null;
        }

        return toRevocationInfo(selected);
    }

    /**
     * Ham bir DSS {@link RevocationToken} (OCSP veya CRL token) örneğinden
     * doğrudan {@link RevocationInfo} üretir. Standalone timestamp doğrulama
     * akışı gibi DSS {@code DiagnosticData}'nın bulunmadığı yerlerde
     * kullanılır — orada elimizdeki sadece ham token olur ve
     * {@link #extractFor(CertificateWrapper)} çağrılamaz.
     *
     * <p>OCSPToken ve CRLToken aynı {@link RevocationToken} taban sınıfından
     * türediği için tek generic API ile her ikisi de karşılanır.
     *
     * <p>Token {@code null} ise veya hiçbir alanı okunamıyorsa {@code null}
     * döner. Tek tek alan exception'ları defensive yutulur — bir alanın
     * eksikliği diğerlerinin dönüşmesini engellemez.
     */
    public RevocationInfo fromToken(RevocationToken<?> token) {
        if (token == null) {
            return null;
        }

        RevocationInfo info = new RevocationInfo();

        try {
            RevocationType type = token.getRevocationType();
            if (type != null) {
                info.setSource(type.name());
            }
        } catch (Exception ignore) {
            // defensive
        }

        try {
            CertificateStatus status = token.getStatus();
            if (status != null) {
                info.setStatus(status.name());
            }
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setRevocationDate(token.getRevocationDate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            RevocationReason reason = token.getReason();
            if (reason != null) {
                info.setRevocationReason(reason.name());
            }
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setProducedAt(token.getProductionDate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setThisUpdate(token.getThisUpdate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setNextUpdate(token.getNextUpdate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            String url = token.getSourceURL();
            if (url != null && !url.isEmpty()) {
                info.setResponderUrl(url);
            }
        } catch (Exception ignore) {
            // defensive
        }

        try {
            RevocationOrigin origin = token.getExternalOrigin();
            if (origin != null) {
                info.setOrigin(origin.name());
            }
        } catch (Exception ignore) {
            // defensive
        }

        return info;
    }

    /**
     * Bir imzanın tüm sertifika zincirine (leaf + intermediate CA'lar) ait
     * revocation durumunun kompakt özetini hesaplar.
     *
     * <p>Yöntem: zincirin 0. elemanı leaf, 1..n-1 indeksleri ara CA + root
     * (root için DSS DiagnosticData revocation token üretmez —
     * {@link #extractFor(CertificateWrapper)} doğal olarak {@code null}
     * döner ve sessizce atlanır).
     *
     * <p>Önceliklendirme (üstten alta):
     * <ol>
     *   <li>Zincir boş/null veya hiçbir cert için revocation verisi yok →
     *       {@link ChainRevocationStatus#NOT_CHECKED}.</li>
     *   <li>Leaf {@code REVOKED} → {@link ChainRevocationStatus#LEAF_REVOKED}.</li>
     *   <li>Leaf {@code UNKNOWN} → {@link ChainRevocationStatus#UNKNOWN}
     *       (CA durumuna bakılmaz).</li>
     *   <li>Leaf {@code GOOD}, ara CA'lardan biri {@code REVOKED} →
     *       {@link ChainRevocationStatus#LEAF_GOOD_CA_REVOKED}.</li>
     *   <li>Leaf {@code GOOD}, hiç CA {@code REVOKED} değil ama
     *       en az biri {@code UNKNOWN} →
     *       {@link ChainRevocationStatus#UNKNOWN}.</li>
     *   <li>Leaf ve tüm tanımlı CA'lar {@code GOOD} →
     *       {@link ChainRevocationStatus#ALL_GOOD}.</li>
     * </ol>
     *
     * <p>Bu özet doğrulama kararını <em>değiştirmez</em>; DSS policy
     * zincirin tamamını {@code SigningCertificate} + {@code CACertificate}
     * blokları üzerinden kendi kuralları çerçevesinde kontrol eder.
     * Bu metot yalnız SIMPLE mod response'unda kullanıcının zincirin
     * geneline dair tek bakışta doğru karar verebilmesi için.
     */
    public ChainRevocationStatus computeChainStatus(List<CertificateWrapper> chain) {
        if (chain == null || chain.isEmpty()) {
            return ChainRevocationStatus.NOT_CHECKED;
        }

        // Leaf cert — 0. indeks
        CertificateWrapper leaf = chain.get(0);
        RevocationInfo leafRev = extractFor(leaf);

        if (leafRev == null) {
            // Leaf icin hic revocation verisi yok — zincirde herhangi bir cert
            // icin revocation token var mi? Varsa UNKNOWN (kismi gorus), yoksa
            // NOT_CHECKED (hicbir sorgu yapilmadi).
            for (int i = 1; i < chain.size(); i++) {
                if (extractFor(chain.get(i)) != null) {
                    return ChainRevocationStatus.UNKNOWN;
                }
            }
            return ChainRevocationStatus.NOT_CHECKED;
        }

        String leafStatus = leafRev.getStatus();
        if ("REVOKED".equals(leafStatus)) {
            return ChainRevocationStatus.LEAF_REVOKED;
        }
        if ("UNKNOWN".equals(leafStatus)) {
            return ChainRevocationStatus.UNKNOWN;
        }

        // Leaf GOOD — CA'lari incele.
        boolean anyCaRevoked = false;
        boolean anyCaUnknown = false;
        for (int i = 1; i < chain.size(); i++) {
            RevocationInfo caRev = extractFor(chain.get(i));
            if (caRev == null) {
                // Root cert icin normal — DSS revocation token uretmez.
                // Defensive olarak sessizce atla; "missing" UNKNOWN demek
                // degildir, sadece "kontrol gerekmiyor" olabilir.
                continue;
            }
            String caStatus = caRev.getStatus();
            if ("REVOKED".equals(caStatus)) {
                anyCaRevoked = true;
            } else if ("UNKNOWN".equals(caStatus)) {
                anyCaUnknown = true;
            }
        }

        if (anyCaRevoked) {
            return ChainRevocationStatus.LEAF_GOOD_CA_REVOKED;
        }
        if (anyCaUnknown) {
            return ChainRevocationStatus.UNKNOWN;
        }
        return ChainRevocationStatus.ALL_GOOD;
    }

    /**
     * Sertifika için DSS DiagnosticData'sında REVOKED durumda bir revocation
     * token olup olmadığını kontrol eder. Hiç revocation verisi yoksa
     * "iptal olduğuna dair kanıt yok" anlamında {@code true} döner.
     * Strict politikalar bu durumda imzanın {@code valid} field'ını zaten
     * FAIL'a düşürür (RevocationDataAvailable = FAIL), dolayısıyla bu
     * varsayım güvenlidir.
     */
    public boolean isNotRevoked(CertificateWrapper certWrapper) {
        if (certWrapper == null) {
            return true;
        }
        List<CertificateRevocationWrapper> revocations;
        try {
            revocations = certWrapper.getCertificateRevocationData();
        } catch (Exception e) {
            return true;
        }
        if (revocations == null || revocations.isEmpty()) {
            return true;
        }
        for (CertificateRevocationWrapper rev : revocations) {
            if (rev != null && safeStatus(rev) == CertificateStatus.REVOKED) {
                return false;
            }
        }
        return true;
    }

    CertificateRevocationWrapper selectMostRelevantRevocation(List<CertificateRevocationWrapper> revocations) {
        CertificateRevocationWrapper bestRevoked = null;
        CertificateRevocationWrapper bestOther = null;

        for (CertificateRevocationWrapper rev : revocations) {
            if (rev == null) {
                continue;
            }
            CertificateStatus status = safeStatus(rev);
            if (status == CertificateStatus.REVOKED) {
                if (bestRevoked == null || isMoreRecent(rev, bestRevoked)) {
                    bestRevoked = rev;
                }
            } else {
                if (bestOther == null || isMoreRecent(rev, bestOther)) {
                    bestOther = rev;
                }
            }
        }
        return bestRevoked != null ? bestRevoked : bestOther;
    }

    RevocationInfo toRevocationInfo(CertificateRevocationWrapper rev) {
        RevocationInfo info = new RevocationInfo();

        try {
            RevocationType type = rev.getRevocationType();
            if (type != null) {
                info.setSource(type.name());
            }
        } catch (Exception ignore) {
            // defensive — eksik alan diğerlerini bloklamasın
        }

        try {
            CertificateStatus status = rev.getStatus();
            if (status != null) {
                info.setStatus(status.name());
            }
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setRevocationDate(rev.getRevocationDate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            RevocationReason reason = rev.getReason();
            if (reason != null) {
                info.setRevocationReason(reason.name());
            }
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setProducedAt(rev.getProductionDate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setThisUpdate(rev.getThisUpdate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            info.setNextUpdate(rev.getNextUpdate());
        } catch (Exception ignore) {
            // defensive
        }

        try {
            String url = rev.getSourceAddress();
            if (url != null && !url.isEmpty()) {
                info.setResponderUrl(url);
            }
        } catch (Exception ignore) {
            // defensive
        }

        try {
            RevocationOrigin origin = rev.getOrigin();
            if (origin != null) {
                info.setOrigin(origin.name());
            }
        } catch (Exception ignore) {
            // defensive
        }

        return info;
    }

    private boolean isMoreRecent(CertificateRevocationWrapper candidate,
                                 CertificateRevocationWrapper current) {
        Date candidateAt = safeProductionDate(candidate);
        Date currentAt = safeProductionDate(current);
        if (candidateAt == null) {
            return false;
        }
        if (currentAt == null) {
            return true;
        }
        return candidateAt.after(currentAt);
    }

    private CertificateStatus safeStatus(CertificateRevocationWrapper rev) {
        try {
            return rev.getStatus();
        } catch (Exception ignore) {
            return null;
        }
    }

    private Date safeProductionDate(CertificateRevocationWrapper rev) {
        try {
            return rev.getProductionDate();
        } catch (Exception ignore) {
            return null;
        }
    }
}
