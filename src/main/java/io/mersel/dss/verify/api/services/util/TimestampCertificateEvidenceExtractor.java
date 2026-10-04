package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import io.mersel.dss.verify.api.models.CertificateInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.tsp.TimeStampToken;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** RFC 3161 signer selection and display chains; never assumes a certificate's position in a CMS SET. */
public final class TimestampCertificateEvidenceExtractor {
    private TimestampCertificateEvidenceExtractor() { }

    public static CertificateToken selectSigner(TimestampToken token) {
        if (token == null || token.getCertificates() == null) return null;
        TimeStampToken timestamp = token.getTimeStamp();
        if (timestamp == null) return null;
        List<CertificateToken> matching = new ArrayList<>();
        for (CertificateToken certificate : token.getCertificates()) {
            try {
                if (timestamp.getSID().match(new X509CertificateHolder(certificate.getEncoded()))) matching.add(certificate);
            } catch (Exception ignored) { }
        }
        if (matching.size() == 1) return matching.get(0);
        // Ambiguous issuer+serial IDs require cryptographic disambiguation; never fall back to list order.
        for (CertificateToken certificate : matching) {
            if (token.isSignedBy(certificate)) return certificate;
        }
        return null;
    }

    public static List<CertificateInfo> exportChain(CertificateToken leaf, List<CertificateToken> embedded,
            CommonTrustedCertificateSource trust, CertificateInfo leafInfo, CertificateInfoExtractor extractor) {
        List<CertificateInfo> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        CertificateToken current = leaf;
        while (current != null && seen.add(current.getDSSIdAsString()) && result.size() < 32) {
            CertificateInfo info = current == leaf && leafInfo != null ? leafInfo : extractor.extractCertificateInfo(current);
            if (trust != null && current != leaf) info.setTrusted(trust.isTrusted(current));
            result.add(info);
            if (current.isSelfSigned()) break;
            CertificateToken issuer = findIssuer(current, embedded, trust);
            if (issuer == null || seen.contains(issuer.getDSSIdAsString())) break;
            info.setIssuerCertificateId(issuer.getDSSIdAsString());
            current = issuer;
        }
        return result;
    }

    public static CertificateToken findIssuer(CertificateToken certificate, List<CertificateToken> embedded,
            CommonTrustedCertificateSource trust) {
        if (certificate == null) return null;
        if (embedded != null) {
            for (CertificateToken candidate : embedded) if (isIssuer(certificate, candidate)) return candidate;
        }
        if (trust != null) {
            for (CertificateToken candidate : trust.getBySubject(certificate.getIssuer())) {
                if (isIssuer(certificate, candidate)) return candidate;
            }
        }
        return null;
    }

    private static boolean isIssuer(CertificateToken certificate, CertificateToken candidate) {
        return candidate != null && !certificate.getDSSIdAsString().equals(candidate.getDSSIdAsString())
                && certificate.getIssuer().getCanonical().equals(candidate.getSubject().getCanonical())
                && certificate.isSignedBy(candidate);
    }
}
