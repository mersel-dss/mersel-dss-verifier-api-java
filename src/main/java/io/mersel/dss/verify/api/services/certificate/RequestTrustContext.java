package io.mersel.dss.verify.api.services.certificate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import io.mersel.dss.verify.api.models.TrustEvidence;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Request-owned snapshot. Never exposes or mutates the shared resolver's source. */
public final class RequestTrustContext {
    private final String mode;
    private final String activeTrustId;
    private final String activatedAt;
    private final SortedMap<String, CertificateToken> certificates = new TreeMap<>();
    public RequestTrustContext(String mode, Collection<CertificateToken> tokens) {
        this(mode, tokens, null, null);
    }
    private RequestTrustContext(String mode, Collection<CertificateToken> tokens, String activeTrustId, String activatedAt) {
        this.mode = mode; this.activeTrustId = activeTrustId; this.activatedAt = activatedAt;
        try {
            for (CertificateToken token : tokens) {
                // Separate token objects too: DSS can attach validation state to tokens.
                CertificateToken copy = new CertificateToken(token.getCertificate());
                certificates.put(sha256(copy.getEncoded()), copy);
            }
        } catch (Exception e) { throw new IllegalArgumentException("Güven kökü özeti üretilemedi", e); }
    }
    public static RequestTrustContext server(CommonTrustedCertificateSource source) {
        return new RequestTrustContext("SERVER", source == null ? Collections.emptyList() : new ArrayList<>(source.getCertificates()));
    }
    public String getActiveTrustId() { return activeTrustId; }
    public RequestTrustContext activated(String id, String at) {
        return new RequestTrustContext(mode, certificates.values(), id, at);
    }
    public List<CertificateToken> retain(Collection<String> hashes) {
        if (!certificates.keySet().containsAll(hashes)) throw new IllegalArgumentException("Etkin kümede olmayan kök korunamaz");
        List<CertificateToken> tokens = new ArrayList<>();
        for (String hash : new TreeSet<>(hashes)) tokens.add(new CertificateToken(certificates.get(hash).getCertificate()));
        return tokens;
    }
    public boolean isCustom() { return "CUSTOM".equals(mode); }
    public CommonTrustedCertificateSource newSource() {
        CommonTrustedCertificateSource source = new CommonTrustedCertificateSource();
        for (CertificateToken token : certificates.values()) source.addCertificate(new CertificateToken(token.getCertificate()));
        return source;
    }
    public TrustEvidence evidence(boolean onlineValidationEnabled) {
        List<TrustEvidence.Anchor> anchors = new ArrayList<>();
        for (Map.Entry<String, CertificateToken> entry : certificates.entrySet()) {
            java.security.cert.X509Certificate cert = entry.getValue().getCertificate();
            anchors.add(new TrustEvidence.Anchor(entry.getKey(), cert.getSubjectX500Principal().getName(),
                    cert.getIssuerX500Principal().getName(), cert.getSerialNumber().toString(16)));
        }
        return new TrustEvidence(mode, sha256(String.join("\n", certificates.keySet()).getBytes(StandardCharsets.UTF_8)), anchors, onlineValidationEnabled, activeTrustId, activatedAt);
    }
    private static String sha256(byte[] bytes) {
        try {
            StringBuilder result = new StringBuilder();
            for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) result.append(String.format("%02x", value & 255));
            return result.toString();
        } catch (Exception e) { throw new IllegalStateException(e); }
    }
}
