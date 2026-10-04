package io.mersel.dss.verify.api.services.certificate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.*;

@Component
public class RequestTrustFactory {
    public static final int MAX_CERTIFICATES = 100;
    public static final int MAX_BYTES = 1024 * 1024;
    private final boolean enabled;
    public RequestTrustFactory(@Value("${verification.request-trust.enabled:false}") boolean enabled) { this.enabled = enabled; }
    public boolean isEnabled() { return enabled; }
    /** null means the standard server source. CUSTOM with no files is an intentionally empty source. */
    public RequestTrustContext resolve(String mode, List<MultipartFile> files) {
        List<MultipartFile> uploads = files == null ? Collections.emptyList() : files;
        if ("SERVER".equals(mode)) {
            if (!uploads.isEmpty()) throw new IllegalArgumentException("SERVER modunda trustedCertificates gönderilemez");
            return null;
        }
        if (!"CUSTOM".equals(mode)) throw new IllegalArgumentException("trustMode SERVER veya CUSTOM olmalıdır");
        if (!enabled) throw new IllegalArgumentException("İsteğe özel güven kökleri kapalı. Değerlendirme sunucusunda REQUEST_TRUST_ENABLED=true ayarlayın.");
        if (uploads.size() > MAX_CERTIFICATES) throw new IllegalArgumentException("En fazla 100 kök sertifika dosyası gönderilebilir");
        long size = 0;
        for (MultipartFile file : uploads) {
            size += file.getSize();
            if (file.isEmpty() || size > MAX_BYTES) throw new IllegalArgumentException("Kök dosyaları boş olamaz ve toplam 1 MB sınırını aşamaz");
        }
        List<CertificateToken> tokens = new ArrayList<>();
        try {
            for (MultipartFile file : uploads) {
                byte[] bytes = file.getBytes();
                String pem = new String(bytes, StandardCharsets.US_ASCII);
                if (bytes[0] != 0x30 && pem.contains("-----BEGIN")) {
                    Matcher matcher = Pattern.compile("-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\\s]+)-----END CERTIFICATE-----").matcher(pem);
                    int end = 0;
                    while (matcher.find()) {
                        if (!pem.substring(end, matcher.start()).trim().isEmpty()) throw new IllegalArgumentException();
                        tokens.add(parseDer(Base64.getDecoder().decode(matcher.group(1).replaceAll("\\s", ""))));
                        end = matcher.end();
                        if (tokens.size() > MAX_CERTIFICATES) throw new IllegalArgumentException();
                    }
                    if (end == 0 || !pem.substring(end).trim().isEmpty()) throw new IllegalArgumentException();
                } else tokens.add(parseDer(bytes));
                if (tokens.size() > MAX_CERTIFICATES) throw new IllegalArgumentException();
            }
        } catch (Exception e) { throw new IllegalArgumentException("Kök dosyaları yalnız geçerli X.509 DER/PEM sertifikaları içermeli; en fazla 100 sertifika kabul edilir.", e); }
        return new RequestTrustContext("CUSTOM", tokens);
    }
    private CertificateToken parseDer(byte[] bytes) throws Exception {
        ByteArrayInputStream input = new ByteArrayInputStream(bytes);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        if (input.available() != 0 || !Arrays.equals(bytes, cert.getEncoded())) throw new IllegalArgumentException();
        return new CertificateToken(cert);
    }
}
