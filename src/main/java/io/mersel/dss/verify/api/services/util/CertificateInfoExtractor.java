package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.model.x509.CertificateToken;
import io.mersel.dss.verify.api.models.CertificateInfo;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Sertifika bilgilerini extract eden utility sınıfı
 */
@Component
public class CertificateInfoExtractor {

    /**
     * CertificateToken'dan CertificateInfo oluşturur
     */
    public CertificateInfo extractCertificateInfo(CertificateToken certToken) {
        if (certToken == null) {
            return null;
        }

        CertificateInfo info = new CertificateInfo();
        
        try {
            String subjectDN = certToken.getSubject().getPrettyPrintRFC2253();
            info.setCommonName(subjectDN);
            info.setSubject(subjectDN);
            info.setIssuerDN(certToken.getIssuer().getPrettyPrintRFC2253());
            info.setSerialNumber(certToken.getSerialNumber().toString(16).toUpperCase());
            info.setNotBefore(certToken.getNotBefore());
            info.setNotAfter(certToken.getNotAfter());
            
            // Key usage ve diğer bilgiler X509Certificate'ten alınır
            X509Certificate x509 = (X509Certificate) certToken.getCertificate();
            if (x509 != null) {
                boolean[] keyUsage = x509.getKeyUsage();
                if (keyUsage != null) {
                    info.setKeyUsage(formatKeyUsage(keyUsage));
                }
                
                // Public key bilgileri
                if (x509.getPublicKey() != null) {
                    info.setPublicKeyAlgorithm(x509.getPublicKey().getAlgorithm());
                    // Key size hesaplama
                    try {
                        if (x509.getPublicKey() instanceof java.security.interfaces.RSAPublicKey) {
                            java.security.interfaces.RSAPublicKey rsaKey = 
                                (java.security.interfaces.RSAPublicKey) x509.getPublicKey();
                            info.setPublicKeySize(rsaKey.getModulus().bitLength());
                        }
                    } catch (Exception ignored) {
                        // Key size alınamazsa atla
                    }
                }
                
                info.setSignatureAlgorithm(x509.getSigAlgName());
            }
            
            // Expiry check
            Date now = new Date();
            info.setExpired(now.after(certToken.getNotAfter()) || now.before(certToken.getNotBefore()));
            
            // Revocation durumu başlangıçta false
            info.setRevoked(false);
            
        } catch (Exception e) {
            // Hata durumunda sadece temel bilgileri dön
        }
        
        return info;
    }

    /**
     * Key usage bilgisini formatlar
     */
    private String formatKeyUsage(boolean[] keyUsage) {
        StringBuilder sb = new StringBuilder();
        String[] usages = {
            "Digital Signature", "Non Repudiation", "Key Encipherment", 
            "Data Encipherment", "Key Agreement", "Key Cert Sign", 
            "CRL Sign", "Encipher Only", "Decipher Only"
        };
        
        for (int i = 0; i < keyUsage.length && i < usages.length; i++) {
            if (keyUsage[i]) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(usages[i]);
            }
        }
        
        return sb.toString();
    }
}

