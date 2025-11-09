package io.mersel.dss.verify.api.services.certificate;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Güvenilir kök sertifika çözümleyici interface'i
 * Farklı kaynaklardan (KamuSM XML deposu, CRT klasörü, vb.) güvenilir kök sertifikaları yükler
 */
public interface TrustedRootCertificateResolver {
    
    /**
     * Güvenilir kök sertifikaları yükler ve cache'ler
     */
    void refreshTrustedRoots();
    
    /**
     * Cache'lenmiş güvenilir kök sertifikaları döndürür
     */
    List<X509Certificate> getTrustedRoots();
    
    /**
     * Cache'lenmiş güvenilir kök sertifikaları DSS CertificateToken olarak döndürür
     */
    List<CertificateToken> getTrustedRootTokens();
    
    /**
     * Güvenilir sertifika kaynağını döner
     */
    CommonTrustedCertificateSource getTrustedCertificateSource();
    
    /**
     * Sertifikayı güvenilir sertifikalar arasına ekler
     */
    void addTrustedCertificate(CertificateToken certificate);
    
    /**
     * Sertifikayı güvenilir sertifikalar arasına ekler
     */
    void addTrustedCertificate(X509Certificate certificate);
    
    /**
     * Sertifikanın güvenilir olup olmadığını kontrol eder
     */
    boolean isTrusted(CertificateToken certificate);
}

