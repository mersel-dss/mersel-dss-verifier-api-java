package io.mersel.dss.verify.api.services.util;

import io.mersel.dss.verify.api.models.CertificateInfo;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.PolicyInformation;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Exports public certificate material only; never computes or replaces DSS trust/revocation verdicts. */
public final class CertificateMaterialExtractor {
    private static final String[] KEY_USAGE_NAMES = {
            "Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment",
            "Key Agreement", "Key Cert Sign", "CRL Sign", "Encipher Only", "Decipher Only"
    };

    private CertificateMaterialExtractor() { }

    /** Missing or unreadable bytes leave the original diagnostic details intact. */
    public static void enrich(CertificateInfo info, byte[] der) {
        if (info == null || der == null || der.length == 0) {
            return;
        }
        try {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            enrich(info, certificate);
        } catch (Exception ignored) {
            // A malformed/missing export must not erase the DSS certificate or change its verdict.
        }
    }

    public static void enrich(CertificateInfo info, X509Certificate certificate) {
        if (info == null || certificate == null) {
            return;
        }
        try {
            byte[] der = certificate.getEncoded();
            info.setCertificateBase64(Base64.getEncoder().encodeToString(der));
            info.setSha256Fingerprint(hex(MessageDigest.getInstance("SHA-256").digest(der)));
            info.setSha1Fingerprint(hex(MessageDigest.getInstance("SHA-1").digest(der)));
            info.setSignatureAlgorithm(certificate.getSigAlgName());
            PublicKey key = certificate.getPublicKey();
            if (key != null) {
                info.setPublicKeyAlgorithm(key.getAlgorithm());
                if (key instanceof RSAPublicKey) {
                    info.setPublicKeySize(((RSAPublicKey) key).getModulus().bitLength());
                } else if (key instanceof ECPublicKey && ((ECPublicKey) key).getParams() != null) {
                    info.setPublicKeySize(((ECPublicKey) key).getParams().getCurve().getField().getFieldSize());
                } else if (key instanceof DSAPublicKey && ((DSAPublicKey) key).getParams() != null) {
                    info.setPublicKeySize(((DSAPublicKey) key).getParams().getP().bitLength());
                }
            }
            List<String> usages = new ArrayList<>();
            boolean[] usageBits = certificate.getKeyUsage();
            if (usageBits != null) {
                for (int i = 0; i < usageBits.length && i < KEY_USAGE_NAMES.length; i++) {
                    if (usageBits[i]) usages.add(KEY_USAGE_NAMES[i]);
                }
            }
            info.setKeyUsages(usages);
            info.setKeyUsage(String.join(", ", usages));
            info.setCertificateAuthority(certificate.getBasicConstraints() >= 0);
            info.setBasicConstraints(certificate.getBasicConstraints());
            info.setCriticalExtensionOids(sorted(certificate.getCriticalExtensionOIDs()));
            info.setNonCriticalExtensionOids(sorted(certificate.getNonCriticalExtensionOIDs()));
        } catch (Exception ignored) {
            // Export metadata remains best effort. No trust/validity fields are written here.
        }
        try {
            List<String> extended = certificate.getExtendedKeyUsage();
            info.setExtendedKeyUsages(extended == null ? Collections.emptyList() : new ArrayList<>(extended));
        } catch (Exception ignored) { }
        try {
            List<String> policies = new ArrayList<>();
            byte[] extension = certificate.getExtensionValue("2.5.29.32");
            if (extension != null) {
                byte[] value = ASN1OctetString.getInstance(extension).getOctets();
                for (PolicyInformation policy : CertificatePolicies.getInstance(value).getPolicyInformation()) {
                    policies.add(policy.getPolicyIdentifier().getId());
                }
            }
            info.setCertificatePolicyOids(policies);
        } catch (Exception ignored) { }
        try {
            Collection<List<?>> names = certificate.getSubjectAlternativeNames();
            List<String> values = new ArrayList<>();
            if (names != null) {
                for (List<?> name : names) {
                    if (name.size() >= 2) {
                        Object value = name.get(1);
                        values.add(name.get(0) + ": " + (value instanceof byte[]
                                ? Base64.getEncoder().encodeToString((byte[]) value) : String.valueOf(value)));
                    }
                }
            }
            info.setSubjectAlternativeNames(values);
        } catch (Exception ignored) { }
    }

    private static List<String> sorted(Set<String> values) {
        List<String> result = values == null ? new ArrayList<>() : new ArrayList<>(values);
        Collections.sort(result);
        return result;
    }

    public static String hex(byte[] bytes) {
        if (bytes == null) return null;
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) value.append(String.format("%02X", b & 0xff));
        return value.toString();
    }
}
