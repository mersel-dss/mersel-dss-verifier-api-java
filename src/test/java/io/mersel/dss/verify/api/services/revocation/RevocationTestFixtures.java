package io.mersel.dss.verify.api.services.revocation;

import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.model.x509.CertificateToken;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Revocation testleri icin offline fixture'lar: BouncyCastle ile uretilen
 * kucuk bir PKI (kok CA + imzaci) ve 127.0.0.1 uzerinde path bazli sabit
 * cevap veren bir HTTP sunucusu. Hicbir test disari (KamuSM vb.) cikmaz.
 */
final class RevocationTestFixtures {

    private RevocationTestFixtures() {
    }

    /** RSA anahtar uretimi yavas; JVM basina bir kez uretilir. */
    private static final class Keys {
        static final KeyPair CA = generate();
        static final KeyPair LEAF = generate();

        private static KeyPair generate() {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                return generator.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /** Kok CA + CA'nin imzaladigi imzaci sertifikasi. */
    static final class TestPki {
        final KeyPair caKeys;
        final KeyPair leafKeys;
        final X509Certificate ca;
        final X509Certificate leaf;

        private TestPki(KeyPair caKeys, KeyPair leafKeys, X509Certificate ca, X509Certificate leaf) {
            this.caKeys = caKeys;
            this.leafKeys = leafKeys;
            this.ca = ca;
            this.leaf = leaf;
        }

        CertificateToken caToken() {
            return new CertificateToken(ca);
        }

        CertificateToken leafToken() {
            return new CertificateToken(leaf);
        }

        /**
         * @param crlUrl  imzacinin CRL dagitim noktasi ({@code null} = yok)
         * @param ocspUrl imzacinin AIA OCSP adresi ({@code null} = yok)
         */
        static TestPki create(String leafCommonName, String crlUrl, String ocspUrl) throws Exception {
            KeyPair caKeys = Keys.CA;
            KeyPair leafKeys = Keys.LEAF;
            JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            Date notBefore = new Date(System.currentTimeMillis() - 3_600_000L);
            Date notAfter = new Date(System.currentTimeMillis() + 86_400_000L * 30);

            X500Name caName = new X500Name("CN=Mersel Revocation Test Root,O=Mersel Test,C=TR");
            X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(caName, BigInteger.valueOf(1),
                    notBefore, notAfter, caName, caKeys.getPublic());
            caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            caBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            caBuilder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(caKeys.getPublic()));
            X509Certificate ca = new JcaX509CertificateConverter().getCertificate(
                    caBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(caKeys.getPrivate())));

            X500Name leafName = new X500Name("CN=" + leafCommonName + ",O=Mersel Test,C=TR");
            X509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(caName, BigInteger.valueOf(2),
                    notBefore, notAfter, leafName, leafKeys.getPublic());
            leafBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            leafBuilder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
            leafBuilder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(leafKeys.getPublic()));
            leafBuilder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(ca));
            if (crlUrl != null) {
                GeneralNames names = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl));
                leafBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(
                        new DistributionPoint[]{new DistributionPoint(new DistributionPointName(names), null, null)}));
            }
            if (ocspUrl != null) {
                leafBuilder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(
                        new AccessDescription(AccessDescription.id_ad_ocsp,
                                new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl))));
            }
            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(
                    leafBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(caKeys.getPrivate())));
            return new TestPki(caKeys, leafKeys, ca, leaf);
        }
    }

    /** 127.0.0.1 uzerinde path bazli sabit cevap veren HTTP sunucusu; istek sayilarini tutar. */
    static final class LocalHttpServer implements AutoCloseable {
        private final HttpServer server;
        private final Map<String, AtomicInteger> hits = new ConcurrentHashMap<>();

        private LocalHttpServer(HttpServer server) {
            this.server = server;
        }

        static LocalHttpServer start() throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "revocation-test-http");
                t.setDaemon(true);
                return t;
            }));
            server.start();
            return new LocalHttpServer(server);
        }

        /** {@code path} icin {@code status} + {@code body} doner (opsiyonel gecikme ile). */
        LocalHttpServer respond(String path, int status, byte[] body, long delayMs) {
            hits.put(path, new AtomicInteger());
            server.createContext(path, exchange -> {
                hits.get(path).incrementAndGet();
                try {
                    while (exchange.getRequestBody().read() != -1) {
                        // drain request body (OCSP POST)
                    }
                    if (delayMs > 0) {
                        Thread.sleep(delayMs);
                    }
                    byte[] payload = body == null ? new byte[0] : body;
                    exchange.sendResponseHeaders(status, payload.length == 0 ? -1 : payload.length);
                    if (payload.length > 0) {
                        try (OutputStream out = exchange.getResponseBody()) {
                            out.write(payload);
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } catch (IOException ignore) {
                    // istemci timeout ile baglantiyi kapatmis olabilir
                } finally {
                    exchange.close();
                }
            });
            return this;
        }

        LocalHttpServer respond(String path, int status, byte[] body) {
            return respond(path, status, body, 0L);
        }

        String url(String path) {
            return "http://127.0.0.1:" + server.getAddress().getPort() + path;
        }

        int hits(String path) {
            AtomicInteger counter = hits.get(path);
            return counter == null ? 0 : counter.get();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
