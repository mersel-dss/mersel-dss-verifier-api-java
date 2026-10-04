package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.LocalHttpServer;
import io.mersel.dss.verify.api.services.revocation.RevocationTestFixtures.TestPki;
import org.apache.hc.client5.http.ConnectTimeoutException;
import org.apache.hc.client5.http.HttpHostConnectException;
import org.apache.hc.client5.http.UnsupportedSchemeException;
import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.NoHttpResponseException;
import org.apache.hc.core5.util.TimeValue;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link RevocationFailureClassifier} — hangi revocation hatalari yeniden
 * denenir, hangileri denenmez.
 *
 * <p>Iki katman test edilir:</p>
 * <ol>
 *   <li>Sentetik zincirler — DSS'in urettigi mesaj formatlari ve JDK /
 *       HttpClient5 exception tipleriyle siniflandirma tablosu.</li>
 *   <li>Gercek DSS zincirleri — {@link OnlineCRLSource} / {@link OnlineOCSPSource}
 *       + {@link CommonsDataLoader} 127.0.0.1'deki yerel HTTP sunucusuna
 *       gercek istek atar; DSS'in sardigi exception zinciri (hem stok DSS
 *       response handler'i hem {@link StatusAwareHttpClientResponseHandler})
 *       siniflandiriciya verilir.</li>
 * </ol>
 */
class RevocationFailureClassifierTest {

    private static final RevocationFailureClassifier CLASSIFIER = RevocationFailureClassifier.INSTANCE;

    private static LocalHttpServer server;
    private static TestPki pki; // CRL DP / OCSP AIA yok: URL'ler alternativeUrls ile verilir

    @BeforeAll
    static void startServer() throws Exception {
        server = LocalHttpServer.start();
        for (int status : new int[]{400, 403, 404, 410, 408, 429, 500, 503}) {
            server.respond("/crl/" + status, status, "error".getBytes(StandardCharsets.UTF_8));
            server.respond("/ocsp/" + status, status, "error".getBytes(StandardCharsets.UTF_8));
        }
        server.respond("/crl/garbage", 200, "this is not a CRL".getBytes(StandardCharsets.UTF_8));
        server.respond("/crl/empty", 200, new byte[0]);
        server.respond("/crl/slow", 200, "late".getBytes(StandardCharsets.UTF_8), 2_000L);
        server.respond("/ocsp/garbage", 200, "this is not an OCSP response".getBytes(StandardCharsets.UTF_8));
        server.respond("/ocsp/try-later", 200, new OCSPRespBuilder().build(OCSPRespBuilder.TRY_LATER, null).getEncoded());
        server.respond("/ocsp/internal-error", 200, new OCSPRespBuilder().build(OCSPRespBuilder.INTERNAL_ERROR, null).getEncoded());
        server.respond("/ocsp/malformed-request", 200, new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null).getEncoded());
        server.respond("/ocsp/unauthorized", 200, new OCSPRespBuilder().build(OCSPRespBuilder.UNAUTHORIZED, null).getEncoded());
        pki = TestPki.create("Classifier Signer", null, null);
    }

    @AfterAll
    static void stopServer() {
        if (server != null) {
            server.close();
        }
    }

    // ------------------------------------------------------------------
    // HTTP status tablosu (sentetik)
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "HTTP {0} -> kalici (retry yok)")
    @ValueSource(ints = {400, 401, 403, 404, 405, 410, 451})
    void permanentHttpStatuses(int status) {
        assertPermanent(dssCrlFailure(typedStatus(status)), "HTTP " + status);
        assertPermanent(dssCrlFailure(new IOException(dssStatusMessage(status))), "HTTP " + status);
        assertFalse(RevocationFailureClassifier.isRetryableHttpStatus(status));
    }

    @ParameterizedTest(name = "HTTP {0} -> gecici (retry)")
    @ValueSource(ints = {408, 425, 429, 500, 502, 503, 504})
    void transientHttpStatuses(int status) {
        assertTransient(dssCrlFailure(typedStatus(status)), "HTTP " + status);
        assertTransient(dssCrlFailure(new IOException(dssStatusMessage(status))), "HTTP " + status);
        assertTrue(RevocationFailureClassifier.isRetryableHttpStatus(status));
    }

    @ParameterizedTest(name = "beklenmeyen HTTP {0} -> kalici")
    @ValueSource(ints = {204, 301, 302, 304})
    void unexpectedNonErrorStatusesArePermanent(int status) {
        assertPermanent(dssCrlFailure(typedStatus(status)), "HTTP " + status);
    }

    @Test
    @DisplayName("Tipli status, mesajdaki status'tan onceliklidir")
    void typedStatusWinsOverMessage() {
        RuntimeException failure = dssCrlFailure(new UnacceptableHttpStatusException(503, dssStatusMessage(400)));
        assertTransient(failure, "HTTP 503");
    }

    @Test
    @DisplayName("Mesaj parse: DSS formatindaki status kodu cikarilir, baska sayilar karistirilmaz")
    void parsesStatusFromDssMessage() {
        assertEquals(Integer.valueOf(400), RevocationFailureClassifier.parseHttpStatus(
                "Unable to retrieve CRL for certificate with Id 'C-1' from URL 'http://depo.test3.kamusm.gov.tr/RootA1.crl'. "
                        + "Reason : Unable to process GET call for url [http://depo.test3.kamusm.gov.tr/RootA1.crl]. "
                        + "Reason : [Not acceptable HTTP Status (HTTP status code : 400 / reason : Bad Request)]"));
        assertEquals(Integer.valueOf(503), RevocationFailureClassifier.parseHttpStatus(
                "Not acceptable HTTP Status (HTTP status code : 503)"));
        assertEquals(null, RevocationFailureClassifier.parseHttpStatus("Read timed out after 4000 ms"));
        assertEquals(null, RevocationFailureClassifier.parseHttpStatus("HTTP status code : 4000"));
        assertEquals(null, RevocationFailureClassifier.parseHttpStatus(null));
    }

    // ------------------------------------------------------------------
    // Transport tablosu (sentetik)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Timeout / reset / refused / erken kapanan baglanti -> gecici")
    void transientTransportFailures() {
        assertTransient(dssCrlFailure(new SocketTimeoutException("Read timed out")), "timeout");
        assertTransient(dssCrlFailure(new ConnectTimeoutException("Connect to http://x:80 failed: connect timed out")), "timeout");
        assertTransient(dssCrlFailure(new HttpHostConnectException("Connection refused")), "connection refused");
        assertTransient(dssCrlFailure(new java.net.ConnectException("Connection refused")), "connection refused");
        assertTransient(dssCrlFailure(new SocketException("Connection reset")), "socket error");
        assertTransient(dssCrlFailure(new java.net.NoRouteToHostException("No route to host")), "socket error");
        assertTransient(dssCrlFailure(new NoHttpResponseException("The target server failed to respond")), "no HTTP response");
        assertTransient(dssCrlFailure(new ConnectionClosedException("Premature end of Content-Length delimited message body")),
                "connection closed");
        assertTransient(dssCrlFailure(new SSLException("Connection reset")), "TLS I/O error");
        assertTransient(dssCrlFailure(new org.apache.hc.core5.http.ConnectionRequestTimeoutException("Timeout deadline")), "timeout");
    }

    @Test
    @DisplayName("DNS hatasi -> retry yok, ama gecici (cozumleyici kesintisi de UnknownHostException verir)")
    void dnsFailureIsTransientWithoutRetry() {
        // DSS mesaji cozumleyici kesintisinde "DNS error" olur; NXDOMAIN ile ayni exception tipi.
        FailureClassification c = CLASSIFIER.classify(dssCrlFailure(new UnknownHostException("DNS error")));
        assertFalse(c.isRetryable(), "DNS failure must not be retried: " + c);
        assertTrue(c.isTransient(), "DNS failure must use the short (transient) TTL: " + c);
        assertTrue(c.getReason().startsWith("unknown host"), c.getReason());
        // LDAP CDP: CommunicationException(rootCause=UnknownHostException)
        javax.naming.CommunicationException ldap = new javax.naming.CommunicationException("depo.example.invalid:389");
        ldap.setRootCause(new UnknownHostException("depo.example.invalid"));
        FailureClassification l = CLASSIFIER.classify(dssCrlFailure(ldap));
        assertFalse(l.isRetryable());
        assertTrue(l.isTransient());
    }

    @Test
    @DisplayName("Bozuk URL / desteklenmeyen protokol / TLS sertifika hatasi -> kalici")
    void permanentTransportFailures() {
        assertPermanent(new DSSExternalResourceException("Unable to create URL instance",
                new MalformedURLException("no protocol: crl")), "malformed URL");
        assertPermanent(new DSSExternalResourceException("Invalid URI : x",
                new URISyntaxException("ht tp://x", "Illegal character")), "malformed URL");
        assertPermanent(dssCrlFailure(new UnsupportedSchemeException("gopher protocol is not supported")), "unsupported protocol");
        SSLHandshakeException pkix = new SSLHandshakeException("PKIX path building failed");
        pkix.initCause(new CertificateException("unable to find valid certification path"));
        assertPermanent(dssCrlFailure(pkix), "certificate validation failed");
    }

    @Test
    @DisplayName("OCSP responseStatus: TRY_LATER / INTERNAL_ERROR gecici, digerleri kalici")
    void ocspResponseStatuses() {
        assertTransient(dssOcspStatusFailure("TRY_LATER"), "OCSP status TRY_LATER");
        assertTransient(dssOcspStatusFailure("INTERNAL_ERROR"), "OCSP status INTERNAL_ERROR");
        assertPermanent(dssOcspStatusFailure("MALFORMED_REQUEST"), "OCSP status MALFORMED_REQUEST");
        assertPermanent(dssOcspStatusFailure("SIG_REQUIRED"), "OCSP status SIG_REQUIRED");
        assertPermanent(dssOcspStatusFailure("UNAUTHORIZED"), "OCSP status UNAUTHORIZED");
    }

    @Test
    @DisplayName("Bozuk / bos cevap (transport izi yok) -> kalici")
    void unreadableResponsesArePermanent() {
        assertPermanent(new DSSExternalResourceException(
                "Unable to retrieve CRL for certificate with Id 'C-1' from URL 'http://x/a.crl'. Reason : Unable to parse the CRL",
                new DSSException("Unable to parse the CRL")), "unreadable or invalid response");
        assertPermanent(new DSSExternalResourceException(
                "CRL DataLoader for certificate with url 'http://x/a.crl' responded with an empty byte array!"),
                "unreadable or invalid response");
        assertPermanent(new IllegalStateException("unexpected"), "unreadable or invalid response");
    }

    @Test
    @DisplayName("Dongulu cause zinciri sonsuz donguye girmez")
    void cyclicCauseChainIsSafe() {
        RuntimeException a = new RuntimeException("a");
        RuntimeException b = new RuntimeException("b", a);
        a.initCause(b);
        assertFalse(CLASSIFIER.classify(a).isRetryable());
        assertFalse(CLASSIFIER.classify(null).isRetryable());
    }

    // ------------------------------------------------------------------
    // Gercek DSS zincirleri (yerel HTTP sunucusu)
    // ------------------------------------------------------------------

    @ParameterizedTest(name = "gercek CRL zinciri HTTP {0} -> kalici")
    @ValueSource(ints = {400, 403, 404, 410})
    void realCrlChainPermanentStatuses(int status) {
        for (boolean statusAware : new boolean[]{true, false}) {
            RuntimeException failure = realCrlFailure(server.url("/crl/" + status), statusAware);
            assertPermanent(failure, "HTTP " + status);
        }
    }

    @ParameterizedTest(name = "gercek CRL zinciri HTTP {0} -> gecici")
    @ValueSource(ints = {408, 429, 500, 503})
    void realCrlChainTransientStatuses(int status) {
        for (boolean statusAware : new boolean[]{true, false}) {
            RuntimeException failure = realCrlFailure(server.url("/crl/" + status), statusAware);
            assertTransient(failure, "HTTP " + status);
        }
    }

    @Test
    @DisplayName("Gercek zincir: tipli handler tipli status uretir, mesaj stok DSS ile birebir ayni")
    void statusAwareHandlerKeepsDssMessage() {
        String url = server.url("/crl/400");
        RuntimeException typed = realCrlFailure(url, true);
        RuntimeException stock = realCrlFailure(url, false);
        assertEquals(stock.getMessage(), typed.getMessage());
        assertTrue(typed.getMessage().contains("Not acceptable HTTP Status (HTTP status code : 400"), typed.getMessage());
        assertTrue(hasCause(typed, UnacceptableHttpStatusException.class));
        assertFalse(hasCause(stock, UnacceptableHttpStatusException.class));
    }

    @Test
    @DisplayName("Gercek zincir: read timeout -> gecici")
    void realCrlChainReadTimeout() {
        CommonsDataLoader loader = loader(new CommonsDataLoader(), true);
        loader.setTimeoutSocket(300);
        loader.setTimeoutResponse(300);
        RuntimeException failure = crlFailure(loader, server.url("/crl/slow"));
        assertTransient(failure, "timeout");
    }

    @Test
    @DisplayName("Gercek zincir: connection refused -> gecici")
    void realCrlChainConnectionRefused() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        RuntimeException failure = crlFailure(loader(new CommonsDataLoader(), true),
                "http://127.0.0.1:" + closedPort + "/crl/refused");
        assertTransient(failure, "connection refused");
    }

    @Test
    @DisplayName("Gercek zincir: bozuk CRL govdesi / bos govde -> kalici")
    void realCrlChainUnreadableBody() {
        assertPermanent(realCrlFailure(server.url("/crl/garbage"), true), "unreadable or invalid response");
        assertPermanent(realCrlFailure(server.url("/crl/empty"), true), "unreadable or invalid response");
    }

    @Test
    @DisplayName("Gercek zincir: desteklenmeyen protokol -> kalici")
    void realCrlChainUnsupportedProtocol() {
        // DSS bilinmeyen protokolu HTTP GET'e dusurur; HttpClient5 5.5 bunu
        // ProtocolException("Unroutable protocol scheme") ile reddeder.
        RuntimeException failure = realCrlFailure("gopher://127.0.0.1/crl.crl", true);
        assertTrue(failure.getMessage().contains("Unroutable protocol scheme"), failure.getMessage());
        assertPermanent(failure, "HTTP protocol error");
    }

    @Test
    @DisplayName("Gercek OCSP zinciri: 400 kalici, 500 gecici, responseStatus ve bozuk govde")
    void realOcspChains() {
        assertPermanent(realOcspFailure(server.url("/ocsp/400")), "HTTP 400");
        assertTransient(realOcspFailure(server.url("/ocsp/500")), "HTTP 500");
        assertTransient(realOcspFailure(server.url("/ocsp/try-later")), "OCSP status TRY_LATER");
        assertTransient(realOcspFailure(server.url("/ocsp/internal-error")), "OCSP status INTERNAL_ERROR");
        assertPermanent(realOcspFailure(server.url("/ocsp/malformed-request")), "OCSP status MALFORMED_REQUEST");
        assertPermanent(realOcspFailure(server.url("/ocsp/unauthorized")), "OCSP status UNAUTHORIZED");
        assertPermanent(realOcspFailure(server.url("/ocsp/garbage")), "unreadable or invalid response");
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    static String dssStatusMessage(int status) {
        return "Not acceptable HTTP Status (HTTP status code : " + status + " / reason : Some Reason)";
    }

    private static UnacceptableHttpStatusException typedStatus(int status) {
        return new UnacceptableHttpStatusException(status, dssStatusMessage(status));
    }

    /** DSS {@code OnlineCRLSource} + {@code CommonsDataLoader.httpGet}'in sardigi zincirin aynisi. */
    static RuntimeException dssCrlFailure(Exception transportCause) {
        String url = "http://depo.test3.kamusm.gov.tr/RootA1.crl";
        DSSExternalResourceException get = new DSSExternalResourceException(String.format(
                "Unable to process GET call for url [%s]. Reason : [%s]", url, transportCause.getMessage()), transportCause);
        return new DSSExternalResourceException(String.format(
                "Unable to retrieve CRL for certificate with Id '%s' from URL '%s'. Reason : %s",
                "C-030F391FF847CF268CC9C51927BA8D", url, get.getMessage()), get);
    }

    private static RuntimeException dssOcspStatusFailure(String status) {
        String url = "http://ocsp.example.test";
        DSSExternalResourceException inner = new DSSExternalResourceException(String.format(
                "Ignored OCSP Response from URL '%s' : status -> %s", url, status));
        return new DSSExternalResourceException(String.format(
                "Unable to retrieve OCSP response for certificate with Id '%s' from URL '%s'. Reason : %s",
                "C-1", url, inner.getMessage()), inner);
    }

    private static <T extends CommonsDataLoader> T loader(T loader, boolean statusAware) {
        loader.setTimeoutConnection(2_000);
        loader.setTimeoutSocket(2_000);
        loader.setTimeoutConnectionRequest(2_000);
        // HttpClient5'in kendi 429/503 retry'ini (1 s bekleme) testte kapat; siniflandirmayi etkilemez.
        loader.setRetryStrategy(new DefaultHttpRequestRetryStrategy(0, TimeValue.ZERO_MILLISECONDS));
        if (statusAware) {
            loader.setHttpClientResponseHandler(new StatusAwareHttpClientResponseHandler());
        }
        return loader;
    }

    private static RuntimeException realCrlFailure(String url, boolean statusAware) {
        return crlFailure(loader(new CommonsDataLoader(), statusAware), url);
    }

    private static RuntimeException crlFailure(CommonsDataLoader loader, String url) {
        OnlineCRLSource source = new OnlineCRLSource();
        source.setDataLoader(loader);
        return assertThrows(RuntimeException.class,
                () -> source.getRevocationToken(pki.leafToken(), pki.caToken(), Collections.singletonList(url)));
    }

    private static RuntimeException realOcspFailure(String url) {
        OnlineOCSPSource source = new OnlineOCSPSource();
        source.setDataLoader(loader(new OCSPDataLoader(), true));
        return assertThrows(RuntimeException.class,
                () -> source.getRevocationToken(pki.leafToken(), pki.caToken(), Collections.singletonList(url)));
    }

    private static boolean hasCause(Throwable t, Class<? extends Throwable> type) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (type.isInstance(c)) {
                return true;
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return false;
    }

    private static void assertTransient(Throwable failure, String reasonPrefix) {
        FailureClassification c = CLASSIFIER.classify(failure);
        assertTrue(c.isRetryable(), "expected transient for: " + failure + " but was " + c);
        assertTrue(c.isTransient(), "expected transient for: " + failure + " but was " + c);
        assertTrue(c.getReason().startsWith(reasonPrefix), "reason '" + c.getReason() + "' should start with '" + reasonPrefix + "'");
    }

    private static void assertPermanent(Throwable failure, String reasonPrefix) {
        FailureClassification c = CLASSIFIER.classify(failure);
        assertFalse(c.isRetryable(), "expected permanent for: " + failure + " but was " + c);
        assertFalse(c.isTransient(), "expected permanent for: " + failure + " but was " + c);
        assertTrue(c.getReason().startsWith(reasonPrefix), "reason '" + c.getReason() + "' should start with '" + reasonPrefix + "'");
    }
}
