package io.mersel.dss.verify.api.services.revocation;

import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.UnsupportedSchemeException;
import org.apache.hc.client5.http.impl.ConnectionShutdownException;
import org.apache.hc.core5.http.ConnectionClosedException;
import org.apache.hc.core5.http.MalformedChunkCodingException;
import org.apache.hc.core5.http.NoHttpResponseException;
import org.apache.hc.core5.http.ProtocolException;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OCSP/CRL fetch hatalarini <b>gecici</b> (retry'a deger) ve <b>kalici</b>
 * (retry yalniz gecikme ekler) olarak ayirir.
 *
 * <h3>Neden?</h3>
 * <p>Onceki surumde {@link RetryExecutor} her {@code RuntimeException}'i
 * gecici sayiyordu. KamuSM test CRL'leri ({@code depo.test3.kamusm.gov.tr})
 * kalici olarak HTTP 400 donuyor; her basarisiz CRL 1 + 2 retry ve
 * ~200ms + ~400ms backoff ile ~0.8-1.0 s suruyordu (ESA ornekleri: 4 CRL,
 * ~3.5 s). 400 bir sonraki denemede de 400'dur.</p>
 *
 * <h3>Kurallar (cause zinciri boyunca, oncelik sirasiyla)</h3>
 * <ol>
 *   <li><b>HTTP status</b> — once tipli {@link UnacceptableHttpStatusException}
 *       ({@link StatusAwareHttpClientResponseHandler}), yoksa DSS mesajindan
 *       parse ("HTTP status code : 400"). 408/425/429 ve 5xx gecici; diger
 *       tum status'lar (4xx, beklenmeyen 1xx/2xx/3xx) kalici.</li>
 *   <li><b>Retry'siz gecici transport</b> — {@link UnknownHostException}
 *       (DNS; JVM negatif DNS cache'i ~10 s ayni sonucu dondurur, saniye-alti
 *       retry zaten ayni hatayi alir). Cozumleyici kesintisi de bu hatayi
 *       verdigi icin kalici sayilmaz
 *       ({@link FailureClassification#transientNoRetry}): yeniden denenmez,
 *       negatif cache'te gecici hata TTL'i ile tutulur.</li>
 *   <li><b>Kalici transport</b> — {@link MalformedURLException},
 *       {@link URISyntaxException}, {@link UnsupportedSchemeException}
 *       (desteklenmeyen protokol), TLS sertifika/hostname dogrulama hatasi,
 *       HTTP protokol hatasi (redirect dongusu vb.), kapatilmis connection
 *       manager.</li>
 *   <li><b>Gecici transport</b> — {@link InterruptedIOException} (read /
 *       connect timeout, havuzdan baglanti kiralama timeout'u),
 *       {@link ConnectException} (baglanti reddi), diger
 *       {@link SocketException}'lar (reset, no route, broken pipe), cevapsiz
 *       / erken kapanan / kesik govdeli baglanti, sertifika disi TLS I/O
 *       hatalari, LDAP iletisim hatalari.</li>
 *   <li><b>OCSP responseStatus</b> — {@code TRY_LATER} ve
 *       {@code INTERNAL_ERROR} gecici; {@code MALFORMED_REQUEST},
 *       {@code SIG_REQUIRED}, {@code UNAUTHORIZED} kalici.</li>
 *   <li><b>Varsayilan: kalici</b> — transport katmaninda bir hata izi
 *       yoksa cevap gelmis ama okunamamis/gecersizdir (bozuk CRL/OCSP,
 *       bos govde, yanlis issuer). Ayni bayt dizisi tekrar parse edilse de
 *       ayni hatayi verir.</li>
 * </ol>
 *
 * <h3>Baglanti reddi (connection refused) neden gecici?</h3>
 * <p>Refused, hedefin <em>o an</em> o portta dinlemedigini soyler — tipik
 * olarak responder / load balancer dugumunun yeniden baslamasi veya
 * Kubernetes servisinin kisa sure hazir endpoint'siz kalmasi; bunlar
 * saniyeler icinde duzelebilir. Retry ucuzdur (red aninda doner, maliyet
 * yalniz ~0.6 s backoff) ve negatif cache sayesinde ayni sertifika icin
 * TTL boyunca en fazla bir kez odenir. Eski surum de refused'u yeniden
 * deniyordu; dogrulama kararlarini degistirmemek icin bu korunur.
 * (DNS hatasi ise yeniden denenmez: JVM negatif DNS cache'i nedeniyle
 * saniye-alti retry ayni sonucu alir; ama cozumleyici kesintisi gecici
 * oldugundan negatif cache'te kisa TTL ile tutulur.)</p>
 *
 * <p>Stateless ve thread-safe.</p>
 */
public final class RevocationFailureClassifier implements FailureClassifier {

    public static final RevocationFailureClassifier INSTANCE = new RevocationFailureClassifier();

    /** Cause zincirinde en fazla bu kadar derine inilir (dongu/pathological zincir korumasi). */
    private static final int MAX_CAUSE_DEPTH = 16;

    /**
     * DSS {@code CommonsHttpClientResponseHandler} mesaji:
     * {@code "Not acceptable HTTP Status (HTTP status code : 400 / reason : Bad Request)"}.
     * DSS bu mesaji ust katmanlarda ("Unable to process GET call ... Reason : [...]",
     * "Unable to retrieve CRL ... Reason : ...") aynen tasir.
     */
    static final Pattern DSS_HTTP_STATUS_MESSAGE =
            Pattern.compile("HTTP status code\\s*:\\s*(\\d{3})(?!\\d)");

    /**
     * DSS {@code OnlineOCSPSource} mesaji:
     * {@code "Ignored OCSP Response from URL '...' : status -> TRY_LATER"}.
     */
    static final Pattern DSS_OCSP_STATUS_MESSAGE =
            Pattern.compile("Ignored OCSP Response from URL .* : status -> ([A-Z_]+)");

    private RevocationFailureClassifier() {
    }

    @Override
    public FailureClassification classify(Throwable failure) {
        if (failure == null) {
            return FailureClassification.permanentFailure("no exception");
        }
        List<Throwable> chain = causeChain(failure);

        // 1) HTTP status — tipli
        for (Throwable t : chain) {
            if (t instanceof UnacceptableHttpStatusException) {
                return byHttpStatus(((UnacceptableHttpStatusException) t).getStatusCode());
            }
        }
        // 1b) HTTP status — DSS mesajindan (stok DSS response handler'i ile kurulmus loader'lar icin)
        for (Throwable t : chain) {
            Integer status = parseHttpStatus(t.getMessage());
            if (status != null) {
                return byHttpStatus(status);
            }
        }

        // 2) Retry edilmeyen transport sinyalleri (kalici + DNS)
        for (Throwable t : chain) {
            FailureClassification permanent = nonRetryableTransport(t);
            if (permanent != null) {
                return permanent;
            }
        }

        // 3) Gecici transport sinyalleri
        for (Throwable t : chain) {
            FailureClassification transientOne = transientTransport(t);
            if (transientOne != null) {
                return transientOne;
            }
        }

        // 4) OCSP responseStatus
        for (Throwable t : chain) {
            String ocspStatus = parseOcspStatus(t.getMessage());
            if (ocspStatus != null) {
                return isRetryableOcspStatus(ocspStatus)
                        ? FailureClassification.transientFailure("OCSP status " + ocspStatus)
                        : FailureClassification.permanentFailure("OCSP status " + ocspStatus);
            }
        }

        // 5) Transport izi yok: cevap geldi ama okunamadi / gecersiz.
        Throwable root = chain.get(chain.size() - 1);
        return FailureClassification.permanentFailure(
                "unreadable or invalid response (" + root.getClass().getSimpleName() + ")");
    }

    /**
     * HTTP status'un gecici olup olmadigi: 408 Request Timeout, 425 Too Early,
     * 429 Too Many Requests ve tum 5xx.
     */
    public static boolean isRetryableHttpStatus(int statusCode) {
        return statusCode == 408 || statusCode == 425 || statusCode == 429
                || (statusCode >= 500 && statusCode <= 599);
    }

    static FailureClassification byHttpStatus(int statusCode) {
        return isRetryableHttpStatus(statusCode)
                ? FailureClassification.transientFailure("HTTP " + statusCode)
                : FailureClassification.permanentFailure("HTTP " + statusCode);
    }

    static Integer parseHttpStatus(String message) {
        if (message == null || message.isEmpty()) {
            return null;
        }
        Matcher m = DSS_HTTP_STATUS_MESSAGE.matcher(message);
        return m.find() ? Integer.valueOf(m.group(1)) : null;
    }

    static String parseOcspStatus(String message) {
        if (message == null || message.isEmpty()) {
            return null;
        }
        Matcher m = DSS_OCSP_STATUS_MESSAGE.matcher(message);
        return m.find() ? m.group(1) : null;
    }

    private static boolean isRetryableOcspStatus(String status) {
        return "TRY_LATER".equals(status) || "INTERNAL_ERROR".equals(status);
    }

    private static FailureClassification nonRetryableTransport(Throwable t) {
        if (t instanceof UnknownHostException) {
            // Retry yok, ama cozumleyici kesintisi de bu hatayi verir: kisa TTL.
            return FailureClassification.transientNoRetry("unknown host (DNS)");
        }
        if (t instanceof MalformedURLException || t instanceof URISyntaxException) {
            return FailureClassification.permanentFailure("malformed URL");
        }
        if (t instanceof UnsupportedSchemeException) {
            return FailureClassification.permanentFailure("unsupported protocol");
        }
        if (t instanceof SSLPeerUnverifiedException) {
            return FailureClassification.permanentFailure("TLS peer not verified");
        }
        if (t instanceof CertificateException
                || t instanceof CertPathValidatorException
                || t instanceof CertPathBuilderException) {
            return FailureClassification.permanentFailure("certificate validation failed ("
                    + t.getClass().getSimpleName() + ")");
        }
        if (t instanceof ClientProtocolException || t instanceof ProtocolException) {
            return FailureClassification.permanentFailure("HTTP protocol error ("
                    + t.getClass().getSimpleName() + ")");
        }
        if (t instanceof ConnectionShutdownException) {
            return FailureClassification.permanentFailure("connection manager shut down");
        }
        return null;
    }

    private static FailureClassification transientTransport(Throwable t) {
        if (t instanceof InterruptedIOException) {
            // SocketTimeoutException (read / connect timed out), hc5 ConnectTimeoutException,
            // ConnectionRequestTimeoutException (havuz lease timeout).
            return FailureClassification.transientFailure("timeout (" + t.getClass().getSimpleName() + ")");
        }
        if (t instanceof ConnectException) {
            return FailureClassification.transientFailure("connection refused");
        }
        if (t instanceof SocketException) {
            return FailureClassification.transientFailure("socket error (" + t.getClass().getSimpleName() + ")");
        }
        if (t instanceof NoHttpResponseException) {
            return FailureClassification.transientFailure("no HTTP response");
        }
        if (t instanceof ConnectionClosedException) {
            return FailureClassification.transientFailure("connection closed prematurely");
        }
        if (t instanceof MalformedChunkCodingException) {
            return FailureClassification.transientFailure("truncated chunked body");
        }
        if (t instanceof SSLException) {
            return FailureClassification.transientFailure("TLS I/O error (" + t.getClass().getSimpleName() + ")");
        }
        if (t instanceof javax.naming.CommunicationException
                || t instanceof javax.naming.ServiceUnavailableException) {
            return FailureClassification.transientFailure("LDAP unavailable (" + t.getClass().getSimpleName() + ")");
        }
        return null;
    }

    private static List<Throwable> causeChain(Throwable failure) {
        List<Throwable> chain = new ArrayList<>();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        Throwable current = failure;
        while (current != null && chain.size() < MAX_CAUSE_DEPTH && seen.add(current)) {
            chain.add(current);
            current = current.getCause();
        }
        return chain;
    }
}
