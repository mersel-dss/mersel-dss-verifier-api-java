package io.mersel.dss.verify.api.services.revocation;

import java.io.IOException;

/**
 * OCSP responder / CRL dagitim noktasi kabul edilmeyen bir HTTP status
 * dondurdugunde firlatilir; status kodunu <b>tipli</b> tasir.
 *
 * <p>DSS'in {@code CommonsHttpClientResponseHandler}'i ayni durumda duz bir
 * {@link IOException} ("Not acceptable HTTP Status (HTTP status code : 400 /
 * reason : Bad Request)") firlatir; status kodu yalniz mesajin icindedir.
 * {@link StatusAwareHttpClientResponseHandler} bu exception'i <em>birebir
 * ayni mesajla</em> uretir — loglar degismez, ama
 * {@link RevocationFailureClassifier} kodu string parse etmeden okur.</p>
 */
public class UnacceptableHttpStatusException extends IOException {

    private static final long serialVersionUID = 1L;

    private final int statusCode;

    public UnacceptableHttpStatusException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
