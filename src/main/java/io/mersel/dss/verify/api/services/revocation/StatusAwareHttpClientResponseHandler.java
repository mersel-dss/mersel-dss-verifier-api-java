package io.mersel.dss.verify.api.services.revocation;

import eu.europa.esig.dss.service.http.commons.CommonsHttpClientResponseHandler;
import org.apache.hc.core5.http.ClassicHttpResponse;

import java.io.IOException;

/**
 * DSS {@link CommonsHttpClientResponseHandler}'inin davranisini <b>aynen</b>
 * koruyan, tek farki kabul edilmeyen HTTP status'u tipli bir
 * {@link UnacceptableHttpStatusException} ile bildirmesi olan response
 * handler.
 *
 * <ul>
 *   <li>Kabul edilen status'lar, body okuma, bos-entity kontrolu ve
 *       response kapatma tamamen DSS'e birakilir ({@code super}).</li>
 *   <li>Exception mesaji DSS'inkiyle birebir aynidir; yalniz tipi
 *       {@link IOException}'in alt sinifidir. DSS ust katmanlari
 *       ({@code CommonsDataLoader}, {@code OnlineCRLSource},
 *       {@code OnlineOCSPSource}) ayni sekilde sarar.</li>
 * </ul>
 *
 * <p>{@code RevocationServicesConfiguration} bu handler'i yalniz OCSP ve CRL
 * DataLoader'larina takar; fetch edilen icerik ve zamanlama degismez.</p>
 */
public class StatusAwareHttpClientResponseHandler extends CommonsHttpClientResponseHandler {

    @Override
    public byte[] handleResponse(ClassicHttpResponse response) throws IOException {
        final int statusCode = response.getCode();
        try {
            return super.handleResponse(response);
        } catch (UnacceptableHttpStatusException e) {
            throw e;
        } catch (IOException e) {
            if (!getAcceptedHttpStatuses().contains(statusCode)) {
                throw new UnacceptableHttpStatusException(statusCode, e.getMessage());
            }
            throw e;
        }
    }
}
