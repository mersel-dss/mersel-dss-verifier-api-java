package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Date;

/**
 * Bir sertifikanın iptal (revocation) durumuna dair zengin bilgi modeli.
 *
 * <p>OCSP veya CRL kaynağından elde edilen iptal verisinin operasyonel ve
 * audit gereksinimleri için response'a yansıtılan ayrıntılı kesitidir.
 * Eğer ilgili sertifika için revocation verisi yoksa (örn. çevrimdışı mod
 * veya hiç sorgulanmadıysa) ilgili {@link CertificateInfo#getRevocation()}
 * alanı {@code null} olur — JSON'da görünmez ({@code @JsonInclude(NON_NULL)}).
 *
 * <p>Alanlar:
 * <ul>
 *   <li>{@code source}        — Iptal verisinin türü: {@code OCSP} veya {@code CRL}.</li>
 *   <li>{@code status}        — Sertifika durumu: {@code GOOD}, {@code REVOKED}, {@code UNKNOWN}.</li>
 *   <li>{@code revocationDate} — Sertifikanın iptal edildiği an (yalnız {@code REVOKED} ise).</li>
 *   <li>{@code revocationReason} — RFC 5280 iptal nedeni metni (örn. {@code keyCompromise}).</li>
 *   <li>{@code producedAt}    — Iptal token'ının (OCSP response veya CRL) üretilme zamanı.</li>
 *   <li>{@code thisUpdate}    — Token'ın temsil ettiği bilginin geçerli olduğu başlangıç anı.</li>
 *   <li>{@code nextUpdate}    — Bir sonraki güncellemenin beklendiği an (cache TTL ile uyumlu).</li>
 *   <li>{@code responderUrl}  — Bilginin elde edildiği responder/dağıtım noktası adresi (audit).</li>
 *   <li>{@code origin}        — Kaynak menşei: {@code EXTERNAL} (canlı sorgu), {@code CACHED},
 *       {@code CMS_SIGNED_DATA}, {@code REVOCATION_VALUES}, {@code TIMESTAMP_VALIDATION_DATA}, vb.
 *       LT-level imzalarda token genellikle imzanın içinde gömülü gelir (örn.
 *       {@code REVOCATION_VALUES}); bu durumda canlı bir OCSP/CRL çağrısı yapılmamış demektir.</li>
 * </ul>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RevocationInfo {

    private String source;
    private String status;
    private Date revocationDate;
    private String revocationReason;
    private Date producedAt;
    private Date thisUpdate;
    private Date nextUpdate;
    private String responderUrl;
    private String origin;

    public RevocationInfo() {
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Date getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    public String getRevocationReason() {
        return revocationReason;
    }

    public void setRevocationReason(String revocationReason) {
        this.revocationReason = revocationReason;
    }

    public Date getProducedAt() {
        return producedAt;
    }

    public void setProducedAt(Date producedAt) {
        this.producedAt = producedAt;
    }

    public Date getThisUpdate() {
        return thisUpdate;
    }

    public void setThisUpdate(Date thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    public Date getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(Date nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public String getResponderUrl() {
        return responderUrl;
    }

    public void setResponderUrl(String responderUrl) {
        this.responderUrl = responderUrl;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }
}
