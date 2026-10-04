package io.mersel.dss.verify.api.models;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * Bir imza doğrulamasında kullanılan doğrulama politikası. Doğrulamanın başında alınan
 * snapshot'tan üretilir; aynı istek sırasında yapılan etkinleştirme bu değerleri değiştirmez.
 */
@JsonPropertyOrder({"policyId", "profile", "source", "name", "sha256"})
public class PolicyContext {
    private final String policyId;
    private final String profile;
    private final String source;
    private final String name;
    private final String sha256;

    public PolicyContext(String policyId, String profile, String source, String name, String sha256) {
        this.policyId = policyId; this.profile = profile; this.source = source; this.name = name; this.sha256 = sha256;
    }

    /** Sunucu örneğine özgü revizyon kimliği; her etkinleştirmede ve her yeniden başlatmada değişir. */
    public String getPolicyId() { return policyId; }
    /** {@code signer-strict}, {@code strict} veya {@code custom}. */
    public String getProfile() { return profile; }
    /** {@code BUILT_IN} veya {@code CUSTOM_XML}. */
    public String getSource() { return source; }
    public String getName() { return name; }
    /** Etkin politika XML byte'larının küçük harfli hex SHA-256 özeti. */
    public String getSha256() { return sha256; }
}
