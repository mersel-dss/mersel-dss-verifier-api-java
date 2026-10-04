package io.mersel.dss.verify.api.services.revocation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Revocation URL'lerini log'a yazmadan once temizler.
 *
 * <p>CRL/OCSP URL'leri sertifikanin icinden gelir (orn.
 * {@code http://depo.kamusm.gov.tr/...crl}); nadiren de olsa
 * {@code scheme://kullanici:sifre@host/...} bicimli kimlik bilgisi
 * tasiyabilir. Log'a yalniz userinfo'su silinmis hali yazilir.</p>
 */
final class RevocationUrls {

    private static final Pattern USER_INFO = Pattern.compile("^([A-Za-z][A-Za-z0-9+.-]*://)[^/?#@]*@");

    private RevocationUrls() {
    }

    static String sanitize(String url) {
        if (url == null) {
            return null;
        }
        return USER_INFO.matcher(url).replaceFirst("$1");
    }

    static List<String> forLog(List<String> urls) {
        if (urls == null || urls.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> out = new ArrayList<>(urls.size());
        for (String url : urls) {
            out.add(sanitize(url));
        }
        return out;
    }
}
