package io.mersel.dss.verify.api.services.revocation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Ayni anahtar icin eszamanli fetch'leri tek bir gercek cagriya indirger
 * ("single-flight"). Ilk gelen thread (lider) {@code loader}'i calistirir;
 * o surede ayni anahtarla gelen thread'ler liderin sonucunu bekler ve
 * <em>ayni</em> degeri alir. Lider bitince anahtar serbest kalir.
 *
 * <ul>
 *   <li>Lider {@code loader} icinde exception/Error alirsa bekleyenler
 *       {@code null} alir (basarisiz fetch'in revocation akisindaki
 *       karsiligi); exception yalniz liderin cagiranina yukselir.</li>
 *   <li>Bekleme kesintisizdir ({@link CompletableFuture#join()}); suresi
 *       liderin fetch suresiyle (HTTP timeout'lari x attempt) sinirlidir —
 *       bekleyen thread kendi fetch'ini yapsaydi da en az o kadar beklerdi.</li>
 *   <li>Caffeine {@code cache.get(key, loader)}'in aksine hash-bin kilidi
 *       tutmaz: uzun suren ag cagrisi baska anahtarlari bloklamaz.</li>
 * </ul>
 *
 * <p>Thread-safe.</p>
 *
 * @param <T> fetch sonucunun tipi
 */
final class SingleFlight<T> {

    private static final Logger logger = LoggerFactory.getLogger(SingleFlight.class);

    private final String label;
    private final ConcurrentHashMap<String, CompletableFuture<T>> inFlight = new ConcurrentHashMap<>();

    SingleFlight(String label) {
        this.label = Objects.requireNonNull(label, "label must not be null");
    }

    T execute(String key, Supplier<T> loader) {
        CompletableFuture<T> mine = new CompletableFuture<>();
        CompletableFuture<T> leader = inFlight.putIfAbsent(key, mine);
        if (leader != null) {
            logger.debug("{} fetch already in flight for key '{}' — waiting for its result", label, key);
            try {
                return leader.join();
            } catch (CompletionException | CancellationException e) {
                return null;
            }
        }
        T result = null;
        try {
            result = loader.get();
            return result;
        } finally {
            inFlight.remove(key, mine);
            mine.complete(result);
        }
    }

    /** Test/diagnostic: su an devam eden fetch sayisi. */
    int inFlightCount() {
        return inFlight.size();
    }
}
