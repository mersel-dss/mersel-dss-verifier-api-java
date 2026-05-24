package io.mersel.dss.verify.api.services.revocation;

/**
 * {@link Thread#sleep(long)} abstraction'i — {@link RetryExecutor}'in
 * deterministik test edilmesini saglar.
 *
 * <p>Production'da {@link #threadSleep()} kullanilir; testte ge&ccedil;en
 * sure'leri kaydeden bir mock {@code Sleeper} ile gercek sleep'siz davranis
 * dogrulanabilir.</p>
 *
 * <p>InterruptedException expose ediyoruz: caller'in thread interrupt
 * davranisini agresif sekilde handle etmesi gerekir (RetryExecutor
 * interrupt flag'i restore edip retry'i sonlandirir).</p>
 */
@FunctionalInterface
public interface Sleeper {

    void sleep(long millis) throws InterruptedException;

    static Sleeper threadSleep() {
        return Thread::sleep;
    }
}
