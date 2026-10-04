package io.mersel.dss.verify.api.services.revocation;

/**
 * Bir hatanin gecici mi kalici mi oldugunu soyler — {@link RetryExecutor}
 * retry kararini, {@link RevocationFailureCache} negatif-cache suresini
 * buna gore verir.
 *
 * <p>Revocation akisinin uretim siniflandiricisi
 * {@link RevocationFailureClassifier#INSTANCE}'dir.</p>
 */
@FunctionalInterface
public interface FailureClassifier {

    /**
     * @param failure siniflandirilacak hata (cause zinciri dahil incelenir)
     * @return asla {@code null} degil
     */
    FailureClassification classify(Throwable failure);

    /**
     * Her hatayi gecici sayan siniflandirici — {@link RetryExecutor}'in
     * genel amacli (revocation'a ozgu olmayan) varsayilan davranisi.
     */
    static FailureClassifier retryAll() {
        return failure -> FailureClassification.transientFailure("unclassified");
    }
}
