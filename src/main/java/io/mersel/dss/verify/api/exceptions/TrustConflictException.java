package io.mersel.dss.verify.api.exceptions;
public class TrustConflictException extends RuntimeException {
    public TrustConflictException() { super("Etkin kök kümesi değişti veya backend yeniden başladı. Etkin kümeyi yenileyip tekrar deneyin."); }
}
