package io.mersel.dss.verify.api.exceptions;

/**
 * İmza doğrulama hatası exception
 */
public class VerificationException extends RuntimeException {
    
    public VerificationException(String message) {
        super(message);
    }

    public VerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}

