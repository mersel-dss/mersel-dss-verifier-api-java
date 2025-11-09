package io.mersel.dss.verify.api.exceptions;

/**
 * Geçersiz doküman hatası exception
 */
public class InvalidDocumentException extends RuntimeException {
    
    public InvalidDocumentException(String message) {
        super(message);
    }

    public InvalidDocumentException(String message, Throwable cause) {
        super(message, cause);
    }
}

