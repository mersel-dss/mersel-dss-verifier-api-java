package io.mersel.dss.verify.api.exceptions;

/**
 * Zaman damgası hatası exception
 */
public class TimestampException extends RuntimeException {
    
    public TimestampException(String message) {
        super(message);
    }

    public TimestampException(String message, Throwable cause) {
        super(message, cause);
    }
}

