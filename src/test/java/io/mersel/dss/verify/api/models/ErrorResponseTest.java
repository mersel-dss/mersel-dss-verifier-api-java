package io.mersel.dss.verify.api.models;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ErrorResponse test'leri.
 */
class ErrorResponseTest {

    @Test
    void testErrorResponseCreation() {
        // Given
        String error = "TEST_ERROR";
        String message = "Test error message";

        // When
        ErrorResponse errorResponse = new ErrorResponse(error, message);

        // Then
        assertNotNull(errorResponse);
        assertEquals(error, errorResponse.getError());
        assertEquals(message, errorResponse.getMessage());
        assertNotNull(errorResponse.getTimestamp());
    }

    @Test
    void testErrorResponseWithDetails() {
        // Given
        String error = "TEST_ERROR";
        String message = "Test error message";
        String details = "Detailed error information";

        // When
        ErrorResponse errorResponse = new ErrorResponse(error, message, details);

        // Then
        assertNotNull(errorResponse);
        assertEquals(error, errorResponse.getError());
        assertEquals(message, errorResponse.getMessage());
        assertEquals(details, errorResponse.getDetails());
        assertNotNull(errorResponse.getTimestamp());
    }

    @Test
    void testErrorResponseDefaultConstructor() {
        // When
        ErrorResponse errorResponse = new ErrorResponse();

        // Then
        assertNotNull(errorResponse);
        assertNotNull(errorResponse.getTimestamp());
    }

    @Test
    void testErrorResponseSetters() {
        // Given
        ErrorResponse errorResponse = new ErrorResponse("ERROR1", "Message1");

        // When
        errorResponse.setError("ERROR2");
        errorResponse.setMessage("Message2");
        errorResponse.setDetails("Details2");
        errorResponse.setPath("/api/v1/test");
        Date customTimestamp = new Date();
        errorResponse.setTimestamp(customTimestamp);

        // Then
        assertEquals("ERROR2", errorResponse.getError());
        assertEquals("Message2", errorResponse.getMessage());
        assertEquals("Details2", errorResponse.getDetails());
        assertEquals("/api/v1/test", errorResponse.getPath());
        assertEquals(customTimestamp, errorResponse.getTimestamp());
    }

    @Test
    void testErrorResponseTimestampAutoSet() {
        // Given
        Date beforeCreation = new Date();

        // When
        ErrorResponse errorResponse = new ErrorResponse("ERROR", "Message");
        Date afterCreation = new Date();

        // Then
        assertNotNull(errorResponse.getTimestamp());
        assertTrue(errorResponse.getTimestamp().getTime() >= beforeCreation.getTime());
        assertTrue(errorResponse.getTimestamp().getTime() <= afterCreation.getTime());
    }
}

