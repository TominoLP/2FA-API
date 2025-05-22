package de.tomino;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class TOTPTest {

    private static final long TEST_DURATION_SECONDS = 60;
    private static final int DEFAULT_DRIFT_SECONDS = 120; // +/- 2 minutes
    private String testSecret;
    private String initialCode;

    // Helper method to generate TOTP code for a specific time (millis)
    private String generateCodeForTimestamp(String secret, long timeMillis, long durationSeconds) {
        long timestamp = timeMillis / (durationSeconds * 1000);
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (timestamp & 0xff);
            timestamp >>= 8;
        }
        final SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), "HmacSHA1");
        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(signingKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException exception) {
            exception.printStackTrace();
            return null;
        }

        if (mac == null) return null;
        byte[] hash = mac.doFinal(data);
        int offset = hash[hash.length - 1] & 0xf;
        int value = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int mod = (int) Math.pow(10, 6);
        return String.valueOf(value % mod);
    }

    @BeforeEach
    void setUp() {
        // This call is important to populate timeMap in TOTP class for the testSecret
        Map<String, String> secretMap = TOTP.generateCode(TEST_DURATION_SECONDS);
        assertNotNull(secretMap, "Secret map should not be null");
        assertFalse(secretMap.isEmpty(), "Secret map should not be empty");
        testSecret = secretMap.keySet().iterator().next();
        initialCode = secretMap.get(testSecret);
        assertNotNull(testSecret, "Test secret should not be null");
        assertNotNull(initialCode, "Initial code should not be null");
    }

    @Test
    void validateCode_NoDrift_CurrentCode_ShouldBeValid() {
        assertTrue(TOTP.validateTOTPCode(testSecret, initialCode, 0), "Current code should be valid with no drift.");
    }

    @Test
    void validateCode_NoDrift_CodeFromPast_ShouldBeInvalid() throws InterruptedException {
        // Generate a code for a time clearly in the past (e.g., TEST_DURATION_SECONDS + 1 second ago)
        long pastTimeMillis = Instant.now().toEpochMilli() - ((TEST_DURATION_SECONDS + 1) * 1000);
        String pastCode = generateCodeForTimestamp(testSecret, pastTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(pastCode, "Past code should be generated");
        assertFalse(TOTP.validateTOTPCode(testSecret, pastCode, 0), "Past code should be invalid with no drift.");
    }
    
    @Test
    void validateCode_NoDrift_CodeFromFuture_ShouldBeInvalid() {
        // Generate a code for a time clearly in the future (e.g., TEST_DURATION_SECONDS + 1 second from now)
        long futureTimeMillis = Instant.now().toEpochMilli() + ((TEST_DURATION_SECONDS + 1) * 1000);
        String futureCode = generateCodeForTimestamp(testSecret, futureTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(futureCode, "Future code should be generated");
        assertFalse(TOTP.validateTOTPCode(testSecret, futureCode, 0), "Future code should be invalid with no drift.");
    }


    @Test
    void validateCode_WithDrift_CurrentCode_ShouldBeValid() {
        assertTrue(TOTP.validateTOTPCode(testSecret, initialCode, DEFAULT_DRIFT_SECONDS), "Current code should be valid with drift.");
    }

    @Test
    void validateCode_WithDrift_CodeFromNearPast_WithinDrift_ShouldBeValid() {
        long nearPastTimeMillis = Instant.now().toEpochMilli() - (DEFAULT_DRIFT_SECONDS / 2 * 1000); // e.g. 60s ago
        String pastCode = generateCodeForTimestamp(testSecret, nearPastTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(pastCode);
        assertTrue(TOTP.validateTOTPCode(testSecret, pastCode, DEFAULT_DRIFT_SECONDS), "Code from near past within drift should be valid.");
    }
    
    @Test
    void validateCode_WithDrift_CodeFromNearFuture_WithinDrift_ShouldBeValid() {
        long nearFutureTimeMillis = Instant.now().toEpochMilli() + (DEFAULT_DRIFT_SECONDS / 2 * 1000); // e.g. 60s in future
        String futureCode = generateCodeForTimestamp(testSecret, nearFutureTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(futureCode);
        assertTrue(TOTP.validateTOTPCode(testSecret, futureCode, DEFAULT_DRIFT_SECONDS), "Code from near future within drift should be valid.");
    }

    @Test
    void validateCode_WithDrift_CodeFromFarPast_OutsideDrift_ShouldBeInvalid() {
        long farPastTimeMillis = Instant.now().toEpochMilli() - ((DEFAULT_DRIFT_SECONDS + TEST_DURATION_SECONDS) * 1000); // e.g. 120s + 60s = 180s ago
        String farPastCode = generateCodeForTimestamp(testSecret, farPastTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(farPastCode);
        assertFalse(TOTP.validateTOTPCode(testSecret, farPastCode, DEFAULT_DRIFT_SECONDS), "Code from far past outside drift should be invalid.");
    }
    
    @Test
    void validateCode_WithDrift_CodeFromFarFuture_OutsideDrift_ShouldBeInvalid() {
        long farFutureTimeMillis = Instant.now().toEpochMilli() + ((DEFAULT_DRIFT_SECONDS + TEST_DURATION_SECONDS) * 1000); // e.g. 120s + 60s = 180s in future
        String farFutureCode = generateCodeForTimestamp(testSecret, farFutureTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(farFutureCode);
        assertFalse(TOTP.validateTOTPCode(testSecret, farFutureCode, DEFAULT_DRIFT_SECONDS), "Code from far future outside drift should be invalid.");
    }

    @Test
    void validateCode_WithDrift_CodeAtPastDriftBoundary_ShouldBeValid() {
        // Time is current - drift. This should be the earliest valid time.
        long boundaryPastTimeMillis = Instant.now().toEpochMilli() - (DEFAULT_DRIFT_SECONDS * 1000L);
        String boundaryPastCode = generateCodeForTimestamp(testSecret, boundaryPastTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(boundaryPastCode);
        assertTrue(TOTP.validateTOTPCode(testSecret, boundaryPastCode, DEFAULT_DRIFT_SECONDS), "Code at past drift boundary should be valid.");
    }

    @Test
    void validateCode_WithDrift_CodeAtFutureDriftBoundary_ShouldBeValid() {
        // Time is current + drift. This should be the latest valid time.
        long boundaryFutureTimeMillis = Instant.now().toEpochMilli() + (DEFAULT_DRIFT_SECONDS * 1000L);
        String boundaryFutureCode = generateCodeForTimestamp(testSecret, boundaryFutureTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(boundaryFutureCode);
        assertTrue(TOTP.validateTOTPCode(testSecret, boundaryFutureCode, DEFAULT_DRIFT_SECONDS), "Code at future drift boundary should be valid.");
    }
    
    @Test
    void validateCode_WithDrift_CodeJustOutsidePastDriftBoundary_ShouldBeInvalid() {
        // Time is current - drift - duration. This should be just outside the earliest valid time.
        long justOutsidePastTimeMillis = Instant.now().toEpochMilli() - (DEFAULT_DRIFT_SECONDS * 1000L) - (TEST_DURATION_SECONDS * 1000L) ;
        String justOutsidePastCode = generateCodeForTimestamp(testSecret, justOutsidePastTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(justOutsidePastCode);
        assertFalse(TOTP.validateTOTPCode(testSecret, justOutsidePastCode, DEFAULT_DRIFT_SECONDS), "Code just outside past drift boundary should be invalid.");
    }

    @Test
    void validateCode_WithDrift_CodeJustOutsideFutureDriftBoundary_ShouldBeInvalid() {
        // Time is current + drift + duration. This should be just outside the latest valid time.
        long justOutsideFutureTimeMillis = Instant.now().toEpochMilli() + (DEFAULT_DRIFT_SECONDS * 1000L) + (TEST_DURATION_SECONDS * 1000L);
        String justOutsideFutureCode = generateCodeForTimestamp(testSecret, justOutsideFutureTimeMillis, TEST_DURATION_SECONDS);
        assertNotNull(justOutsideFutureCode);
        assertFalse(TOTP.validateTOTPCode(testSecret, justOutsideFutureCode, DEFAULT_DRIFT_SECONDS), "Code just outside future drift boundary should be invalid.");
    }
}
