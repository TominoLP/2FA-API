package de.tomino;

import org.apache.commons.codec.binary.Base32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class AuthSysTest {

    private static final int DEFAULT_DRIFT_SECONDS = 120; // +/- 2 minutes
    private static final int AUTH_SYS_TIME_STEP_SECONDS = 30;
    private String testSecret;

    // Helper method to generate AuthSys TOTP code for a specific time (epoch seconds)
    private String generateAuthCodeForTimestamp(String secret, long epochSeconds) {
        final Base32 base32 = new Base32();
        byte[] decodedKey = base32.decode(secret);
        long timeStep = epochSeconds / AUTH_SYS_TIME_STEP_SECONDS;
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (timeStep & 0xff);
            timeStep >>= 8;
        }
        final SecretKeySpec signingKey = new SecretKeySpec(decodedKey, "HmacSHA1");
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

        int digits = 6;
        int mod = (int) Math.pow(10, digits);
        return String.format("%0" + digits + "d", value % mod); // Ensure leading zeros
    }

    @BeforeEach
    void setUp() {
        testSecret = AuthSys.generateSecretKey();
        assertNotNull(testSecret, "Test secret should not be null");
    }

    @Test
    void validateCode_NoDrift_CurrentCode_ShouldBeValid() {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        String currentCode = generateAuthCodeForTimestamp(testSecret, currentTimeSeconds);
        assertNotNull(currentCode, "Current code should be generated");
        assertTrue(AuthSys.validateCode(testSecret, currentCode, 0), "Current code should be valid with no drift.");
    }

    @Test
    void validateCode_NoDrift_CodeFromPast_ShouldBeInvalid() {
        long pastTimeSeconds = Instant.now().getEpochSecond() - (AUTH_SYS_TIME_STEP_SECONDS + 1);
        String pastCode = generateAuthCodeForTimestamp(testSecret, pastTimeSeconds);
        assertNotNull(pastCode, "Past code should be generated");
        assertFalse(AuthSys.validateCode(testSecret, pastCode, 0), "Past code should be invalid with no drift.");
    }
    
    @Test
    void validateCode_NoDrift_CodeFromFuture_ShouldBeInvalid() {
        long futureTimeSeconds = Instant.now().getEpochSecond() + (AUTH_SYS_TIME_STEP_SECONDS + 1);
        String futureCode = generateAuthCodeForTimestamp(testSecret, futureTimeSeconds);
        assertNotNull(futureCode, "Future code should be generated");
        assertFalse(AuthSys.validateCode(testSecret, futureCode, 0), "Future code should be invalid with no drift.");
    }

    @Test
    void validateCode_WithDrift_CurrentCode_ShouldBeValid() {
        long currentTimeSeconds = Instant.now().getEpochSecond();
        String currentCode = generateAuthCodeForTimestamp(testSecret, currentTimeSeconds);
        assertNotNull(currentCode);
        assertTrue(AuthSys.validateCode(testSecret, currentCode, DEFAULT_DRIFT_SECONDS), "Current code should be valid with drift.");
    }

    @Test
    void validateCode_WithDrift_CodeFromNearPast_WithinDrift_ShouldBeValid() {
        long nearPastTimeSeconds = Instant.now().getEpochSecond() - (DEFAULT_DRIFT_SECONDS / 2); // e.g. 60s ago
        String pastCode = generateAuthCodeForTimestamp(testSecret, nearPastTimeSeconds);
        assertNotNull(pastCode);
        assertTrue(AuthSys.validateCode(testSecret, pastCode, DEFAULT_DRIFT_SECONDS), "Code from near past within drift should be valid.");
    }
    
    @Test
    void validateCode_WithDrift_CodeFromNearFuture_WithinDrift_ShouldBeValid() {
        long nearFutureTimeSeconds = Instant.now().getEpochSecond() + (DEFAULT_DRIFT_SECONDS / 2); // e.g. 60s in future
        String futureCode = generateAuthCodeForTimestamp(testSecret, nearFutureTimeSeconds);
        assertNotNull(futureCode);
        assertTrue(AuthSys.validateCode(testSecret, futureCode, DEFAULT_DRIFT_SECONDS), "Code from near future within drift should be valid.");
    }

    @Test
    void validateCode_WithDrift_CodeFromFarPast_OutsideDrift_ShouldBeInvalid() {
        long farPastTimeSeconds = Instant.now().getEpochSecond() - (DEFAULT_DRIFT_SECONDS + AUTH_SYS_TIME_STEP_SECONDS); // e.g. 120s + 30s = 150s ago
        String farPastCode = generateAuthCodeForTimestamp(testSecret, farPastTimeSeconds);
        assertNotNull(farPastCode);
        assertFalse(AuthSys.validateCode(testSecret, farPastCode, DEFAULT_DRIFT_SECONDS), "Code from far past outside drift should be invalid.");
    }
    
    @Test
    void validateCode_WithDrift_CodeFromFarFuture_OutsideDrift_ShouldBeInvalid() {
        long farFutureTimeSeconds = Instant.now().getEpochSecond() + (DEFAULT_DRIFT_SECONDS + AUTH_SYS_TIME_STEP_SECONDS); // e.g. 120s + 30s = 150s in future
        String farFutureCode = generateAuthCodeForTimestamp(testSecret, farFutureTimeSeconds);
        assertNotNull(farFutureCode);
        assertFalse(AuthSys.validateCode(testSecret, farFutureCode, DEFAULT_DRIFT_SECONDS), "Code from far future outside drift should be invalid.");
    }

    @Test
    void validateCode_WithDrift_CodeAtPastDriftBoundary_ShouldBeValid() {
        long boundaryPastTimeSeconds = Instant.now().getEpochSecond() - DEFAULT_DRIFT_SECONDS;
        String boundaryPastCode = generateAuthCodeForTimestamp(testSecret, boundaryPastTimeSeconds);
        assertNotNull(boundaryPastCode);
        assertTrue(AuthSys.validateCode(testSecret, boundaryPastCode, DEFAULT_DRIFT_SECONDS), "Code at past drift boundary should be valid.");
    }

    @Test
    void validateCode_WithDrift_CodeAtFutureDriftBoundary_ShouldBeValid() {
        long boundaryFutureTimeSeconds = Instant.now().getEpochSecond() + DEFAULT_DRIFT_SECONDS;
        String boundaryFutureCode = generateAuthCodeForTimestamp(testSecret, boundaryFutureTimeSeconds);
        assertNotNull(boundaryFutureCode);
        assertTrue(AuthSys.validateCode(testSecret, boundaryFutureCode, DEFAULT_DRIFT_SECONDS), "Code at future drift boundary should be valid.");
    }
    
    @Test
    void validateCode_WithDrift_CodeJustOutsidePastDriftBoundary_ShouldBeInvalid() {
        long justOutsidePastTimeSeconds = Instant.now().getEpochSecond() - DEFAULT_DRIFT_SECONDS - AUTH_SYS_TIME_STEP_SECONDS;
        String justOutsidePastCode = generateAuthCodeForTimestamp(testSecret, justOutsidePastTimeSeconds);
        assertNotNull(justOutsidePastCode);
        assertFalse(AuthSys.validateCode(testSecret, justOutsidePastCode, DEFAULT_DRIFT_SECONDS), "Code just outside past drift boundary should be invalid.");
    }

    @Test
    void validateCode_WithDrift_CodeJustOutsideFutureDriftBoundary_ShouldBeInvalid() {
        long justOutsideFutureTimeSeconds = Instant.now().getEpochSecond() + DEFAULT_DRIFT_SECONDS + AUTH_SYS_TIME_STEP_SECONDS;
        String justOutsideFutureCode = generateAuthCodeForTimestamp(testSecret, justOutsideFutureTimeSeconds);
        assertNotNull(justOutsideFutureCode);
        assertFalse(AuthSys.validateCode(testSecret, justOutsideFutureCode, DEFAULT_DRIFT_SECONDS), "Code just outside future drift boundary should be invalid.");
    }
}
