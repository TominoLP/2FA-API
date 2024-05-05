package de.tomino;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@SuppressWarnings("unused")
public class TOTP {
    private static HashMap<String, Long> timeMap = new HashMap<>();

    public static Map<String, String> generateCode(long durationInSeconds) {
        HashMap<String, String> secretKeys = new HashMap<>();

        String secret = AuthSys.generateSecretKey();

        long timestamp = Instant.now().toEpochMilli() / (durationInSeconds * 1000);
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
        }

        if (mac == null) return null;
        byte[] hash = mac.doFinal(data);
        int offset = hash[hash.length - 1] & 0xf;
        int value = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int mod = (int) Math.pow(10, 6);
        int code = value % mod;
        secretKeys.put(secret, String.valueOf(code));
        timeMap.put(secret, durationInSeconds * 1000);
        return secretKeys;
    }

    public static boolean validateTOTPCode(String secret, String code) {
        final long durationInMillis = TOTP.timeMap.get(secret);
        long timestamp = Instant.now().toEpochMilli() / durationInMillis;
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
        }

        if (mac == null) return false;
        byte[] hash = mac.doFinal(data);
        int offset = hash[hash.length - 1] & 0xf;
        int value = ((hash[offset] & 0x7f) << 24) |
                ((hash[offset + 1] & 0xff) << 16) |
                ((hash[offset + 2] & 0xff) << 8) |
                (hash[offset + 3] & 0xff);

        int mod = (int) Math.pow(10, 6);
        int expectedCode = value % mod;

        return expectedCode == Integer.parseInt(code);
    }

    public static Date getExpirationDate(String secret) {
        long durationInMillis = timeMap.get(secret);
        long timestamp = Instant.now().toEpochMilli() / durationInMillis;
        long expirationTime = timestamp * durationInMillis + durationInMillis;
        return new Date(expirationTime);
    }

}
