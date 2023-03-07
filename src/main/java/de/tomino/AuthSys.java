package de.tomino;
/*
 * Copyright 2023 Tom Werth
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import net.glxn.qrgen.javase.QRCode;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * A class that contains all the methods to generate a QR code and validate the code
 *
 * @author TominoLP / Tomino#0101
 * @version 1.2
 */
@SuppressWarnings("unused")
public class AuthSys {

    static final SecureRandom random = new SecureRandom();

    /**
     * Generates a random Security Key
     *
     * @return the Security Key as a String
     */
    public static String generateSecretKey() {
        byte[] bytes = new byte[20];
        AuthSys.random.nextBytes(bytes);
        final Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    /**
     * Validate the code to check if it is valid
     *
     * @param secret The secret key
     * @param code   The code that should be validated
     * @return True if the code is valid
     */
    public static boolean validateCode(String secret, String code) {
        final Base32 base32 = new Base32();
        byte[] decodedKey = base32.decode(secret);
        long time = Instant.now().getEpochSecond() / 30;
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) (time & 0xff);
            time >>= 8;
        }
        final SecretKeySpec signingKey = new SecretKeySpec(decodedKey, "HmacSHA1");
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

        int digits = 6;
        int mod = (int) Math.pow(10, digits);
        return value % mod == Integer.parseInt(code);
    }

    /**
     * Validate the code to check if it is valid
     *
     * @param secret The secret key
     * @param code   The code that should be validated
     * @return True if the code is valid
     */
    public static boolean validateTOTPCode(String secret, String code) {
        final long durationInSeconds = TOTP.timeMap.get(secret);
        long timestamp = Instant.now().getEpochSecond() / durationInSeconds;
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

    /**
     * Generate the QR code from the data as a BufferedImage
     *
     * @param secretKey The secret key
     * @param issuer    The issuer
     * @param account   The account name
     * @return The generated BufferedImage
     * @see BufferedImage
     */
    public static BufferedImage generateQrCodeData(String secretKey, String issuer, String account) {
        Image image = generateQrCode(secretKey, issuer, account);
        final BufferedImage imageData = new BufferedImage(128, 128, BufferedImage.TYPE_INT_ARGB_PRE);
        final Graphics graphics = imageData.getGraphics();
        graphics.drawImage(image, 0, 0, 128, 128, null);
        graphics.dispose();

        return imageData;
    }

    /**
     * Generate the QR code from the data as an Image
     *
     * @param secretKey The secret key
     * @param issuer    The issuer
     * @param account   The account name
     * @return The generated Image
     * @see Image
     */
    public static Image generateQrCode(String secretKey, String issuer, String account) {
        final String data = "otpauth://totp/" + account + "?secret=" + secretKey
                + "&issuer=" + issuer + "&algorithm=SHA1&digits=6&period=30";
        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        QRCode.from(data).withCharset("UTF-8").writeTo(stream);

        final InputStream is = new ByteArrayInputStream(stream.toByteArray());
        Image image = null;
        try {
            image = ImageIO.read(is);
        } catch (IOException exception) {
            exception.printStackTrace();
        }
        return image;

    }

    /**
     * Generate the QR code as an Image
     *
     * @param image The image that should be saved
     * @param fileFormat The file format of the image
     * @param path The path where the image should be saved
     * @see Image
     */
    public static void saveImage(Image image, String fileFormat, File path) {
        int width = image.getWidth(null);
        int height = image.getHeight(null);
        BufferedImage bi = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
        Graphics g = bi.getGraphics();
        try {
            g.drawImage(image, 0, 0, null);
            ImageIO.write(bi, fileFormat, path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generate the QR code from the data as an Image
     *
     * @param image The image that should be saved
     * @param fileFormat The file format of the image
     * @param path The path where the image should be saved
     * @see Image
     */
    public static void saveImage(BufferedImage image, String fileFormat, File path) {
        int width = image.getWidth(null);
        int height = image.getHeight(null);
        BufferedImage bi = new BufferedImage(width, height, BufferedImage.TYPE_3BYTE_BGR);
        Graphics g = bi.getGraphics();
        try {
            g.drawImage(image, 0, 0, null);
            ImageIO.write(bi, fileFormat, path);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     * Generate the link to the QR code
     *
     * @param secretKey The secret key
     * @param issuer    The issuer
     * @param account   The account name
     * @return The generated link
     */
    public static String generateLink(String secretKey, String issuer, String account) {
        return "otpauth://totp/" + account + "?secret=" + secretKey
                + "&issuer=" + issuer + "&algorithm=SHA1&digits=6&period=30";
    }

}