package de.tomino.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.Writer;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;

import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;

public abstract class AbstractQRCode {
    protected final HashMap<EncodeHintType, Object> hints = new HashMap<>();
    protected Writer qrWriter;
    protected int width = 125;
    protected int height = 125;
    protected String imageType;

    public AbstractQRCode() {
        this.imageType = "PNG";
    }

    public void writeTo(OutputStream stream) {
        try {
            this.writeToStream(stream);
        } catch (Exception var3) {
            try {
                throw new Exception("Failed to create QR image from text due to underlying exception", var3);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    protected abstract void writeToStream(OutputStream var1) throws IOException, WriterException;

    public BitMatrix createMatrix(String text) throws WriterException {
        return this.qrWriter.encode(text, BarcodeFormat.QR_CODE, this.width, this.height, this.hints);
    }
}
