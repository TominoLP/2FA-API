package de.tomino.utils;

import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageConfig;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.IOException;
import java.io.OutputStream;

public class QRCode extends AbstractQRCode {
    public static final MatrixToImageConfig DEFAULT_CONFIG = new MatrixToImageConfig();
    protected final String text;
    protected MatrixToImageConfig matrixToImageConfig;

    protected QRCode(String text) {
        this.matrixToImageConfig = DEFAULT_CONFIG;
        this.text = text;
        this.qrWriter = new QRCodeWriter();
    }

    public static QRCode from(String text) {
        return new QRCode(text);
    }

    public QRCode withCharset(String charset) {
        return this.withHint(EncodeHintType.CHARACTER_SET, charset);
    }

    public QRCode withHint(EncodeHintType hintType, Object value) {
        this.hints.put(hintType, value);
        return this;
    }

    protected void writeToStream(OutputStream stream) throws IOException, WriterException {
        MatrixToImageWriter.writeToStream(this.createMatrix(this.text), this.imageType, stream, this.matrixToImageConfig);
    }
}
