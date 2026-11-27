package dev.proxyroute;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.EncodeHintType;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.ReaderException;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.util.Map;

final class ShareQr {
    private static final int MODULE_PIXELS = 8;
    private static final int QUIET_MODULES = 4;

    static Bitmap render(String link, Drawable logo) throws WriterException {
        QRCodeWriter writer = new QRCodeWriter();
        Bitmap best = null;
        for (ErrorCorrectionLevel level : new ErrorCorrectionLevel[]{ErrorCorrectionLevel.Q, ErrorCorrectionLevel.M, ErrorCorrectionLevel.L}) {
            BitMatrix matrix;
            try { matrix = encode(writer, link, level); }
            catch (WriterException e) { continue; }
            for (float radius : new float[]{4f, 3f, 2.5f}) {
                Bitmap candidate = draw(matrix, logo, radius * MODULE_PIXELS);
                if (!scans(candidate, link, 640)) {
                    candidate.recycle();
                    continue;
                }
                if (scans(candidate, link, 320)) {
                    if (best != null) best.recycle();
                    return candidate;
                }
                if (best == null) best = candidate;
                else candidate.recycle();
            }
        }
        if (best != null) return best;
        throw new WriterException("QR does not decode with the logo");
    }

    private static boolean scans(Bitmap bitmap, String expected, int side) {
        Bitmap scaled = Bitmap.createScaledBitmap(bitmap, side, side, false);
        try {
            int[] pixels = new int[side * side];
            scaled.getPixels(pixels, 0, side, 0, 0, side, side);
            var image = new BinaryBitmap(new HybridBinarizer(new RGBLuminanceSource(side, side, pixels)));
            return expected.equals(new QRCodeReader().decode(image, Map.of(DecodeHintType.TRY_HARDER, true)).getText());
        } catch (ReaderException e) {
            return false;
        } finally {
            if (scaled != bitmap) scaled.recycle();
        }
    }

    private static Bitmap draw(BitMatrix matrix, Drawable logo, float radius) {
        int modules = matrix.getWidth();
        int side = modules * MODULE_PIXELS;
        Bitmap bitmap = Bitmap.createBitmap(side, side, Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(bitmap);
        canvas.drawColor(Color.WHITE);
        Paint dark = new Paint();
        dark.setColor(Color.BLACK);
        for (int y = QUIET_MODULES; y < modules - QUIET_MODULES; y++) {
            for (int x = QUIET_MODULES; x < modules - QUIET_MODULES; x++) {
                if (matrix.get(x, y)) canvas.drawRect(x * MODULE_PIXELS, y * MODULE_PIXELS,
                        (x + 1) * MODULE_PIXELS, (y + 1) * MODULE_PIXELS, dark);
            }
        }
        float center = side / 2f;
        Paint badge = new Paint(Paint.ANTI_ALIAS_FLAG);
        badge.setColor(Color.WHITE);
        canvas.drawCircle(center, center, radius + MODULE_PIXELS * .45f, badge);
        badge.setColor(0xff14181a);
        canvas.drawCircle(center, center, radius, badge);
        int halfLogo = Math.round(radius * 1.12f);
        logo.setBounds(Math.round(center)-halfLogo, Math.round(center)-halfLogo,
                Math.round(center)+halfLogo, Math.round(center)+halfLogo);
        logo.draw(canvas);
        return bitmap;
    }

    private static BitMatrix encode(QRCodeWriter writer, String link, ErrorCorrectionLevel correction) throws WriterException {
        return writer.encode(link, BarcodeFormat.QR_CODE, 0, 0,
                Map.of(EncodeHintType.ERROR_CORRECTION, correction, EncodeHintType.MARGIN, QUIET_MODULES));
    }
}
