java
package client;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;

public class SteganographyUtil {
    public static File embedFileInImage(File inputFile, File coverImage) throws Exception {
        BufferedImage image = ImageIO.read(coverImage);
        byte[] fileBytes = new byte[(int) inputFile.length()];
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            fis.read(fileBytes);
        }

        // Embed file length
        byte[] lengthBytes = intToByteArray(fileBytes.length);
        int width = image.getWidth();
        int height = image.getHeight();
        int pixelIndex = 0;

        // Embed length in first 32 pixels (4 bytes)
        for (int i = 0; i < 4; i++) {
            int x = pixelIndex % width;
            int y = pixelIndex / width;
            int rgb = image.getRGB(x, y);
            rgb = (rgb & 0xFFFFFF00) | (lengthBytes[i] & 0xFF);
            image.setRGB(x, y, rgb);
            pixelIndex++;
        }

        // Embed file data
        for (byte b : fileBytes) {
            if (pixelIndex >= width * height) {
                throw new IllegalArgumentException("Cover image too small to hold file data");
            }
            int x = pixelIndex % width;
            int y = pixelIndex / width;
            int rgb = image.getRGB(x, y);
            rgb = (rgb & 0xFFFFFF00) | (b & 0xFF);
            image.setRGB(x, y, rgb);
            pixelIndex++;
        }

        File outputImage = new File(inputFile.getName() + "_stego.png");
        ImageIO.write(image, "png", outputImage);
        return outputImage;
    }

    public static File extractFileFromImage(File stegoImage, String outputFileName) throws Exception {
        BufferedImage image = ImageIO.read(stegoImage);
        int width = image.getWidth();
        int height = image.getHeight();

        // Extract file length
        byte[] lengthBytes = new byte[4];
        int pixelIndex = 0;
        for (int i = 0; i < 4; i++) {
            int x = pixelIndex % width;
            int y = pixelIndex / width;
            int rgb = image.getRGB(x, y);
            lengthBytes[i] = (byte) (rgb & 0xFF);
            pixelIndex++;
        }
        int fileLength = byteArrayToInt(lengthBytes);

        // Extract file data
        byte[] fileBytes = new byte[fileLength];
        for (int i = 0; i < fileLength; i++) {
            int x = pixelIndex % width;
            int y = pixelIndex / width;
            int rgb = image.getRGB(x, y);
            fileBytes[i] = (byte) (rgb & 0xFF);
            pixelIndex++;
        }

        File outputFile = new File(outputFileName);
        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            fos.write(fileBytes);
        }
        return outputFile;
    }

    private static byte[] intToByteArray(int value) {
        return new byte[] {
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value
        };
    }

    private static int byteArrayToInt(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
               ((bytes[1] & 0xFF) << 16) |
               ((bytes[2] & 0xFF) << 8) |
               (bytes[3] & 0xFF);
    }
}
```