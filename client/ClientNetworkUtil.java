package client;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.awt.image.BufferedImage;
import java.util.Base64;

public class ClientNetworkUtil {
    public static SecretKey sendFileToServer(File fileToSend, File keyFileOrStegoImage, boolean useStego, String serverIP, int serverPort, String algorithm, PublicKey publicKey) throws Exception {
        try (Socket socket = new Socket(serverIP, serverPort);
             DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
             DataInputStream dis = new DataInputStream(socket.getInputStream());
             FileInputStream fis = new FileInputStream(fileToSend);
             FileInputStream keyFis = new FileInputStream(keyFileOrStegoImage)) {

            byte[] publicKeyEncoded = publicKey.getEncoded();
            dos.writeInt(publicKeyEncoded.length);
            dos.write(publicKeyEncoded);
            dos.flush();

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
            keyAgreement.init(keyPair.getPrivate());

            byte[] clientPubKeyEncoded = keyPair.getPublic().getEncoded();
            dos.writeInt(clientPubKeyEncoded.length);
            dos.write(clientPubKeyEncoded);
            dos.flush();

            int serverPubKeyLen = dis.readInt();
            byte[] serverPubKeyEncoded = new byte[serverPubKeyLen];
            dis.readFully(serverPubKeyEncoded);

            KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
            PublicKey serverPubKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPubKeyEncoded));

            keyAgreement.doPhase(serverPubKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            byte[] sharedKeyBytes = new byte[32];
            System.arraycopy(sharedSecret, 0, sharedKeyBytes, 0, Math.min(sharedSecret.length, 32));
            SecretKey sharedKey = new SecretKeySpec(sharedKeyBytes, algorithm.equals("DOUBLE") ? "AES" : algorithm);

            dos.writeUTF(algorithm);
            dos.writeLong(fileToSend.length());
            dos.writeBoolean(useStego);
            dos.writeLong(keyFileOrStegoImage.length());

            File signatureFile = new File(fileToSend.getAbsolutePath() + ".sig");
            if (!signatureFile.exists()) {
                throw new FileNotFoundException("Signature file not found: " + signatureFile.getAbsolutePath());
            }
            dos.writeLong(signatureFile.length());

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                dos.write(buffer, 0, bytesRead);
            }
            dos.flush();
            while ((bytesRead = keyFis.read(buffer)) != -1) {
                dos.write(buffer, 0, bytesRead);
            }
            dos.flush();
            try (FileInputStream sigFis = new FileInputStream(signatureFile)) {
                while ((bytesRead = sigFis.read(buffer)) != -1) {
                    dos.write(buffer, 0, bytesRead);
                }
            }
            dos.flush();

            return sharedKey;
        }
    }
    public static BufferedImage embedKeyInImage(BufferedImage image, String keyData) {
        int width = image.getWidth();
        int height = image.getHeight();
        BufferedImage stegoImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);

        byte[] keyBytes = keyData.getBytes();
        int bitIndex = 0;

        for (int y = 0; y < height && bitIndex < keyBytes.length * 8; y++) {
            for (int x = 0; x < width && bitIndex < keyBytes.length * 8; x++) {
                int pixel = image.getRGB(x, y);
                int alpha = (pixel >> 24) & 0xff;
                int red = (pixel >> 16) & 0xff;
                int green = (pixel >> 8) & 0xff;
                int blue = pixel & 0xff;

                int bitPosition = bitIndex % 8;
                int byteIndex = bitIndex / 8;
                int bit = (keyBytes[byteIndex] >> (7 - bitPosition)) & 1;

                blue = (blue & 0xFE) | bit;

                int newPixel = (alpha << 24) | (red << 16) | (green << 8) | blue;
                stegoImage.setRGB(x, y, newPixel);
                bitIndex++;
            }
        }
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (bitIndex >= keyBytes.length * 8) {
                    stegoImage.setRGB(x, y, image.getRGB(x, y));
                }
            }
        }
        return stegoImage;
    }
    public static String extractKeyFromImage(BufferedImage stegoImage) {
        int width = stegoImage.getWidth();
        int height = stegoImage.getHeight();
        StringBuilder keyBits = new StringBuilder();
        int bitIndex = 0;

        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int pixel = stegoImage.getRGB(x, y);
                int blue = pixel & 0xff;
                int bit = blue & 1;
                keyBits.append(bit);
                bitIndex++;
                
                if (keyBits.length() % 8 == 0) {
                    String keyData = bitsToString(keyBits.toString());
                    if (keyData.contains(":")) {
                        return keyData;
                    }
                }
            }
        }
        return bitsToString(keyBits.toString());
    }
    private static String bitsToString(String bits) {
        StringBuilder keyData = new StringBuilder();
        for (int i = 0; i < bits.length(); i += 8) {
            String byteBits = bits.substring(i, Math.min(i + 8, bits.length()));
            int byteValue = Integer.parseInt(byteBits, 2);
            keyData.append((char) byteValue);
        }
        return keyData.toString();
    }
}