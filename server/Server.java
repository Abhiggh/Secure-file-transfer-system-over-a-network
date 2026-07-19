package server;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.nio.file.Files;
import java.util.Base64;
import client.ClientNetworkUtil;

public class Server {
    public static final int PORT = 5000;
    public static final String SAVE_DIR = "received_files/";

    public static void main(String[] args) throws Exception {
        new File(SAVE_DIR).mkdirs();
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Server is running and listening on port " + PORT);

        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("Client connected: " + socket.getInetAddress());

            new Thread(() -> handleClient(socket)).start();
        }
    }
    private static void handleClient(Socket socket) {
        try (
            DataInputStream dis = new DataInputStream(socket.getInputStream());
            DataOutputStream dos = new DataOutputStream(socket.getOutputStream())
        ) {
            int publicKeyLen = dis.readInt();
            byte[] publicKeyEncoded = new byte[publicKeyLen];
            dis.readFully(publicKeyEncoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey clientPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyEncoded));
            System.out.println("Received client's RSA public key");

            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            keyPairGen.initialize(2048);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            KeyAgreement keyAgreement = KeyAgreement.getInstance("DiffieHellman");
            keyAgreement.init(keyPair.getPrivate());

            byte[] serverPubKeyEncoded = keyPair.getPublic().getEncoded();
            dos.writeInt(serverPubKeyEncoded.length);
            dos.write(serverPubKeyEncoded);
            dos.flush();

            int clientPubKeyLen = dis.readInt();
            byte[] clientPubKeyEncoded = new byte[clientPubKeyLen];
            dis.readFully(clientPubKeyEncoded);

            PublicKey clientDHPubKey = KeyFactory.getInstance("DiffieHellman")
                .generatePublic(new X509EncodedKeySpec(clientPubKeyEncoded));
            keyAgreement.doPhase(clientDHPubKey, true);
            byte[] sharedSecret = keyAgreement.generateSecret();

            String algorithm = dis.readUTF();
            long fileSize = dis.readLong();
            boolean useStego = dis.readBoolean();
            long keyFileSize = dis.readLong();
            long signatureSize = dis.readLong();

            byte[] sharedKeyBytes = new byte[32];
            System.arraycopy(sharedSecret, 0, sharedKeyBytes, 0, Math.min(sharedSecret.length, 32));
            SecretKey sharedKey = new SecretKeySpec(sharedKeyBytes, algorithm.equals("DOUBLE") ? "AES" : algorithm);

            String fileName = "received_" + System.currentTimeMillis() + ".encrypted";
            File encryptedFile = new File(SAVE_DIR + fileName);
            try (FileOutputStream fos = new FileOutputStream(encryptedFile)) {
                byte[] buffer = new byte[4096];
                long bytesReadTotal = 0;
                int bytesRead;
                while (bytesReadTotal < fileSize && (bytesRead = dis.read(buffer, 0, (int) Math.min(buffer.length, fileSize - bytesReadTotal))) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    bytesReadTotal += bytesRead;
                }
            }
            System.out.println("Received and saved encrypted file: " + encryptedFile.getAbsolutePath());

            String keyFileName = useStego ? fileName + ".stego.png" : fileName + ".key";
            File keyFileOrStegoImage = new File(SAVE_DIR + keyFileName);
            try (FileOutputStream fos = new FileOutputStream(keyFileOrStegoImage)) {
                byte[] buffer = new byte[4096];
                long bytesReadTotal = 0;
                int bytesRead;
                while (bytesReadTotal < keyFileSize && (bytesRead = dis.read(buffer, 0, (int) Math.min(buffer.length, keyFileSize - bytesReadTotal))) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    bytesReadTotal += bytesRead;
                }
            }
            System.out.println("Received and saved " + (useStego ? "stego-image" : "key file") + ": " + keyFileOrStegoImage.getAbsolutePath());

            String signatureFileName = fileName + ".sig";
            File signatureFile = new File(SAVE_DIR + signatureFileName);
            try (FileOutputStream fos = new FileOutputStream(signatureFile)) {
                byte[] buffer = new byte[4096];
                long bytesReadTotal = 0;
                int bytesRead;
                while (bytesReadTotal < signatureSize && (bytesRead = dis.read(buffer, 0, (int) Math.min(buffer.length, signatureSize - bytesReadTotal))) != -1) {
                    fos.write(buffer, 0, bytesRead);
                    bytesReadTotal += bytesRead;
                }
            }
            System.out.println("Received and saved signature file: " + signatureFile.getAbsolutePath());

            boolean isSignatureValid = verifyDigitalSignature(encryptedFile, signatureFile, clientPublicKey);
            if (isSignatureValid) {
                System.out.println("Digital signature verified successfully");
                logToAuditFile("Signature verification successful for file: " + fileName);
            } else {
                System.err.println("Digital signature verification failed");
                logToAuditFile("Signature verification failed for file: " + fileName);
                encryptedFile.delete();
                keyFileOrStegoImage.delete();
                signatureFile.delete();
                throw new SecurityException("Digital signature verification failed");
            }
            String sharedKeyData = Base64.getEncoder().encodeToString(sharedKey.getEncoded()) + ":" + sharedKey.getAlgorithm();
            File sharedKeyFile = new File(SAVE_DIR + fileName + ".server" + (useStego ? ".stego.png" : ".key"));
            if (useStego) {
                BufferedImage coverImage = new BufferedImage(100, 100, BufferedImage.TYPE_INT_ARGB);
                BufferedImage stegoImage = ClientNetworkUtil.embedKeyInImage(coverImage, sharedKeyData);
                ImageIO.write(stegoImage, "PNG", sharedKeyFile);
            } else {
                try (FileOutputStream fos = new FileOutputStream(sharedKeyFile)) {
                    fos.write(sharedKeyData.getBytes());
                }
            }
            System.out.println("Saved server key to: " + sharedKeyFile.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
            logToAuditFile("Error handling client: " + e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    private static boolean verifyDigitalSignature(File file, File signatureFile, PublicKey publicKey) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        byte[] computedHash = digest.digest();
        byte[] signature = Files.readAllBytes(signatureFile.toPath());

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedHash = cipher.doFinal(signature);

        return MessageDigest.isEqual(computedHash, decryptedHash);
    }
    private static void logToAuditFile(String message) {
        try (PrintWriter out = new PrintWriter(new FileWriter(SAVE_DIR + "audit.log", true))) {
            out.println(new java.util.Date() + " - " + message);
        } catch (IOException e) {
            System.err.println("Error writing to audit log: " + e.getMessage());
        }
    }
}