java
package client;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SecurityUtil {
    private static KeyPair clientKeyPair;

    static {
        try {
            // Generate RSA key pair for digital signatures
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            clientKeyPair = keyGen.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static PublicKey getPublicKey() {
        return clientKeyPair.getPublic();
    }

    public static PrivateKey getPrivateKey() {
        return clientKeyPair.getPrivate();
    }

    public static SecretKey generateSharedSecret(PublicKey serverPublicKey) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
        keyPairGen.initialize(2048);
        KeyPair clientKeyPair = keyPairGen.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(clientKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);

        byte[] sharedSecret = keyAgreement.generateSecret();
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha256.digest(sharedSecret);
        return new SecretKeySpec(keyBytes, 0, 16, "AES");
    }

    public static PublicKey decodePublicKey(String encodedKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        return keyFactory.generatePublic(spec);
    }
}
```