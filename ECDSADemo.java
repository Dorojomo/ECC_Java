import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

public class ECDSADemo {
    public static void main(String[] args) {
        try {
            // 1. Add BouncyCastle as a security provider
            Security.addProvider(new BouncyCastleProvider());

            // 2. Generate Key Pair (Public and Private Key)
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyPairGen.initialize(ecSpec, new SecureRandom());
            KeyPair keyPair = keyPairGen.generateKeyPair();

            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            System.out.println("Private Key: " + Base64.getEncoder().encodeToString(privateKey.getEncoded()));
            System.out.println("Public Key: " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

            // 3. Message to Sign
            String message = "This is a test message for ECDSA";
            byte[] messageBytes = message.getBytes();

            // 4. Sign the Message
            Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaSign.initSign(privateKey);
            ecdsaSign.update(messageBytes);
            byte[] signature = ecdsaSign.sign();

            System.out.println("Signature: " + Base64.getEncoder().encodeToString(signature));

            // 5. Verify the Signature
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(messageBytes);
            boolean isVerified = ecdsaVerify.verify(signature);

            System.out.println("Signature verification: " + (isVerified ? "Success" : "Failed"));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
