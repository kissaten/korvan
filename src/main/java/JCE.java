import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

public class JCE {

    private static final char[] PASSWORD = "abcdefg".toCharArray();

    private static final byte[] SALT =
            {
                    (byte)0x4D, (byte)0x9B, (byte)0xC6, (byte)0x53,
                    (byte)0x17, (byte)0xAF, (byte)0xE2, (byte)0x08
            };

    private static final int iterations = 311;

    public static void main(String... args) throws Exception {
        String data = "Test";
        for (String arg : args) {
            data += ":" + arg;
        }

        System.out.println("Encrypting, \"" + data + "\"");

        byte[] encryptedData = encrypt(data);
        System.out.println("Encrypted: " + new String(encryptedData));

        byte[] decipheredText = decrypt(encryptedData);
        System.out.println("Decrypted: " + new String(decipheredText));
    }

    private static byte[] encrypt(String property) throws Exception {
        Cipher pbeCipher = getCipher(Cipher.ENCRYPT_MODE);
        return pbeCipher.doFinal(property.getBytes());
    }

    private static byte[] decrypt(byte[] property) throws Exception {
        Cipher pbeCipher = getCipher(Cipher.DECRYPT_MODE);
        return pbeCipher.doFinal(property);
    }

    private static Cipher getCipher(int mode) throws Exception {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(PASSWORD));
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
        pbeCipher.init(mode, key, new PBEParameterSpec(SALT, 20));
        return pbeCipher;
    }
}
