package crypto.symmetric;

import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class ThreefishEncryptionServiceTest {

    private ThreefishEncryptionService classUnderTest = new ThreefishEncryptionService();

    private String symmetricKeyStoreName = "symmetric";
    private String password = "mypassword";

    @Test
    public void generateKeyStoreTest() throws Exception {
        classUnderTest.generateKeyStore(symmetricKeyStoreName, password);
        assertTrue(new File(symmetricKeyStoreName+".ubr").exists());
        SecretKey secretKey = classUnderTest.loadSecretKeyFromKeyStore(symmetricKeyStoreName+".ubr", password);
        assertSame(secretKey.getClass(), SecretKeySpec.class);
    }

    @Test(expected = Exception.class)
    public void loadSecretKeyWithWrongPasswordTest() throws Exception{
        classUnderTest.generateKeyStore(symmetricKeyStoreName, password);
        assertTrue(new File(symmetricKeyStoreName+".ubr").exists());
        SecretKey secretKey = classUnderTest.loadSecretKeyFromKeyStore(symmetricKeyStoreName+".ubr", "my");
    }

    @Test
    public void encryptAndDecryptTest() throws Exception{
        classUnderTest.generateKeyStore(symmetricKeyStoreName, password);
        assertTrue(new File(symmetricKeyStoreName+".ubr").exists());
        SecretKey secretKey = classUnderTest.loadSecretKeyFromKeyStore(symmetricKeyStoreName+".ubr", password);
        byte [] data = new byte[20];
        new SecureRandom().nextBytes(data);
        ArrayList<byte []> encryptedData = classUnderTest.encrypt(secretKey, data);
        byte [] decryptedData = classUnderTest.decrypt(secretKey, encryptedData.get(0), encryptedData.get(1));
        assertTrue(Arrays.equals(data, decryptedData));
    }

    @Test
    public void secretKeyFromEncodedTest() throws Exception{
       SecretKey key = classUnderTest.generateSecretKey();
       byte [] keyBytes = key.getEncoded();
       SecretKey keyRestored = classUnderTest.getSecretKeyFromEncoded(keyBytes);
       assertTrue(Arrays.equals(keyBytes, keyRestored.getEncoded()));
       assertEquals(keyRestored.getFormat(), key.getFormat());
    }

}
