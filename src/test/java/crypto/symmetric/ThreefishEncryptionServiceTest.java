package crypto.symmetric;

import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.Assert.assertTrue;

public class ThreefishEncryptionServiceTest {

    private ThreefishEncryptionService classUnderTest = new ThreefishEncryptionService();

    @Test
    public void generateKeyStoreTest() throws Exception{
        classUnderTest.generateKeyStore("symmetric", "mypassword");
        assertTrue(new File("symmetric.ubr").exists());
        Optional<SecretKey> secretKeyOpt = classUnderTest.loadSecretKeyFromKeyStore("symmetric.ubr", "mypassword");
        assertTrue(secretKeyOpt.isPresent());
    }

    @Test
    public void loadSecretKeyWithWrongPasswordTest() throws Exception{
        classUnderTest.generateKeyStore("symmetric", "mypassword");
        assertTrue(new File("symmetric.ubr").exists());
        Optional<SecretKey> secretKeyOpt = classUnderTest.loadSecretKeyFromKeyStore("symmetric.ubr", "my");
        assertTrue(secretKeyOpt.isEmpty());
    }

    @Test
    public void encryptAndDecryptTest() throws Exception{
        classUnderTest.generateKeyStore("symmetric", "mypassword");
        assertTrue(new File("symmetric.ubr").exists());
        Optional<SecretKey> secretKeyOpt = classUnderTest.loadSecretKeyFromKeyStore("symmetric.ubr", "mypassword");
        assertTrue(secretKeyOpt.isPresent());
        byte [] data = new byte[20];
        new SecureRandom().nextBytes(data);
        Optional<ArrayList<byte []>> encryptedDataOpt = classUnderTest.encrypt(secretKeyOpt.get(), data);
        assertTrue(encryptedDataOpt.isPresent());
        ArrayList<byte[]> list = encryptedDataOpt.get();
        Optional<byte []> decryptedDataOpt = classUnderTest.decrypt(secretKeyOpt.get(), list.get(0), list.get(1));
        assertTrue(decryptedDataOpt.isPresent());
        assertTrue(Arrays.equals(data, decryptedDataOpt.get()));
    }

}
