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

    private String symmetricKeyStoreName = "symmetric";
    private String password = "mypassword";

    @Test
    public void generateKeyStoreTest() throws Exception{
        classUnderTest.generateKeyStore(symmetricKeyStoreName, password);
        assertTrue(new File(symmetricKeyStoreName+".ubr").exists());
        Optional<SecretKey> secretKeyOpt = classUnderTest.loadSecretKeyFromKeyStore(symmetricKeyStoreName+".ubr", password);
        assertTrue(secretKeyOpt.isPresent());
    }

    @Test
    public void loadSecretKeyWithWrongPasswordTest() throws Exception{
        classUnderTest.generateKeyStore(symmetricKeyStoreName, password);
        assertTrue(new File(symmetricKeyStoreName+".ubr").exists());
        Optional<SecretKey> secretKeyOpt = classUnderTest.loadSecretKeyFromKeyStore(symmetricKeyStoreName+".ubr", "my");
        assertTrue(secretKeyOpt.isEmpty());
    }

    @Test
    public void encryptAndDecryptTest() throws Exception{
        classUnderTest.generateKeyStore(symmetricKeyStoreName, password);
        assertTrue(new File(symmetricKeyStoreName+".ubr").exists());
        Optional<SecretKey> secretKeyOpt = classUnderTest.loadSecretKeyFromKeyStore(symmetricKeyStoreName+".ubr", password);
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
