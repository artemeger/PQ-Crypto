package crypto.asymmetric;

import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Optional;

import static org.junit.Assert.assertTrue;

public class SphincsSignatureServiceTest {

    private SphincsSignatureService classUnderTest = new SphincsSignatureService();

    @Test
    public void generateSaveLoadKeyStore() throws Exception {
        classUnderTest.generateKeystore("keystore", "thisisapassword");
        assertTrue(new File("keystore.ubr").exists());
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore("keystore.ubr", "thisisapassword");
        assertTrue(keyPairOpt.isPresent());
    }

    @Test
    public void LoadKeyStoreWithWrongPass() throws Exception {
        classUnderTest.generateKeystore("keystore", "thisisapassword");
        assertTrue(new File("keystore.ubr").exists());
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore("keystore.ubr", "this");
        assertTrue(keyPairOpt.isEmpty());
    }

    @Test
    public void createSignatureAndVerifyTest() throws Exception {
        classUnderTest.generateKeystore("keystore", "thisisapassword");
        assertTrue(new File("keystore.ubr").exists());
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore("keystore.ubr", "thisisapassword");
        assertTrue(keyPairOpt.isPresent());
        byte [] data = new byte[20];
        new SecureRandom().nextBytes(data);
        Optional<byte[]> signatureBytesOpt = classUnderTest.getSignature(keyPairOpt.get().getPrivate(), data);
        assertTrue(signatureBytesOpt.isPresent());
        assertTrue(classUnderTest.verifySignature(keyPairOpt.get().getPublic(), data, signatureBytesOpt.get()));
    }

}
