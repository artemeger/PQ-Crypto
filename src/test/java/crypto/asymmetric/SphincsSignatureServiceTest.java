package crypto.asymmetric;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Optional;

import static org.junit.Assert.assertTrue;

public class SphincsSignatureServiceTest {

    private SphincsSignatureService classUnderTest = new SphincsSignatureService();

    private static String signKeyStoreName = "signKeyStore";
    private static String password = "mypassword";

    @Test
    public void generateSaveLoadKeyStore(){
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore(signKeyStoreName + ".ubr", password);
        assertTrue(keyPairOpt.isPresent());
    }

    @Test
    public void LoadKeyStoreWithWrongPass(){
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore("keystore.ubr", "this");
        assertTrue(keyPairOpt.isEmpty());
    }

    @Test
    public void createSignatureAndVerifyTest(){
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore(signKeyStoreName + ".ubr", password);
        assertTrue(keyPairOpt.isPresent());
        byte[] data = new byte[20];
        new SecureRandom().nextBytes(data);
        Optional<byte[]> signatureBytesOpt = classUnderTest.getSignature(keyPairOpt.get().getPrivate(), data);
        assertTrue(signatureBytesOpt.isPresent());
        assertTrue(classUnderTest.verifySignature(keyPairOpt.get().getPublic(), data, signatureBytesOpt.get()));
    }

}
