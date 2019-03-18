package crypto.asymmetric;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SphincsSignatureServiceTest {

    private SphincsSignatureService classUnderTest = new SphincsSignatureService();

    private static String signKeyStoreName = "signKeyStore";
    private static String password = "mypassword";

    @Test
    public void generateSaveLoadKeyStore() throws Exception {
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        classUnderTest.loadKeyPairFromKeyStore(signKeyStoreName + ".ubr", password);
    }

    @Test(expected = Exception.class)
    public void LoadKeyStoreWithWrongPass() throws Exception {
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        classUnderTest.loadKeyPairFromKeyStore("keystore.ubr", "this");
    }

    @Test
    public void createSignatureAndVerifyTest() throws Exception {
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        KeyPair keyPair = classUnderTest.loadKeyPairFromKeyStore(signKeyStoreName + ".ubr", password);
        byte[] data = new byte[20];
        new SecureRandom().nextBytes(data);
        byte[] signatureBytes = classUnderTest.getSignature(keyPair.getPrivate(), data);
        assertTrue(classUnderTest.verifySignature(keyPair.getPublic(), data, signatureBytes));
    }

    @Test
    public void encodedToPublicKeyTest() throws Exception {
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        KeyPair keyPair = classUnderTest.loadKeyPairFromKeyStore(signKeyStoreName + ".ubr", password);
        PublicKey publicKey = keyPair.getPublic();
        byte [] encodedBytes = publicKey.getEncoded();
        PublicKey publicKey2 = classUnderTest.encodedToPublicKey(encodedBytes);
        assertEquals(publicKey.getAlgorithm(), publicKey2.getAlgorithm());
        assertTrue(Arrays.equals(publicKey.getEncoded(), publicKey2.getEncoded()));
        assertEquals(publicKey.hashCode(), publicKey2.hashCode());
    }

}
