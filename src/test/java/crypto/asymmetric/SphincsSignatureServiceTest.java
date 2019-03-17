package crypto.asymmetric;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
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

    @Test
    public void encodedToPublicKeyTest(){
        classUnderTest.generateKeystore(signKeyStoreName, password);
        assertTrue(Files.exists(Paths.get(signKeyStoreName + ".ubr")));
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore(signKeyStoreName + ".ubr", password);
        assertTrue(keyPairOpt.isPresent());
        PublicKey publicKey = keyPairOpt.get().getPublic();
        byte [] encodedBytes = publicKey.getEncoded();
        Optional<PublicKey> publicKey2 = classUnderTest.encodedToPublicKey(encodedBytes);
        assertTrue(publicKey2.isPresent());
        assertEquals(publicKey.getAlgorithm(), publicKey2.get().getAlgorithm());
        assertTrue(Arrays.equals(publicKey.getEncoded(), publicKey2.get().getEncoded()));
        assertEquals(publicKey.hashCode(), publicKey2.hashCode());
    }

}
