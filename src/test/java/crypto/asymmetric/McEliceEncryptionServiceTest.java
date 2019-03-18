package crypto.asymmetric;

import org.junit.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class McEliceEncryptionServiceTest {

    private McEliceEncryptionService classUnderTest = new McEliceEncryptionService();
    private SphincsSignatureService signatureService = new SphincsSignatureService();

    private String signKeyStoreName = "signKeyStore";
    private String cipherKeyStoreName = "cipherKeyStore";
    private String password = "mypassword";

    @Test
    public void generateKeyStoreAndLoadEnDecryptTest() throws Exception {
        signatureService.generateKeystore(signKeyStoreName, password);
        classUnderTest.generateKeystore(cipherKeyStoreName, password, signKeyStoreName+".ubr", password);
        KeyPair keyPair = classUnderTest.loadKeyPairFromKeyStore(cipherKeyStoreName+".ubr", password);
        byte [] bytes = new byte [20];
        new SecureRandom().nextBytes(bytes);
        byte [] data = classUnderTest.encrypt(keyPair.getPublic(), bytes);
        byte [] decrypted = classUnderTest.decrypt(keyPair.getPrivate(), data);
        assertTrue(Arrays.equals(decrypted, bytes));
    }

    @Test
    public void loadPublicKeyFromEncoded() throws Exception {
        signatureService.generateKeystore(signKeyStoreName, password);
        classUnderTest.generateKeystore(cipherKeyStoreName, password, signKeyStoreName+".ubr", password);
        KeyPair keyPair = classUnderTest.loadKeyPairFromKeyStore(cipherKeyStoreName+".ubr", password);
        PublicKey publicKey = keyPair.getPublic();
        byte [] encodedBytes = publicKey.getEncoded();
        PublicKey publicKey2 = classUnderTest.encodedToPublicKey(encodedBytes);
        assertEquals(publicKey.getAlgorithm(), publicKey2.getAlgorithm());
        assertTrue(Arrays.equals(publicKey.getEncoded(), publicKey2.getEncoded()));
        assertEquals(publicKey.hashCode(), publicKey2.hashCode());
    }

}
