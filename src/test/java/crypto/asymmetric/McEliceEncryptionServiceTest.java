package crypto.asymmetric;

import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePrivateKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey;
import org.junit.Test;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.Assert.assertTrue;

public class McEliceEncryptionServiceTest {

    private McEliceEncryptionService classUnderTest = new McEliceEncryptionService();
    private SphincsSignatureService signatureService = new SphincsSignatureService();

    private String signKeyStoreName = "signKeyStore";
    private String cipherKeyStoreName = "cipherKeyStore";
    private String password = "mypassword";

    @Test
    public void generateKeyStoreAndLoadEnDecryptTest() {
        signatureService.generateKeystore(signKeyStoreName, password);
        classUnderTest.generateKeystore(cipherKeyStoreName, password, signKeyStoreName+".ubr", password);
        Optional<KeyPair> keyPairOpt = classUnderTest.loadKeyPairFromKeyStore(cipherKeyStoreName+".ubr", password);
        assertTrue(keyPairOpt.isPresent());
        byte [] bytes = new byte [20];
        new SecureRandom().nextBytes(bytes);
        Optional<byte []> dataOpt = classUnderTest.encrypt((BCMcEliecePublicKey)keyPairOpt.get().getPublic(), bytes);
        assertTrue(dataOpt.isPresent());
        Optional<byte []> decryptedOpt = classUnderTest.decrypt((BCMcEliecePrivateKey)keyPairOpt.get().getPrivate(), dataOpt.get());
        assertTrue(decryptedOpt.isPresent());
        assertTrue(Arrays.equals(decryptedOpt.get(), bytes));
    }

}
