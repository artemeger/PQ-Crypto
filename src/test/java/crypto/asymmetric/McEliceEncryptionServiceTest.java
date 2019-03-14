package crypto.asymmetric;

import org.junit.Test;

public class McEliceEncryptionServiceTest {

    private McEliceEncryptionService classUnderTest = new McEliceEncryptionService();
    private SphincsSignatureService signatureService = new SphincsSignatureService();

    private String signKeyStoreName = "signKeyStore";
    private String cipherKeyStoreName = "cipherKeyStore";
    private String password = "mypassword";

    @Test
    public void generateKeyStoreTest() throws Exception {
        signatureService.generateKeystore(signKeyStoreName, password);
        classUnderTest.generateKeystore(cipherKeyStoreName, password, signKeyStoreName+".ubr", password);
    }

}
