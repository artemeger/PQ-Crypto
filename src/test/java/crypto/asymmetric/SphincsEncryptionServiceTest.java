package crypto.asymmetric;

import org.junit.Test;

public class SphincsEncryptionServiceTest {

    SphincsEncryptionService classUnderTest = new SphincsEncryptionService();

    @Test
    public void generateSaveLoadKeyStore() throws Exception {

        classUnderTest.generateKeystore("keystore", "thisisapassword");

    }

}
