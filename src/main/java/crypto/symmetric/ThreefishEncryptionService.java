package crypto.symmetric;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.Optional;

public class ThreefishEncryptionService {

    private static final Provider BCPROVIDER = new BouncyCastleProvider();
    private static final String ALGORITHM = "Threefish-1024";
    private static final int KEYSIZE = 1024;
    private static final String KEYSTORE_FORMAT = "UBER";
    private static final String KEYSTORE_FILE_FORMAT = ".ubr";
    private static final String ALIAS = "SymKey";
    private static final String SYM_ALGO_TRANSFORMATION_STRING = "Threefish-1024/CBC/PKCS7Padding";
    private Logger log = LoggerFactory.getLogger(this.getClass());

    static {
        Security.addProvider(BCPROVIDER);
    }

    public void generateKeyStore(String name, String password) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(ALGORITHM, BCPROVIDER);
        generator.init(KEYSIZE, new SecureRandom());
        SecretKey secretKey = generator.generateKey();
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_FORMAT);
        keyStore.load(null, password.toCharArray());
        keyStore.setEntry(ALIAS, new KeyStore.SecretKeyEntry(secretKey),
                new KeyStore.PasswordProtection(password.toCharArray()));
        try (FileOutputStream fos = new FileOutputStream(name + KEYSTORE_FILE_FORMAT)) {
            keyStore.store(fos, password.toCharArray());
            log.info("Keystore was created successfully with name " + name + KEYSTORE_FILE_FORMAT);
        }
    }

    public Optional<SecretKey> loadSecretKeyFromKeyStore(String filename, String password){
        try{
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_FORMAT);
            keyStore.load(new FileInputStream(filename), password.toCharArray());
            log.info("Symmetric key was loaded successfully from keystore");
            return Optional.of((SecretKey) keyStore.getKey(ALIAS, password.toCharArray()));
        } catch (Exception e) {
            log.error("Failed to load symmetric key from keystore with error:" + e.getMessage());
            return Optional.empty();
        }
    }

    public Optional<ArrayList<byte[]>> encrypt(SecretKey secretKey, byte [] data){
        try{
            byte[] iv = new byte[128];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance(SYM_ALGO_TRANSFORMATION_STRING);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            ArrayList<byte []> result = new ArrayList<>();
            result.add(cipher.doFinal(data));
            result.add(iv);
            return Optional.of(result);
        } catch (Exception e){
            log.error(e.getMessage());
            return Optional.empty();
        }
    }

    public Optional<byte[]> decrypt(SecretKey secretKey, byte [] encrypted, byte [] iv){
        try{
            Cipher cipher = Cipher.getInstance(SYM_ALGO_TRANSFORMATION_STRING);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            return Optional.of(cipher.doFinal(encrypted));
        } catch (Exception e){
            log.error(e.getMessage());
            return Optional.empty();
        }
    }

}
