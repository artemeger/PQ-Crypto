package crypto.asymmetric;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyPairGeneratorSpi;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Optional;


public class SphincsEncryptionService {

    private static final Provider PQCPROVIDER = new BouncyCastlePQCProvider();
    private static final Provider BCPROVIDER = new BouncyCastleProvider();
    private static final String ROOTNAME = "CN=refaine.com";
    private static final int VALID = 100;
    private static final String SPHINCSSHA3ALGO = "SHA3-512WITHSPHINCS256";
    private static final String SHA3NAME = "SHA3-256";
    private static final String ALIAS = "Id-Keypair";
    private static final String KEYSTORE_FORMAT = "JKS";
    private static final String KEYSTORE_FILE_FORMAT = ".jks";
    private Logger log = LoggerFactory.getLogger(this.getClass());

    static {
        Security.addProvider(PQCPROVIDER);
        Security.addProvider(BCPROVIDER);
    }

    public void generateKeystore(String filename, String password) throws Exception{

        try {
            Sphincs256KeyPairGeneratorSpi generator = new Sphincs256KeyPairGeneratorSpi();
            generator.initialize(new SPHINCS256KeyGenParameterSpec(SHA3NAME), new SecureRandom());
            final KeyPair keyPair = generator.generateKeyPair();
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_FORMAT);
            keyStore.load(null, password.toCharArray());
            X509Certificate[] certificateChain = new X509Certificate[1];
            certificateChain[0] = generateCertificate(keyPair);
            keyStore.setKeyEntry(ALIAS, keyPair.getPrivate(), password.toCharArray(), certificateChain);
            try (FileOutputStream fos = new FileOutputStream(filename + KEYSTORE_FILE_FORMAT)) {
                keyStore.store(fos, password.toCharArray());
                log.info("Keystore was created successfully with name " + filename + KEYSTORE_FILE_FORMAT);
            }
        } catch (Exception e){
            log.error("Keystore creation failed with error: " + e.getMessage());
            log.error(e.getLocalizedMessage());
        }

    }

    public Optional<KeyPair> loadKeyPairFromKeyStore(String filename, String password){

        try{
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_FORMAT);
            keyStore.load(new FileInputStream(filename), password.toCharArray());
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(ALIAS, password.toCharArray());
            final Certificate certificate = keyStore.getCertificate(ALIAS);
            final PublicKey publicKey = certificate.getPublicKey();
            return Optional.of(new KeyPair(publicKey, privateKey));
        } catch (Exception e) {
           log.error("Keystore could not be loaded with error: " + e.getMessage());
           return Optional.empty();
        }

    }

    private X509Certificate generateCertificate(KeyPair keyPair) throws OperatorCreationException, CertificateException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Calendar calendar = Calendar.getInstance();
        Date validFrom = calendar.getTime();
        calendar.add(Calendar.YEAR, VALID);
        Date validUntil = calendar.getTime();

        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[64];
        random.nextBytes(randomBytes);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(ROOTNAME),
                new BigInteger(64, new SecureRandom()),
                validFrom, validUntil,
                new X500Name(ROOTNAME),
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(SPHINCSSHA3ALGO).build(keyPair.getPrivate());
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(BCPROVIDER).getCertificate(certHolder);
        cert.verify(keyPair.getPublic());
        return cert;
    }

}
