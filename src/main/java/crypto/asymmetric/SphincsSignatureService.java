package crypto.asymmetric;

import crypto.Identifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyPairGeneratorSpi;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Optional;


public class SphincsSignatureService {

    private Logger log = LoggerFactory.getLogger(this.getClass());

    static {
        Security.addProvider(Identifiers.PQCPROVIDER);
        Security.addProvider(Identifiers.BCPROVIDER);
    }

    public void generateKeystore(String name, String password) {

        try {
            Sphincs256KeyPairGeneratorSpi generator = new Sphincs256KeyPairGeneratorSpi();
            generator.initialize(new SPHINCS256KeyGenParameterSpec(Identifiers.SHA3NAME), new SecureRandom());
            final KeyPair keyPair = generator.generateKeyPair();
            KeyStore keyStore = KeyStore.getInstance(Identifiers.KEYSTORE_FORMAT);
            keyStore.load(null, password.toCharArray());
            X509Certificate[] certificateChain = new X509Certificate[1];
            certificateChain[0] = generateCertificate(keyPair);
            keyStore.setKeyEntry(Identifiers.ALIAS_SIGNATURE, keyPair.getPrivate(), password.toCharArray(), certificateChain);
            try (FileOutputStream fos = new FileOutputStream(name + Identifiers.KEYSTORE_FILE_FORMAT)) {
                keyStore.store(fos, password.toCharArray());
                log.info("Keystore was created successfully with name " + name + Identifiers.KEYSTORE_FILE_FORMAT);
            }
        } catch (Exception e){
            log.error("Keystore creation failed with error: " + e.getMessage());
        }

    }

    public Optional<KeyPair> loadKeyPairFromKeyStore(String filename, String password){

        try{
            KeyStore keyStore = KeyStore.getInstance(Identifiers.KEYSTORE_FORMAT);
            keyStore.load(new FileInputStream(filename), password.toCharArray());
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(Identifiers.ALIAS_SIGNATURE, password.toCharArray());
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(Identifiers.ALIAS_SIGNATURE);
            final PublicKey publicKey = certificate.getPublicKey();
            log.info("KeyPair was successfully loaded from keystore");
            return Optional.of(new KeyPair(publicKey, privateKey));
        } catch (Exception e) {
           log.error("KeyPair could not be loaded with error: " + e.getMessage());
           return Optional.empty();
        }

    }

    public Optional<byte[]> getSignature(PrivateKey privateKey, byte [] data){
        try{
            Signature signature = Signature.getInstance(Identifiers.SIGNATUREALGO, Identifiers.PQCPROVIDER);
            signature.initSign(privateKey);
            signature.update(data);
            log.info("Successfully loaded Signature");
            return Optional.of(signature.sign());
        } catch (Exception e){
            log.error("Failed to encrypt data with error: " + e.getMessage());
            return Optional.empty();
        }
    }

    public boolean verifySignature(PublicKey publicKey, byte [] data, byte[] signatureBytes){
        try{
            Signature signature = Signature.getInstance(Identifiers.SIGNATUREALGO, Identifiers.PQCPROVIDER);
            signature.initVerify(publicKey);
            signature.update(data);
            log.info("Successfully loaded Signature");
            return signature.verify(signatureBytes);
        } catch (Exception e){
            log.error("Failed to decrypt data with error: " + e.getMessage());
            return false;
        }
    }

    private X509Certificate generateCertificate(KeyPair keyPair) throws OperatorCreationException, CertificateException,
            NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        Calendar calendar = Calendar.getInstance();
        Date validFrom = calendar.getTime();
        calendar.add(Calendar.YEAR, Identifiers.CERT_VALID);
        Date validUntil = calendar.getTime();

        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[64];
        random.nextBytes(randomBytes);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(Identifiers.ROOTNAME),
                new BigInteger(64, new SecureRandom()),
                validFrom, validUntil,
                new X500Name(Identifiers.ROOTNAME),
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(Identifiers.SPHINCSSHA3ALGO).build(keyPair.getPrivate());
        X509CertificateHolder certHolder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(Identifiers.BCPROVIDER).getCertificate(certHolder);
        cert.verify(keyPair.getPublic());
        return cert;
    }

}
