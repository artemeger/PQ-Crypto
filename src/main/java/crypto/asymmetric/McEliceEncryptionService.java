package crypto.asymmetric;

import crypto.Identifiers;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
import org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2KeyGenParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

public class McEliceEncryptionService {

    private Logger log = LoggerFactory.getLogger(this.getClass());
    private McElieceCCA2KeyGenParameterSpec params = new McElieceCCA2KeyGenParameterSpec(11, 50);

    static {
        Security.addProvider(Identifiers.PQCPROVIDER);
        Security.addProvider(Identifiers.BCPROVIDER);
    }

    public void generateKeystore(String name, String password, String signerKeystorePath, String signerKeyStorePass) throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance(Identifiers.KEYSTORE_FORMAT);
            keyStore.load(null, password.toCharArray());

            KeyPairGenerator generator = KeyPairGenerator.getInstance(Identifiers.ASYM_CIPHER);
            generator.initialize(params);
            final KeyPair keyPair = generator.generateKeyPair();

            SphincsSignatureService signatureService = new SphincsSignatureService();
            final Optional<KeyPair> signerKeyPairOpt = signatureService.loadKeyPairFromKeyStore(signerKeystorePath, signerKeyStorePass);
            if(!signerKeyPairOpt.isPresent()) throw new RuntimeException("Signature KeyPair was empty");
            KeyPair signerKeyPair = signerKeyPairOpt.get();

            ExtensionsGenerator extGenerator = new ExtensionsGenerator();
            extGenerator.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
            extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.encipherOnly));

            X509Certificate cert = generateCertificate(new X500Name(Identifiers.ROOTNAME), signerKeyPair.getPrivate(),
                    new X500Name(Identifiers.ROOTNAME), new AlgorithmIdentifier(BCObjectIdentifiers.sphincs256_with_SHA512),
                    extGenerator.generate(), keyPair.getPublic());

            X509Certificate[] chain = new X509Certificate[1];
            chain[0] = cert;
            keyStore.setKeyEntry(Identifiers.ALIAS_ASYM, keyPair.getPrivate(), password.toCharArray(), chain);

            try (FileOutputStream fos = new FileOutputStream(name + Identifiers.KEYSTORE_FILE_FORMAT)) {
                keyStore.store(fos, password.toCharArray());
                log.info("Keystore was created successfully with name " + name + Identifiers.KEYSTORE_FILE_FORMAT);
            }
        } catch (Exception e){
            log.error("Keystore creation failed with error: " + e.getMessage());
        }
    }

    public Optional<KeyPair> loadKeyPairFromKeyStore(String filename, String password){
        try {
            KeyStore keyStore = KeyStore.getInstance(Identifiers.KEYSTORE_FORMAT);
            keyStore.load(new FileInputStream(filename), password.toCharArray());
            final BCMcElieceCCA2PrivateKey privateKey = (BCMcElieceCCA2PrivateKey) keyStore.getKey(Identifiers.ALIAS_ASYM, password.toCharArray());
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(Identifiers.ALIAS_ASYM);
            Certificate [] chain = keyStore.getCertificateChain(Identifiers.ALIAS_SIGNATURE);
            final BCMcElieceCCA2PublicKey publicKey = (BCMcElieceCCA2PublicKey) certificate.getPublicKey();
            log.info("KeyPair was successfully loaded from keystore");
            return Optional.of(new KeyPair(publicKey, privateKey));
        } catch (Exception e) {
            log.error("KeyPair could not be loaded with error: " + e.getMessage());
            return Optional.empty();
        }
    }

    public Optional<byte []> encrypt(BCMcElieceCCA2PublicKey publicKey, byte [] data){
        try{
            Cipher cipher = Cipher.getInstance(Identifiers.ASYM_CIPHER, Identifiers.PQCPROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, params);
            return Optional.of(cipher.doFinal(data));
        } catch (Exception e){
            return Optional.empty();
        }
    }

    public Optional<byte []> decrypt(PrivateKey privateKey, byte [] data){
        try{
            Cipher cipher = Cipher.getInstance(Identifiers.ASYM_CIPHER, Identifiers.PQCPROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, params);
            return Optional.of(cipher.doFinal(data));
        }catch (Exception e){
            return Optional.empty();
        }
    }

    private X509Certificate generateCertificate(X500Name signerName, PrivateKey signerKey, X500Name dn, AlgorithmIdentifier sigName,
                                                Extensions extensions, PublicKey pubKey) throws Exception {
        V3TBSCertificateGenerator certGen = new V3TBSCertificateGenerator();

        Calendar calendar = Calendar.getInstance();
        Date validFrom = calendar.getTime();
        calendar.add(Calendar.YEAR, Identifiers.CERT_VALID);
        Date validUntil = calendar.getTime();

        AtomicLong serialNumber = new AtomicLong(Instant.now().toEpochMilli());

        certGen.setSerialNumber(new ASN1Integer(serialNumber.getAndIncrement()));
        certGen.setIssuer(signerName);
        certGen.setSubject(dn);
        certGen.setStartDate(new Time(validFrom));
        certGen.setEndDate(new Time(validUntil));
        certGen.setSignature(sigName);
        certGen.setSubjectPublicKeyInfo(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
        certGen.setExtensions(extensions);

        Signature sig = Signature.getInstance(Identifiers.SPHINCSSHA3ALGO, Identifiers.PQCPROVIDER);
        sig.initSign(signerKey);
        sig.update(certGen.generateTBSCertificate().getEncoded(ASN1Encoding.DER));

        TBSCertificate tbsCert = certGen.generateTBSCertificate();
        ASN1EncodableVector vector = new ASN1EncodableVector();

        vector.add(tbsCert);
        vector.add(sigName);
        vector.add(new DERBitString(sig.sign()));

        return (X509Certificate)CertificateFactory.getInstance("X.509", Identifiers.BCPROVIDER)
                .generateCertificate(new ByteArrayInputStream(new DERSequence(vector).getEncoded(ASN1Encoding.DER)));
    }

}
