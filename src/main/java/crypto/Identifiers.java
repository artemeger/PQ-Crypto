package crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.security.Provider;

public final class Identifiers {

    public static final Provider PQCPROVIDER = new BouncyCastlePQCProvider();
    public static final Provider BCPROVIDER = new BouncyCastleProvider();
    public static final String ROOTNAME = "CN=refaine.com";
    public static final int CERT_VALID = 100;
    public static final String SPHINCSSHA3ALGO = "SHA3-512WITHSPHINCS256";
    public static final String SIGNATUREALGO = "SHA3-512withSPHINCS256";
    public static final String SHA3NAME = "SHA3-256";
    public static final String ALIAS_SIGNATURE = "SPHINCS-Keypair";
    public static final String KEYSTORE_FORMAT = "UBER";
    public static final String KEYSTORE_FILE_FORMAT = ".ubr";
    public static final String SYMALGORITHM = "Threefish-1024";
    public static final int KEYSIZE = 1024;
    public static final String ALIAS_SYM = "Threefish-Key";
    public static final String SYM_CIPHER = "Threefish-1024/CBC/PKCS7Padding";
    public static final String ALIAS_ASYM = "McElice-Key";

}
