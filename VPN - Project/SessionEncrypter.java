import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static javax.crypto.Cipher.*;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private IvParameterSpec iv;
    private Cipher Ciph;

    public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.sessionKey = new SessionKey(keylength);
        this.Ciph = getInstance("AES/CTR/NoPadding");
        byte [] BlockByte = new byte[Ciph.getBlockSize()];
        SecureRandom RVal = new SecureRandom();
        RVal.nextBytes(BlockByte);

        this.iv = new IvParameterSpec(BlockByte);
        this.Ciph.init(ENCRYPT_MODE,sessionKey.getSecretKey(),iv);
    }

    public SessionEncrypter(SessionKey skey, IvParameterSpec sIV) throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        this.sessionKey = skey;
        this.iv = sIV;
        this.Ciph = getInstance("AES/CTR/NoPadding");
        this.Ciph.init(ENCRYPT_MODE,sessionKey.getSecretKey(),iv);
    }

    public String encodeKey() {return this.sessionKey.encodeKey();}

    public String encodeIV(){return Base64.getEncoder().encodeToString(iv.getIV());}

    public CipherOutputStream openCipherOutputStream(OutputStream output) {
        CipherOutputStream openCipherOutputsteam = new CipherOutputStream(output, Ciph);
        return openCipherOutputsteam;

    }
}
