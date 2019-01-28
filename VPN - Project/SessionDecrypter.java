import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static javax.crypto.Cipher.*;

public class SessionDecrypter {
    private SessionKey Sessiondec;
    private IvParameterSpec ivdec;
    private Cipher Ciph;

    public SessionDecrypter(String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.Ciph = getInstance("AES/CTR/NoPadding");
        this.Sessiondec = new SessionKey(key);
        this.ivdec = new IvParameterSpec(Base64.getDecoder().decode(iv));
        this.Ciph.init(Cipher.DECRYPT_MODE, this.Sessiondec.getSecretKey(),this.ivdec);
    }

    public SessionDecrypter(SessionKey sKey, IvParameterSpec sIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.Sessiondec = sKey;
        this.ivdec = sIV;
        this.Ciph = getInstance("AES/CTR/NoPadding");
        this.Ciph.init(Cipher.DECRYPT_MODE, this.Sessiondec.getSecretKey(),this.ivdec);
    }


    public CipherInputStream openCipherInputStream(InputStream input){
        CipherInputStream openCipherInputSteam = new CipherInputStream(input,Ciph);
        return openCipherInputSteam;
    }
}
