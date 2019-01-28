import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
//import org.junit.jupiter.api.Test;
//import static org.junit.jupiter.api.Assertions.*;


public class SessionKey {
    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator kGen = KeyGenerator.getInstance("AES");
        kGen.init(keylength);
        this.secretKey = kGen.generateKey();
    }

    public SessionKey(String encodedkey){
      byte[] Base64Key = Base64.getDecoder().decode(encodedkey);
      this.secretKey = new SecretKeySpec(Base64Key,0,Base64Key.length, "AES");
      }

      public SessionKey(byte[] Key) {
        this.secretKey = new SecretKeySpec(Key,"AES");
      }

    public SecretKey getSecretKey() {
        return this.secretKey;
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(this.secretKey.getEncoded());
    }

}

/*class SessionKeyTest {
    @Test
    void equalkey() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(key1.encodeKey());
        assertEquals(key1.getSecretKey(),key2.getSecretKey());
    }

    @Test
    void keylength() throws NoSuchAlgorithmException {
        SessionKey key1 = new SessionKey(128);
        SessionKey key2 = new SessionKey(192);
        SessionKey key3 = new SessionKey(256);
        assertEquals(128, key1.getSecretKey().getEncoded().length *8);
        assertEquals(192, key2.getSecretKey().getEncoded().length *8);
        assertEquals(256, key3.getSecretKey().getEncoded().length *8);
    }
*/
