
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class SessionKeyTest2 {
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
}

