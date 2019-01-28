import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    //public static final String serverHost = "localhost";
    //public static final int serverPort = 4412;

    /* The final destination */
    //public static String targetHost = "localhost";
    //public static int targetPort = 6789;

    public static X509Certificate Clientcert;
    public static X509Certificate Servercert;

    public static String serverHost;
    public static int serverPort;

    public static String targetHost;
    public static int targetPort;

    public static SessionDecrypter Sdecrypt;
    public static SessionEncrypter SessionCrypt;




    public static void Handshake(Socket socket, String ClientFile, String value) throws IOException, CertificateException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", value);
        HandMessage.putParameter("Certificate", Base64.getEncoder().encodeToString(VerifyCertificate.getCertificate(ClientFile).getEncoded()));
        HandMessage.send(socket);
    }

    public static void HandClientverify(Socket socket, String caFile) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
            if(HandMessage.getParameter("MessageType").equals("ClientHello")) {
                String cCert = HandMessage.getParameter("Certificate");
                Clientcert = VerifyCertificate.createCertificate(cCert);
                try{
                    VerifyCertificate.getVerify(VerifyCertificate.getCertificate(caFile),Clientcert);
                    Logger.log("Client Verify Sucess");
                }
                catch(Exception E){
                    socket.close();
                    Logger.log("Error Client Verify");
                }

            }else{
                socket.close();
                Logger.log("MessageType No Match");
            }
    }


    public static void Handserververify(Socket socket, String caFile) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("ServerHello")) {
            String cCert = HandMessage.getParameter("Certificate");
            Servercert = VerifyCertificate.createCertificate(cCert);
            try{
                VerifyCertificate.getVerify(VerifyCertificate.getCertificate(caFile),Servercert);
                Logger.log("Server Verify Sucess");
            }
            catch(Exception E){
                socket.close();
                Logger.log("Error Server Verify");
            }

        }else{
            socket.close();
            Logger.log("MessageType No Match");
        }
    }


    public static void HandForward(Socket socket, String targetHost, String targetPort) throws IOException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "Forward");
        HandMessage.putParameter("TargetHost", targetHost);
        HandMessage.putParameter("TargetPort", targetPort);
        HandMessage.send(socket);
        Logger.log("Portforwarding Sucess");
    }

    public static void ForwardVerify(Socket socket) throws IOException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("Forward")) {
            targetHost = HandMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(HandMessage.getParameter("TargetPort"));
           // Logger.log("Sucess with TargetHost: " + targetHost + " and TargetPort: " + targetPort);
        }else {
            socket.close();
        }
    }

    public static void Session(Socket socket, String sHost, String server) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "Session");
        SessionKey Skey = new SessionKey(128);
        IvParameterSpec sIV = new IvParameterSpec(new SecureRandom().generateSeed(16));

        PublicKey PublicClient = Clientcert.getPublicKey();

        HandMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(Skey.getSecretKey().getEncoded(), PublicClient)));
        HandMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(sIV.getIV(), PublicClient)));

        SessionCrypt = new SessionEncrypter(Skey,sIV);
        Sdecrypt = new SessionDecrypter(Skey, sIV);
        System.out.println(Skey.encodeKey());
        System.out.println(Base64.getEncoder().encodeToString(sIV.getIV()));

        //HandMessage.putParameter("SessionKey", new String(HandshakeCrypto.encrypt(Skey.getBytes(), PublicClient)));
        //HandMessage.putParameter("SessionIV", new String(HandshakeCrypto.encrypt(sIV.getBytes(), PublicClient)));
        HandMessage.putParameter("ServerHost", sHost);
        HandMessage.putParameter("ServerPort", server);
        HandMessage.send(socket);
    }

    public static void RSession(Socket socket, String PrivKey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("Session")){
            String sKey = HandMessage.getParameter("SessionKey");
            String sIV = HandMessage.getParameter("SessionIV");
            serverHost = HandMessage.getParameter("ServerHost");
            serverPort = Integer.parseInt(HandMessage.getParameter("ServerPort"));

            byte[] sKeyhalfdecrypt = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sKey),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));
            byte[] sivhalfdecrypt = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sIV),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));

            //byte[] sKeyhalfdecrypt = HandshakeCrypto.decrypt(sKey.getBytes(),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));
            //byte[] sivhalfdecrypt = HandshakeCrypto.decrypt(sIV.getBytes(),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));

            SessionCrypt = new SessionEncrypter(new SessionKey((sKeyhalfdecrypt)), new IvParameterSpec(sivhalfdecrypt));
            Sdecrypt = new SessionDecrypter(new SessionKey((sKeyhalfdecrypt)), new IvParameterSpec(sivhalfdecrypt));
            System.out.println(new SessionKey((sKeyhalfdecrypt)).encodeKey());
            System.out.println(Base64.getEncoder().encodeToString(new IvParameterSpec(sivhalfdecrypt).getIV()));
        } else{
            socket.close();
        }
    }

    public static String getTargetHost(){
        return targetHost;
    }

    public static int getTargetPort(){
        return targetPort;
    }

    public static String getServerHost(){
        return serverHost;
    }

    public static int getServerPort(){
        return serverPort;
    }

    public static SessionDecrypter getSessionDecrypter() { return Sdecrypt; }

    public static SessionEncrypter getSessionEncrypter() { return SessionCrypt; }

}
