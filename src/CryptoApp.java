import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoApp {
    public  static String cryptwithRSA()  throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream("certificate.cert");
        X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(fileInputStream);
        PublicKey publicKey = cert.getPublicKey();
        String message = "Bonjour_3A_LIA";
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey1 = keyFactory.generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
        Cipher cipher=Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey1);
        byte[] enryptedMessage = cipher.doFinal(message.getBytes());
        String encodedMSG = Base64.getEncoder().encodeToString(enryptedMessage);
        return  encodedMSG;
    }
    public static String decryptwithRSA(String CryptedEncodedMsg) throws Exception {
        FileInputStream fileInputStream = new FileInputStream("examen.jks");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(fileInputStream, "123456".toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("examen", "123456".toCharArray());
        byte[] encrypted = Base64.getDecoder().decode(CryptedEncodedMsg);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMSG = cipher.doFinal(encrypted);
        return new String(decryptedMSG);
    }
    public static String cryptwithAES() throws Exception {
        String message="Message Clair";
        String secret = "Bonjour_3A_LIA12";
        SecretKey secretKey = new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
        byte[] codkey=secretKey.getEncoded();
        System.out.println(Base64.getEncoder().encodeToString(codkey));
        Cipher cipher =Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKey);
        byte[] encryptMsg=cipher.doFinal(message.getBytes());
        String encodeEncryptMsg= Base64.getEncoder().encodeToString(encryptMsg);
        return encodeEncryptMsg;
    }
    public static String decryptwithAES(String CryptedEncodedMsg) throws Exception {
        byte[] decodedMsg = Base64.getDecoder().decode(CryptedEncodedMsg);
        String secret = "Bonjour_3A_LIA12";
        SecretKey secretKey = new SecretKeySpec(secret.getBytes(),0,secret.length(),"AES");
        Cipher cipher=Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] decryptedMsg =cipher.doFinal(decodedMsg);
        return new String(decryptedMsg);
    }




}
