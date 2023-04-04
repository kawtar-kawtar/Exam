public class Main {
    public static void main(String[] args) throws Exception {
        String encryptedMsg = CryptoApp.cryptwithRSA();
        System.out.println("Message crypté : " + encryptedMsg);

        String decryptedMsg = CryptoApp.decryptwithRSA(encryptedMsg);
        System.out.println("Message décrypté : " + decryptedMsg);

        String encryptedMsgAES = CryptoApp.cryptwithAES();
        System.out.println("Message crypté : " + encryptedMsgAES);

        String cryptedEncodedMsg = "aL00CTTqPkqmtRK2P9OoYQ==";
        String decryptedMsgAES = CryptoApp.decryptwithAES(cryptedEncodedMsg);
        System.out.println("Message décrypté : " + decryptedMsgAES);



    }

}
