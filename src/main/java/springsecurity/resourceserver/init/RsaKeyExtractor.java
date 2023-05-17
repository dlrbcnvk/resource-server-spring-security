package springsecurity.resourceserver.init;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import springsecurity.resourceserver.signature.RsaPublicKeySecuritySigner;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;

@Component
public class RsaKeyExtractor implements ApplicationRunner {

    @Autowired
    private RsaPublicKeySecuritySigner rsaPublicKeySecuritySigner;

    private String password = "pass1234";

    @Override
    public void run(ApplicationArguments args) throws Exception {

        String path = "/Users/joseong-gyu/Desktop/spring/resource-server/src/main/resources/certs/";
        File file = new File(path + "publicKey.txt");

        FileInputStream is = new FileInputStream(path + "apiKey.jks");
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(is, password.toCharArray());
        String alias = "apiKey";
        Key key = keyStore.getKey(alias, password.toCharArray());

        if (key instanceof PrivateKey) {

            Certificate certificate = keyStore.getCertificate(alias);
            PublicKey publicKey = certificate.getPublicKey();
            KeyPair keyPair = new KeyPair(publicKey, (PrivateKey) key);
            rsaPublicKeySecuritySigner.setPrivateKey(keyPair.getPrivate());

            if (!file.exists()) {
                String publicStr = java.util.Base64.getMimeEncoder().encodeToString(publicKey.getEncoded());
                publicStr = "-----BEGIN PUBLIC KEY-----\r\n" + publicStr + "\r\n-----END PUBLIC KEY-----";

                OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(file), Charset.defaultCharset());
                writer.write(publicStr);
                writer.close();
            }
        }
        is.close();
    }
}
