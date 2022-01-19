package example;


import com.provider.NDSecProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

public class KeyPairGeneratorExample {

    public static void main(String[] args) throws Exception {

        NDSecProvider baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);

        RSAKeyPairGenerator(baseProvider);

        SM2KeyPairGenerator(baseProvider);
    }


    public static KeyPair RSAKeyPairGenerator(NDSecProvider baseProvider) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", baseProvider);
        keyPairGenerator.initialize(2048);


        //生成钥匙对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        System.out.println(keyPair.getPublic().toString());
        System.out.println(keyPair.getPrivate().toString());

        return keyPair;
    }

    public static KeyPair SM2KeyPairGenerator(NDSecProvider baseProvider) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("SM2", baseProvider);
        keyPairGenerator.initialize(256);

        //生成钥匙对
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        System.out.println(keyPair.getPublic().toString());
        System.out.println(keyPair.getPrivate().toString());

        return keyPair;
    }


}
