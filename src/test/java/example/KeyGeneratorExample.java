package example;

import com.provider.NDSecProvider;
import com.util.BytesUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.Security;

public class KeyGeneratorExample {

    public static void main(String[] args) throws Exception {

        NDSecProvider baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);

        AESKeyGenerator(baseProvider);

        SM1KeyGenerator(baseProvider);

        SM4KeyGenerator(baseProvider);

        SMS4KeyGenerator(baseProvider);

        SSF33KeyGenerator(baseProvider);
    }


    public static SecretKey AESKeyGenerator(NDSecProvider baseProvider) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", baseProvider);
        keyGenerator.init(256);

        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey.getAlgorithm() + " : " + BytesUtil.bytes2hex(secretKey.getEncoded()));

        return secretKey;
    }


    public static SecretKey SM1KeyGenerator(NDSecProvider baseProvider) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM1", baseProvider);
        SecureRandom random = SecureRandom.getInstance("RND", baseProvider);
//        keyGenerator.init(128);
        keyGenerator.init(128, random);

        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey.getAlgorithm() + " : " + BytesUtil.bytes2hex(secretKey.getEncoded()));

        return secretKey;
    }


    public static SecretKey SM4KeyGenerator(NDSecProvider baseProvider) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", baseProvider);
        keyGenerator.init(128);

        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey.getAlgorithm() + " : " + BytesUtil.bytes2hex(secretKey.getEncoded()));

        return secretKey;
    }


    public static SecretKey SMS4KeyGenerator(NDSecProvider baseProvider) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SMS4", baseProvider);
        keyGenerator.init(128);

        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey.getAlgorithm() + " : " + BytesUtil.bytes2hex(secretKey.getEncoded()));

        return secretKey;
    }


    public static SecretKey SSF33KeyGenerator(NDSecProvider baseProvider) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SSF33", baseProvider);
        keyGenerator.init(128);

        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey.getAlgorithm() + " : " + BytesUtil.bytes2hex(secretKey.getEncoded()));

        return secretKey;
    }


}
