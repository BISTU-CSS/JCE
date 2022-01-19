package example;


import com.provider.NDSecProvider;
import com.util.BytesUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Random;

public class MacExample {

    public static void main(String[] args) throws Exception {
        NDSecProvider baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);
        int keysize = 128;
//        byte plain[] = {(byte) 0xe8, (byte) 0x3d, (byte) 0x17, (byte) 0x15, (byte) 0xac, (byte) 0xf3,
//                (byte) 0x48, (byte) 0x63, (byte) 0xac, (byte) 0xeb, (byte) 0x93,
//                (byte) 0xe0, (byte) 0xe5, (byte) 0xab, (byte) 0x8b, (byte) 0x90};

        byte[] plain = new byte[13];
        (new Random()).nextBytes(plain);

        SM1Mac(baseProvider, keysize, plain);
        SMS4Mac(baseProvider, keysize, plain);
    }

    public static void SM1Mac(NDSecProvider baseProvider, int keysize, byte[] plain) throws NoSuchAlgorithmException, InvalidKeyException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM1", baseProvider);
        keyGenerator.init(keysize);
        SecretKey key = keyGenerator.generateKey();

        Mac mac = Mac.getInstance("SM1", baseProvider);
        mac.init(key);
        mac.update(plain);

        byte[] output = mac.doFinal();

        System.out.println(output.length);
        System.out.println(BytesUtil.bytes2hex(output));
    }


    public static void SMS4Mac(NDSecProvider baseProvider, int keysize, byte[] plain) throws NoSuchAlgorithmException, InvalidKeyException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("SMS4", baseProvider);
        keyGenerator.init(keysize);
        SecretKey key = keyGenerator.generateKey();

        Mac mac = Mac.getInstance("SMS4", baseProvider);
        mac.init(key);
        mac.update(plain);

        byte[] output = mac.doFinal();

        System.out.println(output.length);
        System.out.println(BytesUtil.bytes2hex(output));

    }


}
