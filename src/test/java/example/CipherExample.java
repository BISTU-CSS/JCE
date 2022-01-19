package example;


import com.provider.NDSecProvider;
import com.util.BytesUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

public class CipherExample {


    public static void main(String[] args) throws Exception {

        //添加String input
        String input = "abcde";
//        byte[] plain = input.getBytes();

        byte[] plain = new byte[155];
        (new Random()).nextBytes(plain);


//        String input="aabbccdcbbbdbakhjhkhk";
        // 对称
    //    AESCipher(plain);          // SDF暂不支持
        while(true){
            SM1Cipher(plain);
        }
//        SM4Cipher(input);

//        SSF33Cipher(plain);        // SDF暂不支持


        // 非对称
        //    RSACipher(plain);
//        for(int i =0;i<20;i++)
//        SM2Cipher(plain);
    }

    //private改public，返回值为bool
    public static boolean AESCipher(byte[] plain) throws Exception {

        // 128字节长度的数据
//        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30, 45, -15, -109, 102, -118, 109, -93, -122, -51, 99, -114, -93, -67, 8, 37, 26, -123, 16, 3, -21, -50, -2, -40, -125, 95, -52, 25, -41, -58, 8, 16, -13, 85, 1, 76, 84, 114, 70, 7, -32, 96, -83, -98, -116, 38, -120, -99, -77, 31, -27, 49, -97, -121, 57, 67, -84, 20, -72, -31, -63, 82, -117, 57, -33, -42, 25, 93, 8, 124, -31, -63, 24, 117, -118, 72, 53, 126, 70, -79, -112, 53, -110, -51, -67, -64, 48, 79, 71, 99, 93, 86, -78, 127, 77, 126, 26, 72, -15, 31, 10, -77, -87, -88, -127, -5, -97, 124, 93, -97, -25, 24, 121};
//        byte[] plain = "hongyihongyihong".getBytes();
//        byte[] plain=input.getBytes();
//        byte[] plain = "abcdasdfasdfdsaf444".getBytes();
        System.out.println("原数据: " + plain.length);//+ ":" + Arrays.toString(plain));

        NDSecProvider baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);                //嵌入provider

        // 获取钥匙
        SecretKey secretKey = KeyGeneratorExample.AESKeyGenerator(baseProvider);

        // 加密
        Cipher cipher = Cipher.getInstance("AES", baseProvider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypts = cipher.doFinal(plain);
        System.out.println("加密结果: " + encrypts.length + ":" + Arrays.toString(encrypts));

        // 解密
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypts = cipher.doFinal(encrypts);
        System.out.println("解密结果: " + decrypts.length + ":" + Arrays.toString(decrypts));

        // 对比结果
        System.out.println("对比结果: " + Arrays.equals(plain, decrypts));
        return Arrays.equals(plain, decrypts);
    }


    public static boolean SM1Cipher(byte[] plain) throws Exception {
        //需要加密的数据
//        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -31};
//        byte[] plain = "这是一个中文测试用例一共十六个字".getBytes();
//        byte[] plain=input.getBytes();
        System.out.println("原数据: " + plain.length);//+ ":" + Arrays.toString(plain));

        NDSecProvider baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);                //嵌入provider

        // 获取钥匙
        SecretKey secretKey = KeyGeneratorExample.SM1KeyGenerator(baseProvider);

        //加密过程
        Cipher cipher = Cipher.getInstance("SM1", baseProvider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypts = cipher.doFinal(plain);
        System.out.println("加密结果: " + encrypts.length + ":" + Arrays.toString(encrypts));

        //开始解密过程
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypts = cipher.doFinal(encrypts);
        System.out.println("解密结果: " + decrypts.length + ":" + Arrays.toString(decrypts));

        // 对比结果
        System.out.println("对比结果: " + Arrays.equals(plain, decrypts));

        return Arrays.equals(plain, decrypts);
    }


    public static boolean SM4Cipher(byte[] plain) throws Exception {
        //需要加密的数据
//        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30, 45, -15, -109, 102, -118, 109, -93, -122, -51, 99, -114, -93, -67, 8, 37, 26, -123, 16, 3, -21, -50, -2, -40, -125, 95, -52, 25, -41, -58, 8, 16, -13, 85, 1, 76, 84, 114, 70, 7, -32, 96, -83, -98, -116, 38, -120, -99, -77, 31, -27, 49, -97, -121, 57, 67, -84, 20, -72, -31, -63, 82, -117, 57, -33, -42, 25, 93, 8, 124, -31, -63, 24, 117, -118, 72, 53, 126, 70, -79, -112, 53, -110, -51, -67, -64, 48, 79, 71, 99, 93, 86, -78, 127, 77, 126, 26, 72, -15, 31, 10, -77, -87, -88, -127, -5, -97, 124, 93, -97, -25, 24, 121};
//        byte[] plain = "伟大的中华民族".getBytes();
//        byte[] plain=input.getBytes();
        System.out.println("原数据: " + plain.length);//+ ":" + Arrays.toString(plain));

        NDSecProvider baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);                //嵌入provider

        // 获取钥匙
        SecretKey secretKey = KeyGeneratorExample.SM4KeyGenerator(baseProvider);

        //开始加密过程
        Cipher cipher = Cipher.getInstance("SM4", baseProvider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypts = cipher.doFinal(plain);
        System.out.println("加密结果: " + encrypts.length + ":" + Arrays.toString(encrypts));

        //开始解密过程
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypts = cipher.doFinal(encrypts);
        System.out.println("解密结果: " + decrypts.length + ":" + Arrays.toString(decrypts));

        // 对比结果
        System.out.println("对比结果: " + Arrays.equals(plain, decrypts));
        return Arrays.equals(plain, decrypts);
    }


    public static boolean SSF33Cipher(byte[] plain) throws Exception {
        //需要加密的数据
//        byte[] plain=input.getBytes();
//        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30, 45, -15, -109, 102, -118, 109, -93, -122, -51, 99, -114, -93, -67, 8, 37, 26, -123, 16, 3, -21, -50, -2, -40, -125, 95, -52, 25, -41, -58, 8, 16, -13, 85, 1, 76, 84, 114, 70, 7, -32, 96, -83, -98, -116, 38, -120, -99, -77, 31, -27, 49, -97, -121, 57, 67, -84, 20, -72, -31, -63, 82, -117, 57, -33, -42, 25, 93, 8, 124, -31, -63, 24, 117, -118, 72, 53, 126, 70, -79, -112, 53, -110, -51, -67, -64, 48, 79, 71, 99, 93, 86, -78, 127, 77, 126, 26, 72, -15, 31, 10, -77, -87, -88, -127, -5, -97, 124, 93, -97, -25, 24, 121};
        System.out.println("原数据: " + plain.length);// + ":" + Arrays.toString(plain));

        NDSecProvider baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);                //嵌入provider

        // 获取钥匙
        SecretKey secretKey = KeyGeneratorExample.SSF33KeyGenerator(baseProvider);

        //开始加密过程
        Cipher cipher = Cipher.getInstance("SSF33", baseProvider);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypts = cipher.doFinal(plain);
        System.out.println("加密结果: " + encrypts.length + ":" + Arrays.toString(encrypts));

        //开始解密过程
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypts = cipher.doFinal(encrypts);
        System.out.println("解密结果: " + decrypts.length + ":" + Arrays.toString(decrypts));

        // 对比结果
        System.out.println("对比结果: " + Arrays.equals(plain, decrypts));
        return Arrays.equals(plain, decrypts);
    }


    public static boolean RSACipher(byte[] plain) throws Exception {
        //需要加密的数据
//		byte[] plain = {1};
//        byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30, 45, -15, -109, 102, -118, 109, -93, -122, -51, 99, -114, -93, -67, 8, 37, 26, -123, 16, 3, -21, -50, -2, -40, -125, 95, -52, 25, -41, -58, 8, 16, -13, 85, 1, 76, 84, 114, 70, 7, -32, 96, -83, -98, -116, 38, -120, -99, -77, 31, -27, 49, -97, -121, 57, 67, -84, 20, -72, -31, -63, 82, -117, 57, -33, -42, 25, 93, 8, 124, -31, -63, 24, 117, -118, 72, 53, 126, 70, -79, -112, 53, -110, -51, -67, -64, 48, 79, 71, 99, 93, 86, -78, 127, 77, 126, 26, 72, -15, 31, 10, -77, -87, -88, -127, -5, -97, 124, 93, -97, -25, 24, 121};
//        byte[] plain = "hongyi".getBytes();
//        byte[] plain = "中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共中华人名共和国中华人名共和国中华共和国中和国中名共和国中华共弘毅".getBytes();
//        byte[] plain = "中国山东省强大".getBytes();
//        byte[] plain=input.getBytes();
        System.out.println("原数据: " + plain.length);//+ ":" + Arrays.toString(plain));

        NDSecProvider baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);                //嵌入provider

        // 获取钥匙对
        KeyPair keyPair = KeyPairGeneratorExample.RSAKeyPairGenerator(baseProvider);

        //开始加密过程
        Cipher cipher = Cipher.getInstance("RSA", baseProvider);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypts = cipher.doFinal(plain);
        System.out.println("加密结果: " + encrypts.length + ":" + Arrays.toString(encrypts));
        System.out.println("加密: " + BytesUtil.bytes2hex(encrypts));

        //开始解密过程
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypts = cipher.doFinal(encrypts);
        System.out.println("解密结果: " + decrypts.length + ":" + Arrays.toString(decrypts));
        System.out.println("解密: " + new String(decrypts));

        // 对比结果
        System.out.println("对比结果: " + Arrays.equals(plain, decrypts));
        return Arrays.equals(plain, decrypts);
    }


    public static boolean SM2Cipher(byte[] plain) throws Exception {
//        byte[] plain = "1234567890".getBytes();
//        byte[] plain = "这是一段中文测试用例".getBytes();
//        byte[] plain = "中国山东".getBytes();
//        byte[] plain=input.getBytes();
        System.out.println("原数据: " + plain.length);// + ":" + Arrays.toString(plain));

        NDSecProvider baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);                //嵌入provider

        // 获取钥匙对
        KeyPair keyPair = KeyPairGeneratorExample.SM2KeyPairGenerator(baseProvider);

        //开始加密过程
        Cipher cipher = Cipher.getInstance("SM2", baseProvider);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] encrypts = cipher.doFinal(plain);
        System.out.println("加密结果: " + encrypts.length + ":" + Arrays.toString(encrypts));
        System.out.println("加密: " + BytesUtil.bytes2hex(encrypts));

        //开始解密过程
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypts = cipher.doFinal(encrypts);
        System.out.println("解密结果: " + decrypts.length + ":" + Arrays.toString(decrypts));
        System.out.println("解密: " + new String(decrypts));

        // 对比结果
        System.out.println("对比结果: " + Arrays.equals(plain, decrypts));
        return Arrays.equals(plain, decrypts);
    }


}
