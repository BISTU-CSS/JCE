package example;


import com.provider.NDSecProvider;
import com.util.BytesUtil;

import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.util.Random;

public class SignatureExample {


    public static void main(String[] args) throws Exception {
        NDSecProvider baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);//嵌入provider

        KeyPair rsaKeyPair = KeyPairGeneratorExample.RSAKeyPairGenerator(baseProvider);
        KeyPair sm2KeyPair = KeyPairGeneratorExample.SM2KeyPairGenerator(baseProvider);

        String data = "中华人民共和国";
//        byte[] plain = data.getBytes();
        byte[] plain = new byte[1376];
        (new Random()).nextBytes(plain);

//        MD5WithRSA(baseProvider, rsaKeyPair, plain);

//        SHA1WithRSA(baseProvider, rsaKeyPair, plain);
        SHA1WithSM2(baseProvider, sm2KeyPair, plain);

//        SHA224WithRSA(baseProvider, rsaKeyPair, plain);
//        SHA224WithSM2(baseProvider, sm2KeyPair, plain);

//        SHA256WithRSA(baseProvider, rsaKeyPair, plain);
//        SHA256WithSM2(baseProvider, sm2KeyPair, plain);

//        SHA384WithRSA(baseProvider, rsaKeyPair, plain);

//        SHA512WithRSA(baseProvider, rsaKeyPair, plain);

//        SM3WithSM2(baseProvider, sm2KeyPair, plain);
    }

    //修改所有函数为public，返回值为boolean
    public static boolean MD5WithRSA(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
        // 加密数据
//        String data = "12";
//        String data = "中国";

        // 进行签名
        Signature signature = Signature.getInstance("MD5WithRSA", baseProvider);  //进行签名
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("MD5WithRSA", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


    public static boolean SHA1WithRSA(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {

        // 加密数据
//        String data = "123456789";
//        String data = "12";
//        String data = "中国人伟大的中华民族";

        // 进行签名
        Signature signature = Signature.getInstance("SHA1WithRSA", baseProvider);  //进行签名
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA1WithRSA", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


    public static boolean SHA1WithSM2(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
        // 数据
//        String data = "12345678912345612342141242131232";

        //进行签名
        Signature signature = Signature.getInstance("SHA1WithSM2", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA1WithSM2", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


    public static boolean SHA224WithRSA(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {

        // 数据
//        String data = "12345678912345612342141242131232";

        //进行签名
        Signature signature = Signature.getInstance("SHA224WithRSA", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA224WithRSA", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


    public static boolean SHA224WithSM2(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
//        String data = "12345678912345612342141242131232";

        //进行签名
        Signature signature = Signature.getInstance("SHA224WithSM2", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA224WithSM2", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


    public static boolean SHA256WithRSA(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
//        String data = "12345678912345612342141242131232";            //只能32位

        //进行签名
        Signature signature = Signature.getInstance("SHA256WithRSA", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA256WithRSA", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }

    public static boolean SHA256WithSM2(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
//        String data = "12345678912345612342141242131232";

        //进行签名
        Signature signature = Signature.getInstance("SHA256WithSM2", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA256WithSM2", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


    public static boolean SHA384WithRSA(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
//        String data = "12345678912345612342141242131232";

        //进行签名
        Signature signature = Signature.getInstance("SHA384WithRSA", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA384WithRSA", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }

    public static boolean SHA512WithRSA(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
//        String data = "12345678912345612342141242131232";

        //进行签名
        Signature signature = Signature.getInstance("SHA512WithRSA", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SHA512WithRSA", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


    public static boolean SM3WithSM2(NDSecProvider baseProvider, KeyPair keyPair, byte[] data) throws Exception {
//        String data = "12345678912345612342141242131232";

        //进行签名
        Signature signature = Signature.getInstance("SM3WithSM2", baseProvider);
        signature.initSign(keyPair.getPrivate());           // 传入私钥
        signature.update(data);                  // 传入数据

        byte[] out = signature.sign();        //进行签名
        System.out.println("签名length:" + out.length + "     " + BytesUtil.bytes2hex(out));

        //验签
        Signature signatureVerify = Signature.getInstance("SM3WithSM2", baseProvider);
        signatureVerify.initVerify(keyPair.getPublic());    // 传入公钥
        signatureVerify.update(data);            // 传入数据

        boolean flag = signatureVerify.verify(out);
        System.out.println("verify: " + flag);
        return flag;
    }


}
