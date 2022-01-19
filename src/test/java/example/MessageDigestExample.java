package example;

import com.provider.NDSecProvider;
import com.util.BytesUtil;

import java.security.MessageDigest;
import java.security.Security;

public class MessageDigestExample {


    public static void main(String[] args) throws Exception {
        String input ="abcd";
        byte[] plain = input.getBytes();

        NDSecProvider baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);
        MD5MessageDigest(plain,baseProvider);
//        SHA1MessageDigest();
//        SHA224MessageDigest();
//        SHA256MessageDigest();
//        SHA384MessageDigest();
//        SHA512MessageDigest();
//
//        SHA3224MessageDigest();
//        SHA3256MessageDigest();
//        SHA3384MessageDigest();
//        SHA3512MessageDigest();

        // TODO SM3杂凑的区别
//        SM3MessageDigest();
//        SM3WithIDMessageDigest();
//        SM3WithoutIDMessageDigest();
    }


    public static void MD5MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {

//        String input = "原始数据原始数据";



        MessageDigest messageDigest = MessageDigest.getInstance("MD5", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("MD5: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA1MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "12345678912345612342141242131232";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA1", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA1: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA224MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";
//
//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA224", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA224: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA256MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {

//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA256", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA256: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA384MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA384", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA384: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA512MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA512", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA512: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA3224MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA3224", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA3224: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA3256MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA3256", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA3256: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA3384MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA3384", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA3384: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SHA3512MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA3512", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SHA3512: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SM3MessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SM3", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SM3: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SM3WithIDMessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SM3WithID", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SM3WithID: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


    public static void SM3WithoutIDMessageDigest(byte[] plain, NDSecProvider provider) throws Exception {
//        String input = "原始数据";

//        BaseProvider provider = new BaseProvider();
//        Security.addProvider(provider);

        MessageDigest messageDigest = MessageDigest.getInstance("SM3WithoutID", provider);
        messageDigest.update(plain);

        byte[] output = messageDigest.digest();
        System.out.println("SM3WithoutID: " + output.length + " : " + BytesUtil.bytes2hex(output));
    }


}
