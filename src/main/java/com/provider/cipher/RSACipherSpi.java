package com.provider.cipher;


import com.jna.api.LibCrypto;
import com.jna.model.rsa.*;
import com.padding.PKCS1Padding;
import com.provider.serialize.rsa.JCERSAPrivateKey;
import org.bouncycastle.util.BigIntegers;
import sun.security.rsa.RSAPrivateCrtKeyImpl;

import javax.crypto.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * RSA加解密接口(非对称加解密)，进行PKCS1填充
 */
public final class RSACipherSpi extends CipherSpi {
    private int opmode;
    private Key key;

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {

        if (input == null) {
            throw new IllegalArgumentException("The input data is null.");
        }

        /**
         * 加密处理逻辑：
         * 密钥模长（1024bits、2048bits）
         * 根据模长算出一个block的字节长度
         *  int mLengh = moudle.length/8
         * 传入数据length/mLength,得到倍数a，余数b
         * 	if(b==0){
         * 		再填充 mLength 个 mLength
         *  }else{
         * 		再填充 mLength-b 个（mLength-b）
         *  }
         * 对得到的padding字节数组列表进行加密
         * 	for(a+1){
         * 		加密s
         * 		.append(s)
         *  }
         * 得到加密数据stringBuffer
         */
        if (opmode == Cipher.ENCRYPT_MODE) {

            // 公钥加密
            if (key instanceof RSAPublicKey) {
                return publicKeyEncrypt(input, inputOffset, inputLen);
            }

            // 私钥加密
            if (key instanceof RSAPrivateCrtKeyImpl
                    || key instanceof JCERSAPrivateKey) {
                return privateKeyEncrypt(input, inputOffset, inputLen);
            }
        }

        /**
         * 解密处理逻辑：
         * 根据模长算出一个block的字节长度
         *  int mLengh = moudle.length/8
         * 把传入的加密数据切分成 数据长度length/mLength的整数a个数据，组成字节数组列表
         * 对数组列表解密
         * 	for(a){
         * 		循环解密s
         * 		.append(s)
         *  }
         * 	得到解密数据sb
         * 	去除padding，得到解密数据
         */
        if (opmode == Cipher.DECRYPT_MODE) {

            // 私钥解密
            if (key instanceof RSAPrivateCrtKeyImpl
                    || key instanceof JCERSAPrivateKey) {
                return privateKeyDecrypt(input, inputOffset, inputLen);
            }

            // 公钥解密
            if (key instanceof RSAPublicKey) {
                return publicKeyDecrypt(input, inputOffset, inputLen);
            }
        }

        return null;
    }


    // 公钥加密
    private byte[] publicKeyEncrypt(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        RSAPublicKey k = (RSAPublicKey) key;
        byte[] m = BigIntegers.asUnsignedByteArray(k.getModulus());
        byte[] e = k.getPublicExponent().toByteArray();
        int bits = k.getModulus().bitLength();

        IRSArefPublicKey publicKey;
        if (bits >= 2048) {
            publicKey = new RSArefPublicKeyEx(bits, m, e);
        } else {
            publicKey = new RSArefPublicKeyLite(bits, m, e);
        }

        // 一个block字节长度
        int mlength = 256;
        List<byte[]> list = paddingArrays(input, inputLen, mlength - 11);

        byte[] result = new byte[list.size() * mlength];
        //加密模式
        LibCrypto libCrypto = new LibCrypto();
        for (int i = 0; i < list.size(); i++) {
            byte[] temp = libCrypto.rsaExternalPublicKey(publicKey, list.get(i));
            System.arraycopy(temp, 0, result, i * mlength, mlength);
        }

        return result;
    }


    // 私钥解密
    private byte[] privateKeyDecrypt(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        IRSArefPrivateKey privateKey = (IRSArefPrivateKey) genPrivateKey(key);

        // 一个block字节长度
        int mlength = 256;
        //数据做切分，生成List<byte[]>，循环做解密
        List<byte[]> list = mpaddingArrays(input, inputLen, mlength);

        PKCS1Padding pkcs1 = new PKCS1Padding(2048, false, false);

        int dataLength = 0;
        byte[] result = new byte[list.size() * mlength];
        //解密模式
        LibCrypto libCrypto = new LibCrypto();
        for (byte[] aList : list) {
            byte[] temp = libCrypto.rsaExternalPrivateKey(privateKey, aList);

            byte[] data = pkcs1.processBlock(temp, 0, temp.length);
            System.arraycopy(data, 0, result, dataLength, data.length);

            dataLength += data.length;
        }

        byte[] finalResult = new byte[dataLength];
        System.arraycopy(result, 0, finalResult, 0, dataLength);

        return finalResult;
    }


    // 私钥加密
    private byte[] privateKeyEncrypt(byte[] input, int inputOffset, int inputLen) throws BadPaddingException, IllegalBlockSizeException {
        IRSArefPrivateKey privateKey = (IRSArefPrivateKey) genPrivateKey(key);

        // 一个block字节长度
        int mlength = 128;
        List<byte[]> list = paddingArrays(input, inputLen, mlength - 11);

        byte[] result = new byte[list.size() * mlength];
        //加密模式
        LibCrypto libCrypto = new LibCrypto();
        for (int i = 0; i < list.size(); i++) {
            byte[] temp = libCrypto.rsaExternalPrivateKey(privateKey, list.get(i));
            System.arraycopy(temp, 0, result, i * mlength, mlength);
        }

        return result;
    }


    // 公钥解密
    private byte[] publicKeyDecrypt(byte[] input, int inputOffset, int inputLen) throws BadPaddingException, IllegalBlockSizeException {
        RSAPublicKey k = (RSAPublicKey) key;
        byte[] m = BigIntegers.asUnsignedByteArray(k.getModulus());
        byte[] e = k.getPublicExponent().toByteArray();
        int bits = k.getModulus().bitLength();

        IRSArefPublicKey publicKey;
        if (bits > 2048) {
            publicKey = new RSArefPublicKeyEx(bits, m, e);
        } else {
            publicKey = new RSArefPublicKeyLite(bits, m, e);
        }

        // 一个block字节长度
        int mlength = 128;
        //数据做切分，生成List<byte[]>，循环做解密
        List<byte[]> list = mpaddingArrays(input, inputLen, mlength);

        PKCS1Padding pkcs1 = new PKCS1Padding(1024, false, false);

        int dataLength = 0;
        byte[] result = new byte[list.size() * mlength];
        //解密模式
        LibCrypto libCrypto = new LibCrypto();
        for (byte[] aList : list) {
            byte[] temp = libCrypto.rsaExternalPublicKey(publicKey, aList);

            byte[] data = pkcs1.processBlock(temp, 0, temp.length);
            System.arraycopy(data, 0, result, dataLength, data.length);

            dataLength += data.length;
        }

        byte[] finalResult = new byte[dataLength];
        System.arraycopy(result, 0, finalResult, 0, dataLength);

        return finalResult;
    }


    public static List<byte[]> paddingArrays(byte[] input, int inputLen, int mlength) throws BadPaddingException, IllegalBlockSizeException {
        int a = inputLen / mlength;//获取输入长度/模长的倍数
        int b = inputLen % mlength;//获取输入长度/模长的余数

        PKCS1Padding pkcs1 = new PKCS1Padding(2048, true, false);
        List<byte[]> list = new ArrayList<>();

        for (int i = 0; i < a; i++) {
            byte[] temp = new byte[mlength];
            System.arraycopy(input, i * mlength, temp, 0, mlength);
            byte[] result = pkcs1.processBlock(temp, 0, temp.length);
            list.add(result);
        }
        if (b > 0) {
            byte[] temp = new byte[b];
            System.arraycopy(input, a * mlength, temp, 0, b);
            byte[] result = pkcs1.processBlock(temp, 0, temp.length);
            list.add(result);
        }

        return list;
    }

    /**
     * 根据加密后的数据，进行切分，最后一段数据，去除填充
     *
     * @param input
     * @param inputLen
     * @param mlength
     * @return
     */
    public static List<byte[]> mpaddingArrays(byte[] input, int inputLen, int mlength) {
        int a = inputLen / mlength;//获取输入长度/模长的倍数

        List<byte[]> list = new ArrayList<>();

        for (int i = 0; i < a; i++) {
            byte[] temp = new byte[mlength];
            System.arraycopy(input, i * mlength, temp, 0, mlength);
            list.add(temp);
        }
        return list;
    }

    public static Object genPrivateKey(Key key) {
        if (key instanceof RSAPrivateCrtKeyImpl) {
            RSAPrivateCrtKeyImpl k = (RSAPrivateCrtKeyImpl) key;
            byte[] n = BigIntegers.asUnsignedByteArray(k.getModulus());
            byte[] e = k.getPublicExponent().toByteArray();
            byte[] d = k.getPrivateExponent().toByteArray();
            byte[] q1 = k.getPrimeP().toByteArray();
            byte[] q2 = k.getPrimeQ().toByteArray();
            byte[] p1 = k.getPrimeExponentP().toByteArray();
            byte[] p2 = k.getPrimeExponentQ().toByteArray();

            byte[] coef = k.getCrtCoefficient().toByteArray();

            return new RSArefPrivateKeyEx(n, e, d, p1, p2, q1, q2, coef);
        }

        if (key instanceof JCERSAPrivateKey) {
            JCERSAPrivateKey k = (JCERSAPrivateKey) key;
            byte[] n = BigIntegers.asUnsignedByteArray(k.getModulus());
            byte[] e = k.getPublicExponent().toByteArray();
            byte[] d = k.getPrivateExponent().toByteArray();
            byte[] q1 = k.getPrimeP().toByteArray();
            byte[] q2 = k.getPrimeQ().toByteArray();
            byte[] p1 = k.getPrimeExponentP().toByteArray();
            byte[] p2 = k.getPrimeExponentQ().toByteArray();

            byte[] coef = k.getCrtCoefficient().toByteArray();

            return new RSArefPrivateKeyLite(n, e, d, p1, p2, q1, q2, coef);
        }

        return null;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        return 0;
    }

    @Override
    protected int engineGetBlockSize() {

        return 0;
    }

    @Override
    protected byte[] engineGetIV() {

        return null;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {

        return 0;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {

        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.key = key;
        this.opmode = opmode;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = key;
        this.opmode = opmode;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = key;
        this.opmode = opmode;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

        return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {

        return 0;
    }


}
