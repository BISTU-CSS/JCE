package com.provider.signature;


import com.provider.NDSecProvider;
import com.provider.serialize.rsa.JCERSAPrivateKey;
import com.provider.serialize.rsa.JCERSAPublicKey;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Arrays;

public final class SHA512WithRSASignatureSpi extends SignatureSpi {
    private JCERSAPublicKey publicKey;
    private JCERSAPrivateKey privateKey;
    private byte[] datainput;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        //验签
        this.publicKey = (JCERSAPublicKey) publicKey;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        //签名
        this.privateKey = (JCERSAPrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        //传入数据，传入原数据
        this.datainput = b;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        //进行签名，利用私钥

        /**
         * 签名：
         * 	1、先进行哈希后，得到哈希值
         * 	2、然后1中得到的哈希值填充到128Byte
         * 	3、再对2中填充后的数据使用私钥进行加密，得到签名值128Byte
         */
        // 把datainput转换为SHA512哈希值
        NDSecProvider provider = new NDSecProvider();
        Security.addProvider(provider);

        try {
            // SHA512哈希值
            MessageDigest messageDigest = MessageDigest.getInstance("SHA512", provider);
            messageDigest.update(datainput);
            byte[] output = messageDigest.digest();

            // 开始加密过程
            Cipher cipher = Cipher.getInstance("RSA", provider);
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return cipher.doFinal(output);

        } catch (Exception e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        //验签，利用公钥。传入已经签名过的数据
        if (sigBytes == null) {
            return false;
        }

        /**
         * 验签：
         * 	1、先进行哈希后，得到哈希值
         * 	2、对输入的签名值，使用公钥进行解密，然后进行去填充后，得到哈希值
         * 	3、对1和2中的哈希值进行比较，相等则通过，否则不通过
         */
        // 把datainput转换为SHA512哈希值
        NDSecProvider provider = new NDSecProvider();
        Security.addProvider(provider);

        try {
            // SHA512哈希值
            MessageDigest messageDigest = MessageDigest.getInstance("SHA512", provider);
            messageDigest.update(datainput);
            byte[] output = messageDigest.digest();

            // 开始解密过程
            Cipher cipher = Cipher.getInstance("RSA", provider);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decrypts = cipher.doFinal(sigBytes);

            // 对比数组
            return Arrays.equals(output, decrypts);

        } catch (Exception e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
}
