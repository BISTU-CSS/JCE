package com.provider.signature;


import com.jna.api.LibCrypto;
import com.jna.model.sm2.SM2StructSignature;
import com.jna.model.sm2.SM2refPrivateKey;
import com.jna.model.sm2.SM2refPublicKey;
import com.jna.model.sm2.SM2refSignature;
import com.provider.NDSecProvider;
import com.provider.serialize.sm2.JCEECPrivateKey;
import com.provider.serialize.sm2.JCEECPublicKey;
import com.util.BigIntegerUtil;

import java.math.BigInteger;
import java.security.*;

public final class SHA256WithSM2SignatureSpi extends SignatureSpi {
    private JCEECPublicKey publicKey;
    private JCEECPrivateKey privateKey;
    private byte[] datainput;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        //验签
        this.publicKey = (JCEECPublicKey) publicKey;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        //传入签名的key
        this.privateKey = (JCEECPrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        //传入数据，传入原数据
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        //传入数据，传入原数据
        this.datainput = b;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        //进行签名，利用私钥

        //把datainput转换为SHA256哈希值
        NDSecProvider provider = new NDSecProvider();
        Security.addProvider(provider);

        try {
            // SHA256哈希值
            MessageDigest messageDigest = MessageDigest.getInstance("SHA256", provider);
            messageDigest.update(datainput);
            byte[] output = messageDigest.digest();

            LibCrypto libCrypto = new LibCrypto();
            SM2refPrivateKey privateKey = new SM2refPrivateKey(BigIntegerUtil.asUnsigned32ByteArray(this.privateKey.getS()));
            SM2refSignature signature = libCrypto.sm2ExternalSign(privateKey, output);

            BigInteger r = BigIntegerUtil.toPositiveInteger(signature.getR());
            BigInteger s = BigIntegerUtil.toPositiveInteger(signature.getS());

            SM2StructSignature sm2StructSignature = new SM2StructSignature(r, s);
            return sm2StructSignature.getEncoded();

        } catch (Exception e) {
            throw new SignatureException(e);
        }

    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        //验签。传入已经签名过的数据

        byte[] x = BigIntegerUtil.asUnsigned32ByteArray(publicKey.getW().getAffineX());
        byte[] y = BigIntegerUtil.asUnsigned32ByteArray(publicKey.getW().getAffineY());

        SM2StructSignature structSignature = SM2StructSignature.getInstance(sigBytes);
        SM2refSignature signature = new SM2refSignature(BigIntegerUtil.asUnsigned32ByteArray(structSignature.getR()),
                BigIntegerUtil.asUnsigned32ByteArray(structSignature.getS()));
        SM2refPublicKey sm2refPublicKey = new SM2refPublicKey(x, y);

        //把datainput转换为SHA256哈希值
        NDSecProvider provider = new NDSecProvider();
        Security.addProvider(provider);

        try {
            // SHA256哈希值
            MessageDigest messageDigest = MessageDigest.getInstance("SHA256", provider);
            messageDigest.update(datainput);
            byte[] output = messageDigest.digest();

            LibCrypto libCrypto = new LibCrypto();
            return libCrypto.sm2ExternalVerify(sm2refPublicKey, output, signature);

        } catch (NoSuchAlgorithmException e) {
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
