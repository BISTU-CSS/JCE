package com.provider.keypairgenerator;


import com.jna.api.LibCrypto;
import com.jna.model.sm2.SM2refKeyPair;
import com.jna.model.sm2.SM2refPrivateKey;
import com.jna.model.sm2.SM2refPublicKey;
import com.provider.serialize.sm2.JCEECPrivateKey;
import com.provider.serialize.sm2.JCEECPublicKey;
import com.util.BigIntegerUtil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public final class SM2KeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private int keysize;
    private SecureRandom random;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keysize = keysize;
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {

        if (keysize >= 65536) {
            JCEECPublicKey publicKey = new JCEECPublicKey(keysize >> 16, 1, 0, BigInteger.ZERO, BigInteger.ZERO);
            JCEECPrivateKey privateKey = new JCEECPrivateKey(keysize >> 16, 1, 0, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);
            return new KeyPair(publicKey, privateKey);
        }

        LibCrypto libCrypto = new LibCrypto();
        SM2refKeyPair keyPair = libCrypto.generateSM2KeyPair(keysize);

        SM2refPrivateKey sm2refPrivateKey = keyPair.getPrivateKey();
        BigInteger d = BigIntegerUtil.toPositiveInteger(sm2refPrivateKey.getD());

        SM2refPublicKey sm2refPublicKey = keyPair.getPublicKey();
        int bits = sm2refPublicKey.getBits();
        BigInteger x = BigIntegerUtil.toPositiveInteger(sm2refPublicKey.getX());
        BigInteger y = BigIntegerUtil.toPositiveInteger(sm2refPublicKey.getY());

        JCEECPublicKey publicKey = new JCEECPublicKey(0, 0, bits, x, y);
        JCEECPrivateKey privateKey = new JCEECPrivateKey(0, 0, bits, d, x, y);

        return new KeyPair(publicKey, privateKey);
    }

}
