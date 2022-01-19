package com.provider.keypairgenerator;


import com.jna.api.LibCrypto;
import com.jna.model.rsa.RSArefKeyPair;
import com.provider.serialize.rsa.JCERSAPrivateKey;
import com.provider.serialize.rsa.JCERSAPublicKey;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public final class RSAKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private int keysize;
    private SecureRandom random;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keysize = keysize;
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {

        //额外：选择密码机算法
        LibCrypto libCrypto = new LibCrypto();
        RSArefKeyPair rsaKeyPair = libCrypto.generateRSAKeyPair(keysize);

        JCERSAPublicKey publicKey = new JCERSAPublicKey(rsaKeyPair.getPublicKey());
        JCERSAPrivateKey privateKey = new JCERSAPrivateKey(rsaKeyPair.getPrivateKey());
        return new KeyPair(publicKey, privateKey);
    }

}
