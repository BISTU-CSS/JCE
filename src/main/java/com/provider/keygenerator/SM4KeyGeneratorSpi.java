package com.provider.keygenerator;

import com.provider.keygenerator.engine.KeyGeneratorEngine;
import org.bouncycastle.crypto.KeyGenerationParameters;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public final class SM4KeyGeneratorSpi extends KeyGeneratorSpi {

    private String algName = "SM4";
    private int defaultKeySize = 128;

    private int keySize;
    private KeyGeneratorEngine engine;
    private boolean uninitialised = true;

    public SM4KeyGeneratorSpi() {
        this.engine = new KeyGeneratorEngine();
    }

    @Override
    protected void engineInit(SecureRandom random) {
        if (random != null) {
            this.engine.init(new KeyGenerationParameters(random, this.defaultKeySize));
            this.uninitialised = false;
        }
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Not Implemented");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        this.keySize = keysize;

        if (this.keySize != 128) {
            throw new InvalidParameterException("Illegal key length|Only:128bytes");
        }

        this.engine.init(new KeyGenerationParameters(random, keySize));
        this.uninitialised = false;
    }

    @Override
    protected SecretKey engineGenerateKey() {
        if (this.uninitialised) {
            this.engine.init(new KeyGenerationParameters(new SecureRandom(), this.defaultKeySize));
            this.uninitialised = false;
        }
        return new SecretKeySpec(this.engine.generateKey(), this.algName);
    }
}
