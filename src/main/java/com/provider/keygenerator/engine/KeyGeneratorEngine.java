package com.provider.keygenerator.engine;

import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.Serializable;
import java.security.SecureRandom;

public class KeyGeneratorEngine implements Serializable {

    private SecureRandom random;
    private int strength;

    public void init(KeyGenerationParameters param) {
        this.random = param.getRandom();
        this.strength = (param.getStrength() + 7) / 8;
    }

    public byte[] generateKey() {
        byte[] key = new byte[this.strength];
        this.random.nextBytes(key);
        return key;
    }

}
