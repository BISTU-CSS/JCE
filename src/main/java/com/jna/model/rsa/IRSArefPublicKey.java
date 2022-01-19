package com.jna.model.rsa;

import com.jna.model.IKeyPair;

public interface IRSArefPublicKey extends IKeyPair {
    int getBits();

    byte[] getM();

    byte[] getE();
}
