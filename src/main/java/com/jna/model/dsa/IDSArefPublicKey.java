package com.jna.model.dsa;

import com.jna.model.IKeyPair;

public interface IDSArefPublicKey extends IKeyPair {
    int getBits();

    byte[] getP();

    byte[] getQ();

    byte[] getG();

    byte[] getPubkey();
}
