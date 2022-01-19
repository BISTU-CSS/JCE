package com.jna.model.rsa;

import com.jna.model.IKeyPair;

public interface IRSArefPrivateKey extends IKeyPair {
    int getBits();

    byte[] getM();

    byte[] getE();

    byte[] getD();

    byte[] getPrime1();

    byte[] getPrime2();

    byte[] getPexp1();

    byte[] getPexp2();

    byte[] getCoef();
}
