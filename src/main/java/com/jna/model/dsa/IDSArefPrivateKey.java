package com.jna.model.dsa;

public interface IDSArefPrivateKey {
    int getBits();

    byte[] getP();

    byte[] getQ();

    byte[] getG();

    byte[] getPrivkey();

    byte[] getPubkey();
}
