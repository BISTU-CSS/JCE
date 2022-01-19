package com.jna.model;


public interface IKeyPair {

    void decode(byte[] var1);

    byte[] encode();

    int size();
}
