package com.jna.model;


import com.util.BytesUtil;

public class ByteKeyPair {
    private byte[] pubKeyData;
    private byte[] priKeyData;

    public byte[] getPubKeyData() {
        return this.pubKeyData;
    }

    public byte[] getPriKeyData() {
        return this.priKeyData;
    }

    public ByteKeyPair(byte[] pubKeyData, byte[] priKeyData) {
        this.pubKeyData = pubKeyData;
        this.priKeyData = priKeyData;
    }

    @Override
    public String toString() {
        return "ByteKeyPair\nPubKey=" + BytesUtil.bytes2hex(this.pubKeyData) + "\nPriKey=" + BytesUtil.bytes2hex(this.priKeyData);
    }
}
