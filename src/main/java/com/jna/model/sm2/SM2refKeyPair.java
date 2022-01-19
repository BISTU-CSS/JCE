package com.jna.model.sm2;

public class SM2refKeyPair {
    private SM2refPublicKey publicKey;
    private SM2refPrivateKey privateKey;

    public SM2refKeyPair(SM2refPublicKey publicKey, SM2refPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public SM2refKeyPair() {
    }

    public SM2refPublicKey getPublicKey() {
        return this.publicKey;
    }

    public void setPublicKey(SM2refPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public SM2refPrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public void setPrivateKey(SM2refPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String toString() {
        return "SM2refKeyPair\nPublicKey:" + this.publicKey + "\n" + "PrivateKey:" + this.privateKey;
    }

}
