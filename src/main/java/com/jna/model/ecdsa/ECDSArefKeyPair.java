package com.jna.model.ecdsa;

public class ECDSArefKeyPair {

    private ECDSArefPublicKey publicKey;
    private ECDSArefPrivateKey privateKey;

    public ECDSArefKeyPair() {
    }

    public ECDSArefKeyPair(ECDSArefPublicKey publicKey, ECDSArefPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public ECDSArefPublicKey getPublicKey() {
        return this.publicKey;
    }

    public void setPublicKey(ECDSArefPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public ECDSArefPrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public void setPrivateKey(ECDSArefPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String toString() {
        return "ECDSArefKeyPair\nPublicKey:" + this.publicKey + "\n" + "PrivateKey:" + this.privateKey;
    }
}
