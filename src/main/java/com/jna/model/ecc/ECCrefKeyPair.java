package com.jna.model.ecc;

public class ECCrefKeyPair {

    private ECCrefPublicKey publicKey;
    private ECCrefPrivateKey privateKey;

    public ECCrefKeyPair(ECCrefPublicKey publicKey, ECCrefPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public ECCrefPublicKey getPublicKey() {
        return this.publicKey;
    }

    public ECCrefPrivateKey getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public String toString() {
        return "ECCrefKeyPair\nPublicKey:" + this.privateKey.toString() + "\n" + "PrivateKey:" + this.publicKey.toString();
    }
}
