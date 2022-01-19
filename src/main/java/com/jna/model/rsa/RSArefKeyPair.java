package com.jna.model.rsa;

public class RSArefKeyPair {

    private IRSArefPublicKey publicKey;
    private IRSArefPrivateKey privateKey;

    public RSArefKeyPair(IRSArefPublicKey publicKey, IRSArefPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public IRSArefPublicKey getPublicKey() {
        return this.publicKey;
    }

    public IRSArefPrivateKey getPrivateKey() {
        return this.privateKey;
    }

    @Override
    public String toString() {
        return "RSArefKeyPair\nPublicKey:" + this.publicKey.toString() + "\n" + "PrivateKey:" + this.privateKey.toString();
    }
}
