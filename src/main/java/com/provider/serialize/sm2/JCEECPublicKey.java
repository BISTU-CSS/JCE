package com.provider.serialize.sm2;

import com.provider.UnifiedKeyFactory;
import com.provider.serialize.IKeySerDes;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

public class JCEECPublicKey implements ECPublicKey {
    private static final long serialVersionUID = -8145849727580266753L;

    private int keyIndex;       //
    private int keyType;        //0：外部 1：内部
    private int bits;
    private BigInteger x;
    private BigInteger y;

    public int getKeyIndex() {
        return this.keyIndex;
    }

    public int getKeyType() {
        return this.keyType;
    }

    public int getBits() {
        return this.bits;
    }

    public JCEECPublicKey(int keyIndex, int keyType, int bits, BigInteger x, BigInteger y) {
        this.keyIndex = keyIndex;
        this.keyType = keyType;
        this.bits = bits;
        this.x = x;
        this.y = y;
    }

    public JCEECPublicKey(ECPublicKeySpec spec) {
        this.x = spec.getW().getAffineX();
        this.y = spec.getW().getAffineY();
    }

//    public JCEECPublicKey(SubjectPublicKeyInfo info) {
//        try {
//            SM2PublicKeyStructure sm2PublicKey = new SM2PublicKeyStructure(info.getPublicKeyData());
//            this.x = sm2PublicKey.getQ().getAffineX();
//            this.y = sm2PublicKey.getQ().getAffineY();
//        } catch (Exception var3) {
//            throw new IllegalArgumentException("invalid info structure in SM2 public key");
//        }
//    }

    public String getAlgorithm() {
        return "SM2";
    }

    public String getFormat() {
        return "X.509";
    }

    @Override
    public byte[] getEncoded() {
        IKeySerDes<Key> keySerDes = UnifiedKeyFactory.getKeySerDes(getAlgorithm(), UnifiedKeyFactory.PUBLIC_KEY);
        try {
            return keySerDes.serialize(this);
        } catch (IOException e) {
            // bad return
            return new byte[0];
        }
    }

//    public byte[] getEncoded() {
//        ECPoint w = new ECPoint(this.x, this.y);
//        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.ecPublicKey, GBObjectIdentifiers.sm2), (new SM2PublicKeyStructure(w)).getPublicKey());
//
//        try {
//            return info.toASN1Primitive().getEncoded("DER");
//        } catch (IOException var4) {
//            return null;
//        }
//    }

    public int hashCode() {
        return this.getW().hashCode() ^ this.getKeyIndex();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else if (!(o instanceof JCEECPublicKey)) {
            return false;
        } else {
            JCEECPublicKey key = (JCEECPublicKey) o;
            ECPoint w = new ECPoint(this.x, this.y);
            return key.getW().getAffineX().equals(w.getAffineX()) && key.getW().getAffineY().equals(w.getAffineY()) && this.getKeyIndex() == key.getKeyIndex() && this.getKeyType() == key.getKeyType();
        }
    }

    public String toString() {

        if (this.keyIndex == 0) {
            ECPoint w = new ECPoint(this.x, this.y);

            StringBuilder buf = new StringBuilder();
            String nl = System.getProperty("line.separator");
            buf.append("External SM2 Public Key").append(nl);
            buf.append("Bits:").append(this.bits).append(nl);
            buf.append("AffineX: ").append(w.getAffineX().toString(16)).append(nl);
            buf.append("AffineY: ").append(w.getAffineY().toString(16)).append(nl);
            return buf.toString();
        }

        return "Internal SM2 PublicKey[ KeyIndex = " + this.keyIndex + ", KeyType = " + this.keyType + ",Bits=" + this.bits + " ]";
    }

    public ECPoint getW() {
        return new ECPoint(this.x, this.y);
    }

    public ECParameterSpec getParams() {
        return null;
    }
}
