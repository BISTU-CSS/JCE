package com.provider.serialize.sm2;


import com.provider.UnifiedKeyFactory;
import com.provider.serialize.IKeySerDes;
import com.util.KeyIndexUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;

public class JCEECPrivateKey implements ECPrivateKey {
    private static final long serialVersionUID = -8145849727580266753L;

    private static BigInteger MAX_KEY_INDEX = new BigInteger("100");
    private int keyIndex;
    private int keyType;
    private int bits;
    private BigInteger s;
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

    private void setS(BigInteger s) {
        if (s.compareTo(MAX_KEY_INDEX) <= 0 && s.signum() >= 0) {
            try {
                KeyIndexUtil.KeyIndexStruct struct = KeyIndexUtil.parse2KeyIndex(s.intValue());
                this.keyIndex = struct.keyIndex;
                this.keyType = struct.keyType;
            } catch (Exception var3) {
                var3.printStackTrace();
            }
        }

        this.s = s;
    }

    public JCEECPrivateKey(int keyIndex, int keyType, int bits, BigInteger s, BigInteger x, BigInteger y) {
        this.keyIndex = keyIndex;
        this.keyType = keyType;
        this.bits = bits;
        this.s = s;
        this.x = x;
        this.y = y;
    }

    //    JCEECPrivateKey(SM2PrivateKeyParameters prikey, SM2KeyParameters pubkey) {
//        this.keyIndex = prikey.getKeyIndex();
//        this.keyType = prikey.getKeyType();
//        this.bits = prikey.getBits();
//        this.s = prikey.getD();
//        this.x = pubkey.getX();
//        this.y = pubkey.getY();
//    }

    public JCEECPrivateKey(ECPrivateKeySpec spec) {
        this.setS(spec.getS());
    }

//    public JCEECPrivateKey(SM2PrivateKeyStructure sm2PrivateKey) {
//        this.setS(sm2PrivateKey.getKey());
//        DERBitString publicKeyData = sm2PrivateKey.getPublicKey();
//        if (publicKeyData != null) {
//            SM2PublicKeyStructure sm2PublicKey = new SM2PublicKeyStructure(publicKeyData);
//            this.x = sm2PublicKey.getQ().getAffineX();
//            this.y = sm2PublicKey.getQ().getAffineY();
//        }
//
//    }

//    public JCEECPrivateKey(PrivateKeyInfo info) {
//        try {
//            SM2PrivateKeyStructure structure = new SM2PrivateKeyStructure((ASN1Sequence)info.parsePrivateKey());
//            this.setS(structure.getKey());
//            DERBitString publicKeyData = structure.getPublicKey();
//            if (publicKeyData != null) {
//                SM2PublicKeyStructure sm2PublicKey = new SM2PublicKeyStructure(publicKeyData);
//                this.x = sm2PublicKey.getQ().getAffineX();
//                this.y = sm2PublicKey.getQ().getAffineY();
//            }
//
//        } catch (Exception var5) {
//            throw new IllegalArgumentException("invalid info structure in SM2 public key");
//        }
//    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        IKeySerDes<Key> keySerDes = UnifiedKeyFactory.getKeySerDes(getAlgorithm(), UnifiedKeyFactory.PRIVATE_KEY);
        try {
            return keySerDes.serialize(this);
        } catch (IOException e) {
            // bad return
            return new byte[0];
        }
    }

//    public byte[] getEncoded() {
//        DERBitString pubkey = null;
//        if (this.x != null && this.y != null) {
//            pubkey = new DERBitString((new SM2PublicKeyStructure(new ECPoint(this.x, this.y))).getPublicKey());
//        }
//
//        SM2PrivateKeyStructure sm2PrivateKey = new SM2PrivateKeyStructure(this.s, pubkey, (ASN1Encodable)null);
//
//        try {
//            PrivateKeyInfo info = new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.ecPublicKey, GBObjectIdentifiers.sm2), sm2PrivateKey.toASN1Primitive());
//            return info.toASN1Primitive().getEncoded("DER");
//        } catch (IOException var4) {
//            return null;
//        }
//    }

    @Override
    public int hashCode() {
        return this.getS().hashCode() ^ this.getKeyIndex();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else if (!(o instanceof JCEECPrivateKey)) {
            return false;
        } else {
            JCEECPrivateKey key = (JCEECPrivateKey) o;
            return key.getS().equals(this.s) && this.getKeyIndex() == key.getKeyIndex() && this.getKeyType() == key.getKeyType();
        }
    }

    @Override
    public String toString() {
        if (this.keyIndex == 0) {
            StringBuilder buf = new StringBuilder();
            String nl = System.getProperty("line.separator");
            buf.append("External SM2 Private Key").append(nl);
            buf.append("Bits:").append(this.bits).append(nl);
            buf.append("S: ").append(this.s.toString(16)).append(nl);
            return buf.toString();
        }

        return "Internal SM2 PrivateKey[ KeyIndex = " + this.keyIndex + ", KeyType = " + this.keyType + ",Bits= " + this.bits + " ]";
    }

    @Override
    public BigInteger getS() {
        return this.s;
    }

    public BigInteger getX() {
        return this.x;
    }

    public BigInteger getY() {
        return this.y;
    }

    public ECPoint getW() {
        return new ECPoint(this.x, this.y);
    }

    @Override
    public ECParameterSpec getParams() {
        return null;
    }
}
