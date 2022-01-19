package com.provider.serialize.rsa;


import com.jna.model.rsa.IRSArefPublicKey;
import com.provider.UnifiedKeyFactory;
import com.provider.serialize.IKeySerDes;
import com.util.BigIntegerUtil;
import org.bouncycastle.util.Strings;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;


public class JCERSAPublicKey implements RSAPublicKey {
    private static final long serialVersionUID = 2675817738516720772L;

    private BigInteger modulus;            //模N
    private BigInteger publicExponent;    //公钥指数
    private int keyIndex;                //设置Internal或者External
    private int keyType;                //Internal专有属性
    private int bits;                    //模长

    public JCERSAPublicKey(BigInteger modulus, BigInteger publicExponent, int bits) {
        this.modulus = modulus;
        this.publicExponent = publicExponent;
        this.bits = bits;
    }

    public JCERSAPublicKey(IRSArefPublicKey rsArefPublicKey) {
               //参数传递
        this.bits = rsArefPublicKey.getBits();
        this.modulus = BigIntegerUtil.toPositiveInteger(rsArefPublicKey.getM());
        this.publicExponent = BigIntegerUtil.toPositiveInteger(rsArefPublicKey.getE());

    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        //todo
        String nl = Strings.lineSeparator();
        buf.append("RSA Public Key").append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("m: ").append(this.getModulus().toString(16)).append(nl);
        buf.append("public exponent: ").append(this.getPublicExponent().toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    public String getAlgorithm() {
        // TODO Auto-generated method stub
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public BigInteger getModulus() {
        // TODO Auto-generated method stub
        return this.modulus;
    }

    @Override
    public BigInteger getPublicExponent() {
        // TODO Auto-generated method stub
        return this.publicExponent;
    }
//	@Override
//	public	 byte[] getEncoded() {
//		return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), (ASN1Encodable)(new RSAPublicKeyStructure(this.getModulus(), this.getPublicExponent())));
//	}

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

    public int getBits() {
        return bits;
    }
}
