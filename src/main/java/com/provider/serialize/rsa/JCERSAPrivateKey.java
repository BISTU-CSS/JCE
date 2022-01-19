package com.provider.serialize.rsa;

import com.jna.model.rsa.IRSArefPrivateKey;
import com.provider.UnifiedKeyFactory;
import com.provider.serialize.IKeySerDes;
import com.util.BigIntegerUtil;
import org.bouncycastle.util.Strings;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;


public class JCERSAPrivateKey implements RSAPrivateKey, RSAPrivateCrtKey {
    private static final long serialVersionUID = 7834723820638524718L;

    private BigInteger e;        //e,公钥指数
    private BigInteger p;                //prime二维数组存放
    private BigInteger q;                //prime二维数组存放
    private BigInteger pe;        //pexp二维数组存放
    private BigInteger qe;        //pexp二维数组存放
    private BigInteger coeff;        //coef char数组存放
    private static BigInteger ZERO = BigInteger.valueOf(0L);
    protected BigInteger n;            //M，模N
    protected BigInteger d;    //d，私钥指数
    private int keyIndex;
    private int keyType;
    private int bits;                        //bits

    public JCERSAPrivateKey(PrivateKey k) {
    }

    public JCERSAPrivateKey(BigInteger e, BigInteger p, BigInteger q, BigInteger pe, BigInteger qe, BigInteger coeff, BigInteger n, BigInteger d, int bits) {
        this.e = e;
        this.p = p;
        this.q = q;
        this.pe = pe;
        this.qe = qe;
        this.coeff = coeff;
        this.n = n;
        this.d = d;
        this.bits = bits;
    }

    public JCERSAPrivateKey(IRSArefPrivateKey rsArefPrivateKey) {
        //参数传递
        this.n = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getM());
        this.e = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getE());
        this.bits = rsArefPrivateKey.getBits();
        this.pe = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getPrime1());
        this.qe = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getPrime2());
        this.p = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getPexp1());
        this.q = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getPexp2());
        this.d = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getD());
        this.coeff = BigIntegerUtil.toPositiveInteger(rsArefPrivateKey.getCoef());
    }

    @Override
    public String toString() {
        if (this.keyIndex == 0) {
            StringBuilder buf = new StringBuilder();
            String nl = Strings.lineSeparator();
            buf.append("External RSA Private CRT Key").append(nl);
            buf.append("bits:").append(this.bits).append(nl);
            buf.append("n: ").append(this.getModulus().toString(16)).append(nl);
            buf.append("public exponent: ").append(this.getPublicExponent().toString(16)).append(nl);
            buf.append("private exponent: ").append(this.getPrivateExponent().toString(16)).append(nl);
            buf.append("p: ").append(this.getPrimeP().toString(16)).append(nl);
            buf.append("q: ").append(this.getPrimeQ().toString(16)).append(nl);
            buf.append("pe: ").append(this.getPrimeExponentP().toString(16)).append(nl);
            buf.append("qe: ").append(this.getPrimeExponentQ().toString(16)).append(nl);
            buf.append("coeff: ").append(this.getCrtCoefficient().toString(16)).append(nl);
            return buf.toString();
        }

        return "Internal RSA PrivateKey[ KeyIndex = " + this.keyIndex + ", KeyType = " + this.keyType + ",Bits=" + this.bits + " ]";
    }

    public int getKeyIndex() {
        return 0;
    }

    public int getKeyType() {
        return 0;
    }

    public int getBits() {
        return bits;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

//	@Override
//	public byte[] getEncoded() {
//		return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPrivateKeyStructure(this.getModulus(), ZERO, this.getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
//	}

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

    @Override
    public BigInteger getModulus() {
        // TODO Auto-generated method stub
        return this.n;
    }

    @Override
    public BigInteger getPublicExponent() {
        // TODO Auto-generated method stub
        return this.e;
    }

    @Override
    public BigInteger getPrimeP() {
        // TODO Auto-generated method stub
        return this.p;
    }

    @Override
    public BigInteger getPrimeQ() {
        // TODO Auto-generated method stub
        return this.q;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        // TODO Auto-generated method stub
        return this.pe;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        // TODO Auto-generated method stub
        return this.qe;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        // TODO Auto-generated method stub
        return this.coeff;
    }

    @Override
    public BigInteger getPrivateExponent() {
        // TODO Auto-generated method stub
        return this.d;
    }

}
