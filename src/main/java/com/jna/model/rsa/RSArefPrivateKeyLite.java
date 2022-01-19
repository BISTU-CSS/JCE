package com.jna.model.rsa;


import com.sun.jna.Structure;
import com.util.BytesUtil;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * @brief RSA私钥数据结构定义
 */
public class RSArefPrivateKeyLite extends Structure implements IRSArefPrivateKey {
    // 模长
    public int bits;
    // 模N
    public byte[] m = new byte[256];
    // 公钥指数
    public byte[] e = new byte[256];
    // 私钥指数
    public byte[] d = new byte[256];
    // 素数p和q
    public byte[] prime = new byte[256];
    // Dp和Dq
    public byte[] pexp = new byte[256];
    // 系数i
    public byte[] coef = new byte[128];

    public RSArefPrivateKeyLite() {
    }

    public RSArefPrivateKeyLite(byte[] m, byte[] e, byte[] d, byte[] p1, byte[] p2, byte[] q1, byte[] q2, byte[] coef) {
        byte[] prime1 = new byte[128];
        byte[] prime2 = new byte[128];
        byte[] pexp1 = new byte[128];
        byte[] pexp2 = new byte[128];
        if (m.length > 257) {
            throw new RuntimeException("n length[ " + m.length + " ]");
        }
        if (m[0] == 0 && m.length % 128 == 1) {
            this.bits = m.length - 1 << 3;
            System.arraycopy(m, 1, this.m, 256 - (m.length - 1), m.length - 1);
        } else {
            this.bits = m.length << 3;
            System.arraycopy(m, 0, this.m, 256 - m.length, m.length);
        }

        if (e.length > 257) {
            throw new RuntimeException("e length[ " + e.length + " ]");
        }
        if (e[0] == 0 && e.length % 128 == 1) {
            System.arraycopy(e, 1, this.e, 256 - (e.length - 1), e.length - 1);
        } else {
            System.arraycopy(e, 0, this.e, 256 - e.length, e.length);
        }

        if (d.length > 257) {
            throw new RuntimeException("d length[ " + d.length + " ]");
        }
        if (d[0] == 0 && d.length % 128 == 1) {
            System.arraycopy(d, 1, this.d, 256 - (d.length - 1), d.length - 1);
        } else {
            System.arraycopy(d, 0, this.d, 256 - d.length, d.length);
        }

        if (p1.length > 129) {
            throw new RuntimeException("p1 length[ " + p1.length + " ]");
        }
        if (p1[0] == 0 && p1.length % 64 == 1) {
            System.arraycopy(p1, 1, prime1, 128 - (p1.length - 1), p1.length - 1);
        } else {
            System.arraycopy(p1, 0, prime1, 128 - p1.length, p1.length);
        }

        if (p2.length > 129) {
            throw new RuntimeException("p2 length[ " + p2.length + " ]");
        }
        if (p2[0] == 0 && p2.length % 64 == 1) {
            System.arraycopy(p2, 1, prime2, 128 - (p2.length - 1), p2.length - 1);
        } else {
            System.arraycopy(p2, 0, prime2, 128 - p2.length, p2.length);
        }

        this.prime = BytesUtil.combineBytes(prime1, prime2);
        if (q1.length > 129) {
            throw new RuntimeException("q1 length[ " + q1.length + " ]");
        }
        if (q1[0] == 0 && q1.length % 64 == 1) {
            System.arraycopy(q1, 1, pexp1, 128 - (q1.length - 1), q1.length - 1);
        } else {
            System.arraycopy(q1, 0, pexp1, 128 - q1.length, q1.length);
        }

        if (q2.length > 129) {
            throw new RuntimeException("q2 length[ " + q2.length + " ]");
        }
        if (q2[0] == 0 && q2.length % 64 == 1) {
            System.arraycopy(q2, 1, pexp2, 128 - (q2.length - 1), q2.length - 1);
        } else {
            System.arraycopy(q2, 0, pexp2, 128 - q2.length, q2.length);
        }

        this.pexp = BytesUtil.combineBytes(pexp1, pexp2);
        if (coef.length > 129) {
            throw new RuntimeException("coef length[ " + coef.length + " ]");
        }
        if (coef[0] == 0 && coef.length % 64 == 1) {
            System.arraycopy(coef, 1, this.coef, 128 - (coef.length - 1), coef.length - 1);
        } else {
            System.arraycopy(coef, 0, this.coef, 128 - coef.length, coef.length);
        }
    }

    @Override
    public int getBits() {
        return this.bits;
    }

    @Override
    public byte[] getM() {
        return this.m;
    }

    @Override
    public byte[] getE() {
        return this.e;
    }

    @Override
    public byte[] getD() {
        return this.d;
    }

    @Override
    public byte[] getPrime1() {
        return BytesUtil.subbytes(this.prime, 0, 128);
    }

    @Override
    public byte[] getPrime2() {
        return BytesUtil.subbytes(this.prime, 128, 128);
    }

    @Override
    public byte[] getPexp1() {
        return BytesUtil.subbytes(this.pexp, 0, 128);
    }

    @Override
    public byte[] getPexp2() {
        return BytesUtil.subbytes(this.pexp, 128, 128);
    }

    @Override
    public byte[] getCoef() {
        return this.coef;
    }

    @Override
    public void decode(byte[] bytes) {
        this.bits = BytesUtil.bytes2int(bytes);
        int pos = 4;
        System.arraycopy(bytes, pos, this.m, 0, 256);
        pos = pos + this.m.length;
        System.arraycopy(bytes, pos, this.e, 0, 256);
        pos += this.e.length;
        System.arraycopy(bytes, pos, this.d, 0, 256);
        pos += this.d.length;
        System.arraycopy(bytes, pos, this.prime, 0, 256);
        pos += this.prime.length;
        System.arraycopy(bytes, pos, this.pexp, 0, 256);
        pos += this.pexp.length;
        System.arraycopy(bytes, pos, this.coef, 0, 128);
        pos += this.coef.length;
        if (pos != bytes.length) {
            throw new RuntimeCryptoException("inputData length != RSAPrivateKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.m);
            buf.write(this.e);
            buf.write(this.d);
            buf.write(this.prime);
            buf.write(this.pexp);
            buf.write(this.coef);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("RSArefPrivateKeyLite encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 1412;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("  bits: ").append(this.bits).append(nl);
        buf.append("     m: ").append((new BigInteger(1, this.m)).toString(16)).append(nl);
        buf.append("     e: ").append((new BigInteger(1, this.e)).toString(16)).append(nl);
        buf.append("     d: ").append((new BigInteger(1, this.d)).toString(16)).append(nl);
        buf.append("prime1: ").append((new BigInteger(1, BytesUtil.subbytes(this.prime, 0, 128))).toString(16)).append(nl);
        buf.append("prime2: ").append((new BigInteger(1, BytesUtil.subbytes(this.prime, 128, 128))).toString(16)).append(nl);
        buf.append(" pexp1: ").append((new BigInteger(1, BytesUtil.subbytes(this.pexp, 0, 128))).toString(16)).append(nl);
        buf.append(" pexp2: ").append((new BigInteger(1, BytesUtil.subbytes(this.pexp, 128, 128))).toString(16)).append(nl);
        buf.append("  coef: ").append((new BigInteger(1, this.coef)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "m", "e", "d", "prime", "pexp", "coef");
    }

    public static class ByValue extends RSArefPrivateKeyLite implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends RSArefPrivateKeyLite implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
