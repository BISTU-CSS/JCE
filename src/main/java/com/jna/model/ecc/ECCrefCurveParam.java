package com.jna.model.ecc;


import com.jna.model.IKeyPair;
import com.sun.jna.Structure;
import com.util.BytesUtil;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * @brief ECC密钥数据结构
 * TODO 不准确，需要修改完善
 */
public class ECCrefCurveParam extends Structure implements IKeyPair {
    // 参数位长, 160/192/224/256
    public int len;
    // 素数p
    public byte[] p = new byte[32];
    // 参数a
    public byte[] a = new byte[32];
    // 参数b
    public byte[] b = new byte[32];

    // 参数Gx:x coordinate of the base point G
    public byte[] gx = new byte[32];

    // 参数Gy:y coordinate of the base point G
    public byte[] gy = new byte[32];

    // 阶N:order n of the base point G
    public byte[] n = new byte[32];


    public ECCrefCurveParam() {
    }

    public ECCrefCurveParam(int len, byte[] p, byte[] a, byte[] b, byte[] gx, byte[] gy, byte[] n) {
        this.len = len;
        if (p.length > 32) {
            throw new RuntimeException("p length[ " + p.length + " ]");
        }
        System.arraycopy(p, 0, this.p, 32 - p.length, p.length);

        if (a.length > 32) {
            throw new RuntimeException("a length[ " + a.length + " ]");
        }
        System.arraycopy(a, 0, this.a, 32 - a.length, a.length);

        if (b.length > 32) {
            throw new RuntimeException("b length[ " + b.length + " ]");
        }
        System.arraycopy(b, 0, this.b, 32 - b.length, b.length);

        if (gx.length > 32) {
            throw new RuntimeException("gx length[ " + gx.length + " ]");
        }
        System.arraycopy(gx, 0, this.gx, 32 - gx.length, gx.length);

        if (gy.length > 32) {
            throw new RuntimeException("gy length[ " + gy.length + " ]");
        }
        System.arraycopy(gy, 0, this.gy, 32 - gy.length, gy.length);

        if (n.length > 32) {
            throw new RuntimeException("n length[ " + n.length + " ]");
        }
        System.arraycopy(n, 0, this.n, 32 - n.length, n.length);
    }

    @Override
    public void decode(byte[] bytes) {
        this.len = BytesUtil.bytes2int(bytes);
        int pos = 4;
        System.arraycopy(bytes, pos, this.p, 0, 32);
        pos += this.p.length;
        System.arraycopy(bytes, pos, this.a, 0, 32);
        pos += this.a.length;
        System.arraycopy(bytes, pos, this.b, 0, 32);
        pos += this.b.length;
        System.arraycopy(bytes, pos, this.gx, 0, 32);
        pos += this.gx.length;
        System.arraycopy(bytes, pos, this.gy, 0, 32);
        pos += this.gy.length;
        System.arraycopy(bytes, pos, this.n, 0, 32);
        pos += this.n.length;
        if (pos != bytes.length) {
            throw new RuntimeCryptoException("inputData length != ECCrefCurveParam length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.len));
            buf.write(this.p);
            buf.write(this.a);
            buf.write(this.b);
            buf.write(this.gx);
            buf.write(this.gy);
            buf.write(this.n);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("ECCrefCurveParam encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 196;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("  len: ").append(this.len).append(nl);
        buf.append("     p: ").append((new BigInteger(1, this.p)).toString(16)).append(nl);
        buf.append("     a: ").append((new BigInteger(1, this.a)).toString(16)).append(nl);
        buf.append("     b: ").append((new BigInteger(1, this.b)).toString(16)).append(nl);
        buf.append("     gx: ").append((new BigInteger(1, this.gx)).toString(16)).append(nl);
        buf.append("     gy: ").append((new BigInteger(1, this.gy)).toString(16)).append(nl);
        buf.append("     n: ").append((new BigInteger(1, this.n)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("len", "p", "a", "b", "gx", "gy", "n");
    }

    public static class ByValue extends ECCrefCurveParam implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends ECCrefCurveParam implements Structure.ByReference {
        public ByReference() {
        }
    }
}
