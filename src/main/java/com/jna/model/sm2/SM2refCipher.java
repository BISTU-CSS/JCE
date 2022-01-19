package com.jna.model.sm2;


import com.jna.model.IKeyPair;
import com.sun.jna.Structure;
import com.util.BytesUtil;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class SM2refCipher extends Structure implements IKeyPair {
    public byte[] x = new byte[32];// X分量
    public byte[] y = new byte[32];// Y分量
    public byte[] C = new byte[136];// 密文数据
    public int cLength;// 密文的数据长度
    public byte[] M = new byte[32];// 明文的杂凑值

    public SM2refCipher() {
    }

    public SM2refCipher(byte[] x, byte[] y, byte[] c, byte[] m) {
        this.x = x;
        this.y = y;
        this.cLength = c.length;
        System.arraycopy(c, 0, this.C, 0, c.length);
        this.M = m;
    }

    public byte[] getX() {
        return this.x;
    }

    public byte[] getY() {
        return this.y;
    }

    public byte[] getC() {
        return this.C;
    }

    public byte[] getM() {
        return this.M;
    }

    public int getCLength() {
        return this.cLength;
    }

    @Override
    public void decode(byte[] cipher) {
        this.cLength = BytesUtil.bytes2int(cipher);
        int pos = 4;
        System.arraycopy(cipher, pos, this.x, 0, 32);
        pos = pos + this.x.length;
        System.arraycopy(cipher, pos, this.y, 0, 32);
        pos += this.y.length;
        System.arraycopy(cipher, pos, this.C, 0, 136);
        pos += this.C.length;
        System.arraycopy(cipher, pos, this.M, 0, 32);
        pos += this.M.length;
        if (pos != cipher.length) {
            throw new RuntimeCryptoException("inputData length != SM2Cipher length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.cLength));
            buf.write(this.x);
            buf.write(this.y);
            buf.write(this.C);
            buf.write(this.M);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("SM2refCipher encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 236;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("cLength: ").append(this.cLength).append(nl);
        buf.append("      x: ").append((new BigInteger(1, this.x)).toString(16)).append(nl);
        buf.append("      y: ").append((new BigInteger(1, this.y)).toString(16)).append(nl);
        buf.append("      C: ").append((new BigInteger(1, this.C)).toString(16)).append(nl);
        buf.append("      M: ").append((new BigInteger(1, this.M)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("cLength", "x", "y", "C", "M");
    }

    public static class ByValue extends SM2refCipher implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refCipher implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
