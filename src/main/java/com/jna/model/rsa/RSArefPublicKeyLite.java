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
 * @brief RSA公钥数据结构定义
 */
public class RSArefPublicKeyLite extends Structure implements IRSArefPublicKey {
    // 模长
    public int bits;
    // 模N
    public byte[] m = new byte[256];
    // 公钥指数
    public byte[] e = new byte[256];

    public RSArefPublicKeyLite() {
    }

    public RSArefPublicKeyLite(int bits, byte[] m, byte[] e) {
        if (m.length > 257) {
            throw new RuntimeException("m length[ " + m.length + " ]");
        }
        if (e.length > 257) {
            throw new RuntimeException("e length[ " + e.length + " ]");
        }
        this.bits = bits;
        System.arraycopy(m, 0, this.m, 256 - m.length, m.length);
        System.arraycopy(e, 0, this.e, 256 - e.length, e.length);
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
    public void decode(byte[] publicKey) {
        this.bits = BytesUtil.bytes2int(publicKey);
        int pos = 4;
        System.arraycopy(publicKey, pos, this.m, 0, 256);
        pos = pos + this.m.length;
        System.arraycopy(publicKey, pos, this.e, 0, 256);
        pos += this.e.length;
        if (pos != publicKey.length) {
            throw new RuntimeCryptoException("inputData length != RSAPublicKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            out.write(BytesUtil.int2bytes(this.bits));
            out.write(this.m);
            out.write(this.e);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("RSArefPublicKeyLite encode error." + ex.getMessage());
        }

        return out.toByteArray();
    }

    @Override
    public int size() {
        return 516;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   m: ").append((new BigInteger(1, this.m)).toString(16)).append(nl);
        buf.append("   e: ").append((new BigInteger(1, this.e)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "m", "e");
    }

    public static class ByValue extends RSArefPublicKeyLite implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends RSArefPublicKeyLite implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
