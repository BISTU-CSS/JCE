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
public class RSArefPublicKeyEx extends Structure implements IRSArefPublicKey {
    // 模长
    public int bits;
    // 模N
    public byte[] m = new byte[512];
    // 公钥指数
    public byte[] e = new byte[512];

    public RSArefPublicKeyEx() {
    }


    public RSArefPublicKeyEx(int bits, byte[] m, byte[] e) {
        if (m.length > 513) {
            throw new RuntimeException("m length[ " + m.length + " ]");
        }
        if (e.length > 513) {
            throw new RuntimeException("e length[ " + e.length + " ]");
        }

        this.bits = bits;
        System.arraycopy(m, 0, this.m, 512 - m.length, m.length);

        if (e[0] == 0 && e.length % 256 == 1) {
            System.arraycopy(e, 1, this.e, 512 - (e.length - 1), e.length - 1);
        } else {
            System.arraycopy(e, 0, this.e, 512 - e.length, e.length);
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
    public void decode(byte[] bytes) {
        this.bits = BytesUtil.bytes2int(bytes);
        int pos = 4;
        System.arraycopy(bytes, pos, this.m, 0, 512);
        pos = pos + this.m.length;
        System.arraycopy(bytes, pos, this.e, 0, 512);
        pos += 512;
        if (pos != bytes.length) {
            throw new RuntimeCryptoException("inputData length != ExRSAPublicKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.m);
            buf.write(this.e);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("RSArefPublicKeyEx encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 1028;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   n: ").append((new BigInteger(1, this.m)).toString(16)).append(nl);
        buf.append("   e: ").append((new BigInteger(1, this.e)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "m", "e");
    }

    public static class ByValue extends RSArefPublicKeyEx implements Structure.ByValue {
    }

    public static class ByReference extends RSArefPublicKeyEx implements Structure.ByReference {
    }

}
