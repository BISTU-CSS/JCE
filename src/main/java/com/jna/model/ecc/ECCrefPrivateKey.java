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
 * @brief ECC私钥数据结构定义
 * TODO 不准确，需要修改完善
 */
public class ECCrefPrivateKey extends Structure implements IKeyPair {
    // 密钥位长
    public int bits;
    // 私钥
    public byte[] k = new byte[32];

    public ECCrefPrivateKey() {
    }

    public ECCrefPrivateKey(int bits, byte[] k) {
        if (k.length > 32) {
            throw new RuntimeException("k length[ " + k.length + " ]");
        }
        this.bits = bits;
        System.arraycopy(k, 0, this.k, 32 - k.length, k.length);
    }

    @Override
    public void decode(byte[] bytes) {
        this.bits = BytesUtil.bytes2int(bytes);
        int pos = 4;
        System.arraycopy(bytes, pos, this.k, 0, 256);
        pos += this.k.length;
        if (pos != bytes.length) {
            throw new RuntimeCryptoException("inputData length != ECCrefPrivateKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.k);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("ECCrefPrivateKey encode error." + ex.getMessage());
        }
        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 36;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("  bits: ").append(this.bits).append(nl);
        buf.append("     k: ").append((new BigInteger(1, this.k)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "k");
    }

    public static class ByValue extends ECCrefPrivateKey implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends ECCrefPrivateKey implements Structure.ByReference {
        public ByReference() {
        }
    }
}
