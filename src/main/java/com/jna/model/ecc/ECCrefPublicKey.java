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
 * @brief ECC公钥数据结构定义
 * TODO 不准确，需要修改完善
 */
public class ECCrefPublicKey extends Structure implements IKeyPair {
    // 密钥位长
    public int bits;
    // 公钥x坐标
    public byte[] x = new byte[32];
    // 公钥y坐标
    public byte[] y = new byte[32];

    public ECCrefPublicKey() {
    }

    public ECCrefPublicKey(int bits, byte[] x, byte[] y) {
        if (x.length > 32) {
            throw new RuntimeException("x length[ " + x.length + " ]");
        }
        if (y.length > 32) {
            throw new RuntimeException("y length[ " + y.length + " ]");
        }
        this.bits = bits;
        System.arraycopy(x, 0, this.x, 32 - x.length, x.length);
        System.arraycopy(y, 0, this.y, 32 - y.length, y.length);
    }

    @Override
    public void decode(byte[] bytes) {
        this.bits = BytesUtil.bytes2int(bytes);
        int pos = 4;
        System.arraycopy(bytes, pos, this.x, 0, 32);
        pos += this.x.length;
        System.arraycopy(bytes, pos, this.y, 0, 32);
        pos += this.y.length;
        if (pos != bytes.length) {
            throw new RuntimeCryptoException("inputData length != ECCrefPublicKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        try {
            out.write(BytesUtil.int2bytes(this.bits));
            out.write(this.x);
            out.write(this.y);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("ECCrefPublicKey encode error." + ex.getMessage());
        }

        return out.toByteArray();
    }

    @Override
    public int size() {
        return 68;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   x: ").append((new BigInteger(1, this.x)).toString(16)).append(nl);
        buf.append("   y: ").append((new BigInteger(1, this.y)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "x", "y");
    }

    public static class ByValue extends ECCrefPublicKey implements Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends ECCrefPublicKey implements Structure.ByReference {
        public ByReference() {
        }
    }
}
