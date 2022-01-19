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

public class SM2refPublicKey extends Structure implements IKeyPair {
    public int bits;// 加密强度为256位
    public byte[] x = new byte[32];// X分量
    public byte[] y = new byte[32];// Y分量

    public SM2refPublicKey() {
    }

    public SM2refPublicKey(byte[] x, byte[] y) {
        this.bits = 256;
        if (x.length < 32) {
            int prefixZero = 32 - x.length;
            for (int i = 0; i < prefixZero; ++i) {
                x[i] = 0;
            }
            System.arraycopy(x, 0, this.x, prefixZero, x.length);
        } else if (x.length > 32) {
            int prefixZero = x.length - 32;
            for (int i = 0; i < prefixZero; ++i) {
                assert x[i] == 0;
            }
            System.arraycopy(x, prefixZero, this.x, 0, 32);
        } else {
            this.x = x;
        }

        if (y.length < 32) {
            int prefixZero = 32 - y.length;
            for (int i = 0; i < prefixZero; ++i) {
                y[i] = 0;
            }
            System.arraycopy(y, 0, this.y, prefixZero, y.length);
        } else if (y.length > 32) {
            int prefixZero = y.length - 32;
            for (int i = 0; i < prefixZero; ++i) {
                assert y[i] == 0;
            }
            System.arraycopy(y, prefixZero, this.y, 0, 32);
        } else {
            this.y = y;
        }
    }

    public int getBits() {
        return this.bits;
    }

    public byte[] getX() {
        return this.x;
    }

    public byte[] getY() {
        return this.y;
    }

    @Override
    public void decode(byte[] publicKey) {
        this.bits = BytesUtil.bytes2int(publicKey);
        int pos = 4;
        System.arraycopy(publicKey, pos, this.x, 0, 32);
        pos = pos + this.x.length;
        System.arraycopy(publicKey, pos, this.y, 0, 32);
        pos += this.y.length;
        if (pos != publicKey.length) {
            throw new RuntimeCryptoException("inputData length != SM2PublicKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.x);
            buf.write(this.y);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("SM2refPublicKey encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 68;
    }

    public static int sizeof() {
        return 68;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   X: ").append((new BigInteger(1, this.x)).toString(16)).append(nl);
        buf.append("   Y: ").append((new BigInteger(1, this.y)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "x", "y");
    }

    public static class ByValue extends SM2refPublicKey implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refPublicKey implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
