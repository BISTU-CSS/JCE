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

public class SM2refPrivateKey extends Structure implements IKeyPair {
    public int bits;// 加密强度为256位
    public byte[] D = new byte[32];// 打点次数

    public SM2refPrivateKey() {
    }

    public SM2refPrivateKey(byte[] D) {
        this.bits = 256;
        if (D.length < 32) {
            int prefixZero = 32 - D.length;
            for (int i = 0; i < prefixZero; ++i) {
                D[i] = 0;
            }
            System.arraycopy(D, 0, this.D, prefixZero, D.length);
        } else if (D.length > 32) {
            int prefixZero = D.length - 32;
            for (int i = 0; i < prefixZero; ++i) {
                assert D[i] == 0;
            }
            System.arraycopy(D, prefixZero, this.D, 0, 32);
        } else {
            this.D = D;
        }
    }

    public int getBits() {
        return this.bits;
    }

    public byte[] getD() {
        return this.D;
    }

    @Override
    public void decode(byte[] privateKey) {
        this.bits = BytesUtil.bytes2int(privateKey);
        int pos = 4;
        System.arraycopy(privateKey, pos, this.D, 0, 32);
        pos = pos + this.D.length;
        if (pos != privateKey.length) {
            throw new RuntimeCryptoException("inputData length != SM2PrivateKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.D);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("SM2refPrivateKey encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 36;
    }

    public static int sizeof() {
        return 36;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append("bits: ").append(this.bits).append(nl);
        buf.append("   D: ").append((new BigInteger(1, this.D)).toString(16)).append(nl);
        return buf.toString();
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "D");
    }

    public static class ByValue extends SM2refPrivateKey implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refPrivateKey implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
