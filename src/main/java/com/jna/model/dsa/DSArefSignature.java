package com.jna.model.dsa;


import com.jna.model.IKeyPair;
import com.sun.jna.Structure;
import com.util.BytesUtil;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class DSArefSignature extends Structure implements IKeyPair {
    public byte[] r = new byte[32];
    public byte[] s = new byte[32];

    public DSArefSignature() {
    }

    public DSArefSignature(byte[] r, byte[] s) {
        this.r = r;
        this.s = s;
    }

    public byte[] getR() {
        return this.r;
    }

    public byte[] getS() {
        return this.s;
    }

    @Override
    public void decode(byte[] signature) {
        int pos = 0;
        int len = signature.length / 2;
        this.r = new byte[len];
        System.arraycopy(signature, pos, this.r, 0, len);
        pos = pos + len;
        this.s = new byte[len];
        System.arraycopy(signature, pos, this.s, 0, len);
        pos += len;
        if (pos != signature.length) {
            throw new RuntimeCryptoException("inputData length != DSASignature length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(this.r);
            buf.write(this.s);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("DSArefSignature encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return this.r.length + this.s.length;
    }

    @Override
    public String toString() {
        return "DSArefSignature{r=" + BytesUtil.bytes2hex(this.r) + ", s=" + BytesUtil.bytes2hex(this.s) + '}';
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("r", "s");
    }

    public static class ByValue extends DSArefSignature implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends DSArefSignature implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
