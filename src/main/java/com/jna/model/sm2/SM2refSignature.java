package com.jna.model.sm2;


import com.jna.model.IKeyPair;
import com.sun.jna.Structure;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class SM2refSignature extends Structure implements IKeyPair {
    public byte[] r = new byte[32];
    public byte[] s = new byte[32];

    public SM2refSignature() {
    }

    public SM2refSignature(byte[] r, byte[] s) {
        this.r = r;
        this.s = s;
    }

    public byte[] getR() {
        return this.r;
    }

    public byte[] getS() {
        return this.s;
    }

    public void decode(byte[] signature) {
        int pos = 0;
        System.arraycopy(signature, pos, this.r, 0, 32);
        pos = pos + 32;
        System.arraycopy(signature, pos, this.s, 0, 32);
        pos += 32;
        if (pos != signature.length) {
            throw new RuntimeCryptoException("inputData length != SM2Signature length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(this.r);
            buf.write(this.s);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("SM2refSignature encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 64;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append(nl);
        buf.append("   R: ").append((new BigInteger(1, this.r)).toString(16)).append(nl);
        buf.append("   S: ").append((new BigInteger(1, this.s)).toString(16)).append(nl);
        return buf.toString();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("r", "s");
    }

    public static class ByValue extends SM2refSignature implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends SM2refSignature implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
