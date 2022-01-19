package com.jna.model.ecdsa;


import com.jna.model.IKeyPair;
import com.sun.jna.Structure;
import com.util.BytesUtil;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class ECDSArefPublicKey extends Structure implements IKeyPair {
    public int bits;
    public int curvetype;
    public byte[] x = new byte[80];
    public byte[] y = new byte[80];


    public ECDSArefPublicKey() {
    }

    public ECDSArefPublicKey(int bits, int curvetype, byte[] x, byte[] y) {
        this.bits = bits;
        this.curvetype = curvetype;
        if (x.length > 80) {
            System.arraycopy(x, x.length - 80, this.x, 0, this.x.length);
        } else {
            System.arraycopy(x, 0, this.x, this.x.length - x.length, x.length);
        }

        if (y.length > 80) {
            System.arraycopy(y, y.length - 80, this.y, 0, this.y.length);
        } else {
            System.arraycopy(y, 0, this.y, this.y.length - y.length, y.length);
        }

    }

    public int getBits() {
        return this.bits;
    }

    public int getCurvetype() {
        return this.curvetype;
    }

    public void setCurvetype(int curvetype) {
        this.curvetype = curvetype;
    }

    public byte[] getX() {
        return this.x;
    }

    public byte[] getY() {
        return this.y;
    }

    public int size() {
        return 168;
    }

    @Override
    public void decode(byte[] publicKey) {
        this.bits = BytesUtil.bytes2int(publicKey);
        int pos = 4;
        byte[] tmpBuffer = new byte[4];
        System.arraycopy(publicKey, pos, tmpBuffer, 0, tmpBuffer.length);
        this.curvetype = BytesUtil.bytes2int(tmpBuffer);
        pos = pos + tmpBuffer.length;
        System.arraycopy(publicKey, pos, this.x, 0, 80);
        pos += this.x.length;
        System.arraycopy(publicKey, pos, this.y, 0, 80);
        pos += this.y.length;
        if (pos != publicKey.length) {
            throw new RuntimeCryptoException("inputData length != ECDSArefPublicKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(BytesUtil.int2bytes(this.curvetype));
            buf.write(this.x);
            buf.write(this.y);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("ECDSArefPublicKey encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public String toString() {
        return "ECDSArefPublicKey{bits=" + this.bits + ", curvetype=" + Integer.toHexString(this.curvetype) + ", X=" + BytesUtil.bytes2hex(this.x) + ", Y=" + BytesUtil.bytes2hex(this.y) + '}';
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "curvetype", "x", "y");
    }

    public static class ByValue extends ECDSArefPublicKey implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends ECDSArefPublicKey implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
