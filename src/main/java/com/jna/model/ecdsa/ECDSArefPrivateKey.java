package com.jna.model.ecdsa;


import com.jna.model.IKeyPair;
import com.sun.jna.Structure;
import com.util.BytesUtil;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class ECDSArefPrivateKey extends Structure implements IKeyPair {
    public int bits;
    public int curvetype;
    public byte[] D = new byte[80];

    public ECDSArefPrivateKey() {
    }

    public ECDSArefPrivateKey(int bits, int curvetype, byte[] D) {
        this.bits = bits;
        this.curvetype = curvetype;
        if (D.length > 80) {
            System.arraycopy(D, D.length - 80, this.D, 0, this.D.length);
        } else {
            System.arraycopy(D, 0, this.D, this.D.length - D.length, D.length);
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

    public byte[] getD() {
        return this.D;
    }

    @Override
    public void decode(byte[] privateKey) {
        this.bits = BytesUtil.bytes2int(privateKey);
        int pos = 4;
        byte[] tmpBuffer = new byte[4];
        System.arraycopy(privateKey, pos, tmpBuffer, 0, tmpBuffer.length);
        this.curvetype = BytesUtil.bytes2int(tmpBuffer);
        pos = pos + tmpBuffer.length;
        System.arraycopy(privateKey, pos, this.D, 0, 80);
        pos += this.D.length;
        if (pos != privateKey.length) {
            throw new RuntimeCryptoException("inputData length != ECDSAPrivateKey length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(BytesUtil.int2bytes(this.curvetype));
            buf.write(this.D);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("ECDSArefPrivateKey encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public int size() {
        return 88;
    }

    @Override
    public String toString() {
        return "ECDSArefPrivateKey{bits=" + this.bits + ", curvetype=" + Integer.toHexString(this.curvetype) + ", D=" + BytesUtil.bytes2hex(this.D) + '}';
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "curvetype", "D");
    }

    public static class ByValue extends ECDSArefPrivateKey implements com.sun.jna.Structure.ByValue {
        public ByValue() {
        }
    }

    public static class ByReference extends ECDSArefPrivateKey implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }


}
