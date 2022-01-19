package com.jna.model.dsa;


import com.sun.jna.Structure;
import com.util.BytesUtil;
import org.bouncycastle.crypto.RuntimeCryptoException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class DSArefPublicKeyEx extends Structure implements IDSArefPublicKey {
    public int bits;
    public byte[] p = new byte[512];
    public byte[] q = new byte[32];
    public byte[] g = new byte[512];
    public byte[] pubkey = new byte[512];

    public DSArefPublicKeyEx() {
    }

    public DSArefPublicKeyEx(int bits, byte[] p, byte[] q, byte[] g, byte[] pubkey) {
        if (p.length > 513) {
            throw new RuntimeException("p length[ " + p.length + " ]");
        }
        this.bits = bits;
        System.arraycopy(p, 0, this.p, 512 - p.length, p.length);

        if (q.length > 33) {
            throw new RuntimeException("q length[ " + q.length + " ]");
        }
        System.arraycopy(q, 0, this.q, 32 - q.length, q.length);

        if (g.length > 513) {
            throw new RuntimeException("g length[ " + g.length + " ]");
        }
        System.arraycopy(g, 0, this.g, 512 - g.length, g.length);

        if (pubkey.length > 513) {
            throw new RuntimeException("q length[ " + q.length + " ]");
        }
        System.arraycopy(pubkey, 0, this.pubkey, 512 - pubkey.length, pubkey.length);
    }

    @Override
    public int getBits() {
        return this.bits;
    }

    @Override
    public byte[] getP() {
        return this.p;
    }

    @Override
    public byte[] getQ() {
        return this.q;
    }

    @Override
    public byte[] getG() {
        return this.g;
    }

    @Override
    public byte[] getPubkey() {
        return this.pubkey;
    }

    @Override
    public void decode(byte[] bytes) {
        this.bits = BytesUtil.bytes2int(bytes);
        int pos = 4;
        System.arraycopy(bytes, pos, this.p, 0, 512);
        pos = pos + this.p.length;
        System.arraycopy(bytes, pos, this.q, 0, 32);
        pos += this.q.length;
        System.arraycopy(bytes, pos, this.g, 0, 512);
        pos += this.g.length;
        System.arraycopy(bytes, pos, this.pubkey, 0, 512);
        pos += this.pubkey.length;
        if (pos != bytes.length) {
            throw new RuntimeCryptoException("inputData length != DSArefPublicKeyEx length");
        }
    }

    @Override
    public byte[] encode() {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();

        try {
            buf.write(BytesUtil.int2bytes(this.bits));
            buf.write(this.p);
            buf.write(this.q);
            buf.write(this.g);
            buf.write(this.pubkey);
        } catch (IOException ex) {
            throw new RuntimeCryptoException("DSArefPublicKeyEx encode error." + ex.getMessage());
        }

        return buf.toByteArray();
    }

    @Override
    public String toString() {
        return "DSArefPublicKeyEx{bits=" + this.bits + ", p=" + BytesUtil.bytes2hex(this.p) + ", q=" + BytesUtil.bytes2hex(this.q) + ", g=" + BytesUtil.bytes2hex(this.g) + ", pubkey=" + BytesUtil.bytes2hex(this.pubkey) + '}';
    }

    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "p", "q", "g", "pubkey");
    }
}
