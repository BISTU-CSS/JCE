package com.provider.messagedigest.digest;

import java.math.BigInteger;

public class SM3Digest {
    private static final int BYTE_LENGTH = 32;
    private static final int BLOCK_LENGTH = 64;
    private static final int BUFFER_LENGTH = 64;
    private byte[] xBuf = new byte[64];
    private int xBufOff;
    private byte[] V;
    private int cntBlock;

    public SM3Digest() {
        this.V = (byte[])((byte[])SM3DigestUtil.iv.clone());
        this.cntBlock = 0;
    }

    public SM3Digest(SM3Digest t) {
        this.V = (byte[])((byte[])SM3DigestUtil.iv.clone());
        this.cntBlock = 0;
        System.arraycopy(t.xBuf, 0, this.xBuf, 0, t.xBuf.length);
        this.xBufOff = t.xBufOff;
        System.arraycopy(t.V, 0, this.V, 0, t.V.length);
        this.cntBlock = t.cntBlock;
    }

    public int doFinal(byte[] out, int outOff) {
        byte[] hash = this.doFinal();
        System.arraycopy(hash, 0, out, outOff, 32);
        this.reset();
        return 32;
    }

    public void reset() {
        this.xBufOff = 0;
        this.cntBlock = 0;
        this.V = (byte[])((byte[])SM3DigestUtil.iv.clone());
    }

    public void update(byte[] in, int inOff, int len) {
        int leftLen = 64 - this.xBufOff;
        int inputLen = len;
        int dPos = inOff;
        if (leftLen < len) {
            System.arraycopy(in, inOff, this.xBuf, this.xBufOff, leftLen);
            inputLen = len - leftLen;
            dPos = inOff + leftLen;
            this.compute();

            while(inputLen > 64) {
                System.arraycopy(in, dPos, this.xBuf, 0, 64);
                inputLen -= 64;
                dPos += 64;
                this.compute();
            }
        }

        System.arraycopy(in, dPos, this.xBuf, this.xBufOff, inputLen);
        this.xBufOff += inputLen;
    }

    private void compute() {
        byte[] B = new byte[64];

        for(int i = 0; i < 64; i += 64) {
            System.arraycopy(this.xBuf, i, B, 0, 64);
            this.compute(B);
        }

        this.xBufOff = 0;
    }

    private void compute(byte[] block) {
        byte[] V1 = SM3DigestUtil.CF(this.V, block);
        System.arraycopy(V1, 0, this.V, 0, this.V.length);
        ++this.cntBlock;
    }

    private byte[] doFinal() {
        byte[] B = new byte[64];
        byte[] buffer = new byte[this.xBufOff];
        System.arraycopy(this.xBuf, 0, buffer, 0, buffer.length);
        byte[] tmp = SM3DigestUtil.padding(buffer, this.cntBlock);

        for(int i = 0; i < tmp.length; i += 64) {
            System.arraycopy(tmp, i, B, 0, B.length);
            this.compute(B);
        }

        return this.V;
    }

    private byte[] getSM2Za(byte[] x, byte[] y, byte[] id) {
        byte[] tmp = DigestUtil.int2bytes(id.length * 8);
        byte[] buffer = new byte[194 + id.length];
        buffer[0] = tmp[2];
        buffer[1] = tmp[3];
        byte[] a = DigestUtil.a;
        byte[] b = DigestUtil.b;
        byte[] gx = DigestUtil.Gx;
        byte[] gy = DigestUtil.Gy;
        int dPos = 2;
        System.arraycopy(id, 0, buffer, dPos, id.length);
        dPos = dPos + id.length;
        System.arraycopy(a, 0, buffer, dPos, 32);
        dPos += 32;
        System.arraycopy(b, 0, buffer, dPos, 32);
        dPos += 32;
        System.arraycopy(gx, 0, buffer, dPos, 32);
        dPos += 32;
        System.arraycopy(gy, 0, buffer, dPos, 32);
        dPos += 32;
        System.arraycopy(x, 0, buffer, dPos, 32);
        dPos += 32;
        System.arraycopy(y, 0, buffer, dPos, 32);
        dPos += 32;
        SM3Digest digest = new SM3Digest();
        digest.update(buffer, 0, buffer.length);
        byte[] out = new byte[32];
        digest.doFinal(out, 0);
        return out;
    }

    public byte[] getSM2Za(byte[] buffer) {
        SM3Digest digest = new SM3Digest();
        digest.update(buffer, 0, buffer.length);
        byte[] out = new byte[32];
        digest.doFinal(out, 0);
        return out;
    }

    public void addId(BigInteger affineX, BigInteger affineY, byte[] id) {
        byte[] x = DigestUtil.asUnsigned32ByteArray(affineX);
        byte[] y = DigestUtil.asUnsigned32ByteArray(affineY);
        this.initWithId(x, y, id);
    }

    public void initWithId(byte[] x, byte[] y, byte[] id) {
        if (x != null && x.length == 32 && y != null && y.length == 32 && id != null) {
            byte[] tmp = this.getSM2Za(x, y, id);
            this.reset();
            this.update(tmp, 0, tmp.length);
        } else {
            throw new RuntimeException("The parameter is null or the parameter length is wrong");
        }
    }

    public String getAlgorithmName() {
        return "SM3";
    }

    public int getDigestSize() {
        return 32;
    }

    public void update(byte in) {
        byte[] buffer = new byte[]{in};
        this.update(buffer, 0, 1);
    }
}
