package com.provider.messagedigest;

import com.provider.messagedigest.digest.SM3Digest;

import java.math.BigInteger;
import java.security.MessageDigestSpi;

public final class SM3MessageDigestSpi extends MessageDigestSpi {
    private boolean isFirst = true;
    private SM3Digest sm3Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (sm3Digest == null) {
            sm3Digest = new SM3Digest();
        }
        sm3Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (sm3Digest == null) {
            sm3Digest = new SM3Digest();
        }
        if (this.isFirst && input.length > 64) {
            this.isFirst = false;
            int idLength = input.length - 64;
            byte[] bX = new byte[32];
            byte[] bY = new byte[32];
            byte[] id = new byte[idLength];
            System.arraycopy(input, offset, bX, 0, 32);
            System.arraycopy(input, offset + 32, bY, 0, 32);
            System.arraycopy(input, offset + 64, id, 0, idLength);
            sm3Digest.addId(new BigInteger(1, bX), new BigInteger(1, bY), id);
        } else {
            sm3Digest.update(input, offset, len);
        }
    }

    @Override
    protected byte[] engineDigest() {
        if (sm3Digest == null) {
            sm3Digest = new SM3Digest();
        }
        byte[] out = new byte[sm3Digest.getDigestSize()];
        sm3Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        this.isFirst = true;
        sm3Digest = new SM3Digest();
    }
}
