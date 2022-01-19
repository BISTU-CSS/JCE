package com.provider.messagedigest;

import com.provider.messagedigest.digest.SM3Digest;

import java.security.MessageDigestSpi;

public final class SM3WithIDMessageDigestSpi extends MessageDigestSpi {
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
        sm3Digest.update(input, offset, len);
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
        sm3Digest = new SM3Digest();
    }
}
