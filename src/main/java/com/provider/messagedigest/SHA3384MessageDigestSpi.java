package com.provider.messagedigest;

import com.provider.messagedigest.digest.SHA3Digest;

import java.security.MessageDigestSpi;

public final class SHA3384MessageDigestSpi extends MessageDigestSpi {
    private static final int LENGTH = 384;
    private SHA3Digest sha3Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (sha3Digest == null) {
            sha3Digest = new SHA3Digest(LENGTH);
        }
        sha3Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (sha3Digest == null) {
            sha3Digest = new SHA3Digest(LENGTH);
        }
        sha3Digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        if (sha3Digest == null) {
            sha3Digest = new SHA3Digest(LENGTH);
        }
        byte[] out = new byte[sha3Digest.getDigestSize()];
        sha3Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        sha3Digest = new SHA3Digest(LENGTH);
    }
}
