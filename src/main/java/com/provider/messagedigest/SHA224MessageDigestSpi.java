package com.provider.messagedigest;

import com.provider.messagedigest.digest.SHA224Digest;

import java.security.MessageDigestSpi;

public final class SHA224MessageDigestSpi extends MessageDigestSpi {
    private SHA224Digest sha224Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (sha224Digest == null) {
            sha224Digest = new SHA224Digest();
        }
        sha224Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (sha224Digest == null) {
            sha224Digest = new SHA224Digest();
        }
        sha224Digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        if (sha224Digest == null) {
            sha224Digest = new SHA224Digest();
        }
        byte[] out = new byte[sha224Digest.getDigestSize()];
        sha224Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        sha224Digest = new SHA224Digest();
    }
}
