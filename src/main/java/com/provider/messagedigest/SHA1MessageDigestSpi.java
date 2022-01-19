package com.provider.messagedigest;

import com.provider.messagedigest.digest.SHA1Digest;

import java.security.MessageDigestSpi;

public final class SHA1MessageDigestSpi extends MessageDigestSpi {
    private SHA1Digest sha1Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (sha1Digest == null) {
            sha1Digest = new SHA1Digest();
        }
        sha1Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (sha1Digest == null) {
            sha1Digest = new SHA1Digest();
        }
        sha1Digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        if (sha1Digest == null) {
            sha1Digest = new SHA1Digest();
        }
        byte[] out = new byte[sha1Digest.getDigestSize()];
        sha1Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        sha1Digest = new SHA1Digest();
    }
}
