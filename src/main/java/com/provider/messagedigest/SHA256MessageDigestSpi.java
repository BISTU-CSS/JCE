package com.provider.messagedigest;

import com.provider.messagedigest.digest.SHA256Digest;

import java.security.MessageDigestSpi;

public final class SHA256MessageDigestSpi extends MessageDigestSpi {
    private SHA256Digest sha256Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (sha256Digest == null) {
            sha256Digest = new SHA256Digest();
        }
        sha256Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (sha256Digest == null) {
            sha256Digest = new SHA256Digest();
        }
        sha256Digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        if (sha256Digest == null) {
            sha256Digest = new SHA256Digest();
        }
        byte[] out = new byte[sha256Digest.getDigestSize()];
        sha256Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        sha256Digest = new SHA256Digest();
    }
}
