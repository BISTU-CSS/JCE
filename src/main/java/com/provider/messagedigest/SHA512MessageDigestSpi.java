package com.provider.messagedigest;

import com.provider.messagedigest.digest.SHA512Digest;

import java.security.MessageDigestSpi;

public final class SHA512MessageDigestSpi extends MessageDigestSpi {
    private SHA512Digest sha512Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (sha512Digest == null) {
            sha512Digest = new SHA512Digest();
        }
        sha512Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (sha512Digest == null) {
            sha512Digest = new SHA512Digest();
        }
        sha512Digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        if (sha512Digest == null) {
            sha512Digest = new SHA512Digest();
        }
        byte[] out = new byte[sha512Digest.getDigestSize()];
        sha512Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        sha512Digest = new SHA512Digest();
    }
}
