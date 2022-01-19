package com.provider.messagedigest;

import com.provider.messagedigest.digest.SHA384Digest;

import java.security.MessageDigestSpi;

public final class SHA384MessageDigestSpi extends MessageDigestSpi {
    private SHA384Digest sha384Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (sha384Digest == null) {
            sha384Digest = new SHA384Digest();
        }
        sha384Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (sha384Digest == null) {
            sha384Digest = new SHA384Digest();
        }
        sha384Digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        if (sha384Digest == null) {
            sha384Digest = new SHA384Digest();
        }
        byte[] out = new byte[sha384Digest.getDigestSize()];
        sha384Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        sha384Digest = new SHA384Digest();
    }
}
