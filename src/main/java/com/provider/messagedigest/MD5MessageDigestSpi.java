package com.provider.messagedigest;

import com.provider.messagedigest.digest.MD5Digest;

import java.security.MessageDigestSpi;

public final class MD5MessageDigestSpi extends MessageDigestSpi {
    private int digestSize = 16;
    private MD5Digest md5Digest;

    @Override
    protected void engineUpdate(byte input) {
        if (this.md5Digest == null) {
            md5Digest = new MD5Digest();
        }
        md5Digest.update(input);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        if (this.md5Digest == null) {
            md5Digest = new MD5Digest();
        }
        md5Digest.update(input, offset, len);
    }

    @Override
    protected byte[] engineDigest() {
        if (this.md5Digest == null) {
            md5Digest = new MD5Digest();
        }
        
        byte[] out = new byte[md5Digest.getDigestSize()];
        md5Digest.doFinal(out, 0);
        return out;
    }

    @Override
    protected void engineReset() {
        md5Digest = new MD5Digest();
    }
}
