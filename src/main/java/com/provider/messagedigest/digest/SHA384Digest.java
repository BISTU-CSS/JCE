package com.provider.messagedigest.digest;

import org.bouncycastle.crypto.digests.LongDigest;
import org.bouncycastle.util.Memoable;

public class SHA384Digest extends LongDigest {
    private static final int DIGEST_LENGTH = 48;

    public SHA384Digest() {
    }

    public SHA384Digest(SHA384Digest t) {
        super(t);
    }

    public SHA384Digest(byte[] encodedState) {
        this.restoreState(encodedState);
    }

    public String getAlgorithmName() {
        return "SHA-384";
    }

    public int getDigestSize() {
        return 48;
    }

    public int doFinal(byte[] out, int outOff) {
        this.finish();
        Pack.longToBigEndian(this.H1, out, outOff);
        Pack.longToBigEndian(this.H2, out, outOff + 8);
        Pack.longToBigEndian(this.H3, out, outOff + 16);
        Pack.longToBigEndian(this.H4, out, outOff + 24);
        Pack.longToBigEndian(this.H5, out, outOff + 32);
        Pack.longToBigEndian(this.H6, out, outOff + 40);
        this.reset();
        return 48;
    }

    public SHA384Digest copy() {
        return new SHA384Digest(this);
    }

    public void reset(Memoable other) {
        SHA384Digest d = (SHA384Digest)other;
        super.copyIn(d);
    }

    public void reset() {
        super.reset();
        this.H1 = -3766243637369397544L;
        this.H2 = 7105036623409894663L;
        this.H3 = -7973340178411365097L;
        this.H4 = 1526699215303891257L;
        this.H5 = 7436329637833083697L;
        this.H6 = -8163818279084223215L;
        this.H7 = -2662702644619276377L;
        this.H8 = 5167115440072839076L;
    }




    public byte[] getEncodedState() {
        byte[] encoded = new byte[this.getEncodedStateSize()];
        super.populateState(encoded);
        return encoded;
    }
}