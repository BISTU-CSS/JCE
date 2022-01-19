package com.provider.messagedigest.digest;

public class SHA3Digest extends KeccakDigest {
    private static int checkBitLength(int bitLength) {
        switch (bitLength) {
            case 224:
            case 256:
            case 384:
            case 512:
                return bitLength;
            default:
                throw new IllegalArgumentException("'bitLength' " + bitLength + " not supported for SHA-3");
        }
    }

    public SHA3Digest() {
        this(224);
    }

    public SHA3Digest(int bitLength) {
        super(checkBitLength(bitLength));
    }

    public SHA3Digest(SHA3Digest source) {
        super(source);
    }

    public String getAlgorithmName() {
        return "SHA3-" + this.fixedOutputLength;
    }

    public int doFinal(byte[] out, int outOff) {
        this.absorb(new byte[]{2}, 0, 2L);
        return super.doFinal(out, outOff);
    }

    protected int doFinal(byte[] out, int outOff, byte partialByte, int partialBits) {
        if (partialBits >= 0 && partialBits <= 7) {
            int finalInput = partialByte & (1 << partialBits) - 1 | 2 << partialBits;
            int finalBits = partialBits + 2;
            if (finalBits >= 8) {
                this.oneByte[0] = (byte) finalInput;
                this.absorb(this.oneByte, 0, 8L);
                finalBits -= 8;
                finalInput >>>= 8;
            }

            return super.doFinal(out, outOff, (byte) finalInput, finalBits);
        } else {
            throw new IllegalArgumentException("'partialBits' must be in the range [0,7]");
        }
    }
}
