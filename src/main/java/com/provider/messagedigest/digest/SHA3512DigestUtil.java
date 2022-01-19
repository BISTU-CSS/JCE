package com.provider.messagedigest.digest;

public class SHA3512DigestUtil {
    public static final byte[] iv = DigestUtil.hex2bytes("7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e");
    private static int[] Tj = new int[64];

    private static int FFj(int X, int Y, int Z, int j) {
        return j >= 0 && j <= 15 ? FF1j(X, Y, Z) : FF2j(X, Y, Z);
    }

    private static int GGj(int X, int Y, int Z, int j) {
        return j >= 0 && j <= 15 ? GG1j(X, Y, Z) : GG2j(X, Y, Z);
    }

    private static int FF1j(int X, int Y, int Z) {
        return X ^ Y ^ Z;
    }

    private static int FF2j(int X, int Y, int Z) {
        return X & Y | X & Z | Y & Z;
    }

    private static int GG1j(int X, int Y, int Z) {
        return X ^ Y ^ Z;
    }

    private static int GG2j(int X, int Y, int Z) {
        return X & Y | ~X & Z;
    }

    private static int P0(int X) {
        return X ^ rotateLeft(X, 9) ^ rotateLeft(X, 17);
    }

    private static int P1(int X) {
        return X ^ rotateLeft(X, 15) ^ rotateLeft(X, 23);
    }

    public static byte[] CF(byte[] V, byte[] B) {
        int[] v = byteArray2intArray(V);
        int[] b = byteArray2intArray(B);
        return intArray2byteArray(CF(v, b));
    }

    private static int[] byteArray2intArray(byte[] bytes) {
        int[] out = new int[bytes.length / 4];
        byte[] tmp = new byte[4];

        for(int i = 0; i < bytes.length; i += 4) {
            System.arraycopy(bytes, i, tmp, 0, 4);
            out[i / 4] = DigestUtil.bytes2int(tmp);
        }

        return out;
    }

    private static byte[] intArray2byteArray(int[] arr) {
        byte[] out = new byte[arr.length * 4];
        byte[] tmp = null;

        for(int i = 0; i < arr.length; ++i) {
            tmp = DigestUtil.int2bytes(arr[i]);
            System.arraycopy(tmp, 0, out, i * 4, 4);
        }

        return out;
    }

    public static int[] CF(int[] V, int[] B) {
        int a = V[0];
        int b = V[1];
        int c = V[2];
        int d = V[3];
        int e = V[4];
        int f = V[5];
        int g = V[6];
        int h = V[7];
        int[][] arr = Expand(B);
        int[] w = arr[0];
        int[] w1 = arr[1];

        for(int j = 0; j < 64; ++j) {
            int ss1 = rotateLeft(rotateLeft(a, 12) + e + rotateLeft(Tj[j], j), 7);
            int ss2 = ss1 ^ rotateLeft(a, 12);
            int tt1 = FFj(a, b, c, j) + d + ss2 + w1[j];
            int tt2 = GGj(e, f, g, j) + h + ss1 + w[j];
            d = c;
            c = rotateLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = rotateLeft(f, 19);
            f = e;
            e = P0(tt2);
        }

        int[] out = new int[]{a ^ V[0], b ^ V[1], c ^ V[2], d ^ V[3], e ^ V[4], f ^ V[5], g ^ V[6], h ^ V[7]};
        return out;
    }

    private static int[][] Expand(int[] B) {
        int[] W = new int[68];
        int[] W1 = new int[64];

        int j;
        for(j = 0; j < B.length; ++j) {
            W[j] = B[j];
        }

        for(j = 16; j < 68; ++j) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotateLeft(W[j - 3], 15)) ^ rotateLeft(W[j - 13], 7) ^ W[j - 6];
        }

        for(j = 0; j < 64; ++j) {
            W1[j] = W[j] ^ W[j + 4];
        }

        int[][] arr = new int[][]{W, W1};
        return arr;
    }

    public static byte[] padding(byte[] in, int bLen) {
        int k = 448 - (8 * in.length + 1) % 512;
        if (k < 0) {
            k = 960 - (8 * in.length + 1) % 512;
        }

        ++k;
        byte[] padd = new byte[k / 8];
        padd[0] = -128;
        long n = (long)(in.length * 8 + bLen * 512);
        byte[] out = new byte[in.length + k / 8 + 8];
        int pos = 0;
        System.arraycopy(in, 0, out, 0, in.length);
        pos = pos + in.length;
        System.arraycopy(padd, 0, out, pos, padd.length);
        pos += padd.length;
        byte[] tmp = DigestUtil.long2bytes(n);
        System.arraycopy(tmp, 0, out, pos, tmp.length);
        return out;
    }

    private static int rotateLeft(int x, int n) {
        return x << n | x >>> 32 - n;
    }

    static {
        int i;
        for(i = 0; i < 16; ++i) {
            Tj[i] = 2043430169;
        }

        for(i = 16; i < 64; ++i) {
            Tj[i] = 2055708042;
        }

    }


}
