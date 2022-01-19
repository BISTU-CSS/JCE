package com.util;

import java.math.BigInteger;

public class BigIntegerUtil {
    public BigIntegerUtil() {
    }

    public static BigInteger toPositiveInteger(byte[] in) {
        if (in == null) {
            return null;
        }

        if (in[0] < 0) {
            byte[] tmp = new byte[in.length + 1];
            tmp[0] = 0;
            System.arraycopy(in, 0, tmp, 1, tmp.length - 1);
            return new BigInteger(tmp);
        }

        return new BigInteger(in);
    }

    public static byte[] asUnsigned32ByteArray(BigInteger n) {
        return asUnsignedNByteArray(n, 32);
    }

    public static byte[] asUnsignedNByteArray(BigInteger x, int length) {
        if (x == null) {
            return null;
        }

        byte[] in = x.toByteArray();
        byte[] tmp = new byte[length];
        int len = in.length;
        if (len > length + 1) {
            return null;
        }

        if (len == length + 1) {
            if (in[0] != 0) {
                return null;
            }
            System.arraycopy(in, 1, tmp, 0, length);
            return tmp;
        }

        System.arraycopy(in, 0, tmp, length - len, len);
        return tmp;
    }


}
