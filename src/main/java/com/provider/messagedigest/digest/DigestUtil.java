package com.provider.messagedigest.digest;


import java.math.BigInteger;

public final class DigestUtil {
    public static final byte[] p = hex2bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF");
    public static final byte[] a = hex2bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC");
    public static final byte[] b = hex2bytes("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93");
    public static final byte[] n = hex2bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123");
    public static final byte[] Gx = hex2bytes("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");
    public static final byte[] Gy = hex2bytes("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0");
    public static final char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    public static byte[] int2bytes(int num) {
        byte[] bytes = new byte[4];

        for (int i = 0; i < 4; ++i) {
            bytes[3 - i] = (byte) (255 & num >> i * 8);
        }

        return bytes;
    }

    public static int bytes2int(byte[] bytes) {
        int num = 0;

        for (int i = 0; i < 4; ++i) {
            num += (255 & bytes[3 - i]) << i * 8;
        }

        return num;
    }

    public static byte[] long2bytes(long num) {
        byte[] bytes = new byte[8];

        for (int i = 0; i < 8; ++i) {
            bytes[7 - i] = (byte) ((int) (255L & num >> i * 8));
        }

        return bytes;
    }

    public static byte[] asUnsigned32ByteArray(BigInteger value) {
        byte[] out = asUnsignedByteArray(value);
        if (out.length == 32) {
            return out;
        } else if (out.length < 32) {
            byte[] buf = new byte[32];
            System.arraycopy(out, 0, buf, 32 - out.length, out.length);
            return buf;
        } else {
            throw new RuntimeException("参数有误");
        }
    }

    public static byte[] asUnsignedByteArray(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        } else {
            return bytes;
        }
    }

    public static byte[] hex2bytes(String str) {
        str = str.toLowerCase();
        byte[] buf = new byte[str.length() / 2];

        for (int i = 0; i < buf.length; ++i) {
            char ch1 = str.charAt(i * 2);
            char ch2 = str.charAt(i * 2 + 1);
            buf[i] = hex2byte(ch1, ch2);
        }

        return buf;
    }

    private static byte hex2byte(char ch1, char ch2) {
        byte n;
        if (ch1 >= 'a' && ch1 <= 'f') {
            n = (byte) (ch1 - 97 + 10 << 4);
        } else {
            n = (byte) (ch1 - 48 << 4);
        }

        if (ch2 >= 'a' && ch2 <= 'f') {
            n += (byte) (ch2 - 97 + 10);
        } else {
            n += (byte) (ch2 - 48);
        }

        return n;
    }
}

