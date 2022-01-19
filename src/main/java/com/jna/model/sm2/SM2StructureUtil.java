package com.jna.model.sm2;


import com.util.BigIntegerUtil;

import java.math.BigInteger;

public class SM2StructureUtil {

    public static SM2StructCipher convertStruct(SM2refCipher cipher) {
        //从jna结构体转换到jce结构体
        BigInteger x = BigIntegerUtil.toPositiveInteger(cipher.getX());
        BigInteger y = BigIntegerUtil.toPositiveInteger(cipher.getY());

        int cLength = cipher.getCLength();
        byte[] c = new byte[cLength];

        System.arraycopy(cipher.getC(), 0, c, 0, c.length);

        byte[] m = cipher.getM();

        return new SM2StructCipher(x, y, c, m);
    }

    public static SM2refCipher convertCipher(SM2StructCipher cipherStruct) {
        //从jce结构体转换到jna结构体
        byte[] x = BigIntegerUtil.asUnsigned32ByteArray(cipherStruct.getX());
        byte[] y = BigIntegerUtil.asUnsigned32ByteArray(cipherStruct.getY());
        byte[] c = cipherStruct.getC();
        byte[] m = cipherStruct.getM();
        return new SM2refCipher(x, y, c, m);
    }

}
