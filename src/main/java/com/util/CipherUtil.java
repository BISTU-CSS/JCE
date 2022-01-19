package com.util;

import com.padding.PKCS7Padding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;

public class CipherUtil {

    public static byte[] encrypt(byte[] data, Key key, String alg, Provider provider) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = provider == null ? Cipher.getInstance(alg) : Cipher.getInstance(alg, provider);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, Key key, String alg, Provider provider) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = provider == null ? Cipher.getInstance(alg) : Cipher.getInstance(alg, provider);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }


    /**
     * 针对对称加密，做数据PKCS7填充
     *
     * @param algId
     * @param input
     * @return
     * @throws BadPaddingException
     */
    public static byte[] encryptPadding(int algId, byte[] input) throws BadPaddingException {

        if (!SymmetryUtil.isRightAlg(algId)) {
            throw new BadPaddingException("Illegal GBAlgorithmID: " + Integer.toHexString(algId));
        }
        if (input == null || input.length == 0) {
            throw new BadPaddingException("The input data is null.");
        }

        int baseLen = SymmetryUtil.inputBaseLength(algId);
        int inputLen = input.length;

        int destLen = (inputLen / baseLen + 1) * baseLen;

        return PKCS7Padding.getPaddingData(input, destLen);
    }


    public static List<byte[]> splitArraysAndPKCS7Padding(byte[] input, int mlength) {
        int inputLen = input.length;
        int a = inputLen / mlength;//获取输入长度/模长的倍数
        int b = inputLen % mlength;//获取输入长度/模长的余数

        List<byte[]> list = new ArrayList<>();

        for (int i = 0; i < a; i++) {
            byte[] temp = new byte[mlength];
            System.arraycopy(input, i * mlength, temp, 0, mlength);
            list.add(temp);
        }
        if (b > 0) {
            byte[] temp = new byte[b];
            System.arraycopy(input, a * mlength, temp, 0, b);

            byte[] encrypts = PKCS7Padding.getPaddingData(temp, mlength);
            list.add(encrypts);
        }

        return list;
    }

}
