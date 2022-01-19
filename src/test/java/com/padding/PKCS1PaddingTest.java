package com.padding;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.util.Arrays;

/**
 * @Description: TODO
 * @Author: hongyi
 * @Date: 2020/9/15 20:41
 */
public class PKCS1PaddingTest {

    public static void main(String[] args) throws BadPaddingException, IllegalBlockSizeException {

//        PKCS1Padding p1 = new PKCS1Padding(1024, true, false);
        PKCS1Padding p1 = new PKCS1Padding(1024, true, true);

        byte[] plain = {1};
        System.out.println(Arrays.toString(plain));


        byte[] data = p1.processBlock(plain, 0, plain.length);
        System.out.println(Arrays.toString(data));

        PKCS1Padding p2 = new PKCS1Padding(1024, false, false);

        byte[] result = p2.processBlock(data, 0, data.length);
        System.out.println(Arrays.toString(result));

    }

}
